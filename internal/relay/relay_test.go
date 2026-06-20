package relay

import (
	"net"
	"testing"
	"time"

	"github.com/tzero78/buddynet/pkg/protocol"
)

func TestParseBind(t *testing.T) {
	pkt := MarshalBind(Bind{SessionToken: "sess123"})
	b, ok := ParseBind(pkt)
	if !ok || b.SessionToken != "sess123" {
		t.Fatalf("round trip failed: %+v ok=%v", b, ok)
	}
	if _, ok := ParseBind([]byte("random QUIC bytes")); ok {
		t.Fatal("non-bind data must not parse as a bind")
	}
	if _, ok := ParseBind(MarshalBind(Bind{SessionToken: ""})); ok {
		t.Fatal("empty session token must be rejected")
	}
	// A challenge must round-trip and must not be mistaken for a bind.
	cookie := make([]byte, CookieLen)
	chal := MarshalChallenge(cookie)
	if got, ok := ParseChallenge(chal); !ok || len(got) != CookieLen {
		t.Fatalf("challenge round trip failed: ok=%v len=%d", ok, len(got))
	}
	if _, ok := ParseBind(chal); ok {
		t.Fatal("a challenge must not parse as a bind")
	}
	if _, ok := ParseChallenge(MarshalBind(Bind{SessionToken: "x"})); ok {
		t.Fatal("a bind must not parse as a challenge")
	}
}

// TestRelayBindNeedsCookie verifies the return-routability gate: a bind without a
// valid cookie draws only a challenge and binds NO leg, so a spoofed source can
// never have traffic laundered to it (the relay's anti-reflection guarantee).
func TestRelayBindNeedsCookie(t *testing.T) {
	relayConn := mustListen(t)
	defer relayConn.Close()
	go NewServer(2*time.Second, nil, 0, 0).Run(relayConn)
	dial := &net.UDPAddr{IP: net.IPv6loopback, Port: relayConn.LocalAddr().(*net.UDPAddr).Port}

	victim := mustListen(t)
	defer victim.Close()
	// One uncookied bind (what a spoofer would send "from" the victim): the relay
	// must answer with a challenge, never an ack, and bind no leg.
	// A realistic 22-char session token (base64 of 16 bytes), as buddy.go mints.
	const sessTok = "AAAAAAAAAAAAAAAAAAAAAA"
	victim.WriteToUDP(MarshalBind(Bind{SessionToken: sessTok}), dial)
	victim.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1500)
	n, _, err := victim.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("expected an address-validation challenge, got none: %v", err)
	}
	if _, ok := ParseChallenge(buf[:n]); !ok {
		t.Fatalf("uncookied bind must draw a challenge, got %q", buf[:n])
	}
	if _, ok := ParseBind(buf[:n]); ok {
		t.Fatal("relay must NOT ack a leg without a validated cookie")
	}
	if len(buf[:n]) >= len(MarshalBind(Bind{SessionToken: sessTok})) {
		t.Fatal("challenge must be smaller than the bind it answers (no amplification)")
	}

	// An attacker binds the other leg properly and tries to launder data to the
	// victim, which never validated: the victim must not receive the payload.
	attacker := mustListen(t)
	defer attacker.Close()
	if err := BindLeg(attacker, dial, sessTok, 2*time.Second); err != nil {
		t.Fatalf("attacker bind: %v", err)
	}
	attacker.WriteToUDP([]byte("laundered payload"), dial)
	victim.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if n, _, err := victim.ReadFromUDP(buf); err == nil && string(buf[:n]) == "laundered payload" {
		t.Fatal("relay forwarded data to an address that never validated (laundering)")
	}
}

// TestRelayForwardsBlind starts a real relay and two client sockets, binds both
// legs under one token, and checks a datagram from A reaches B unchanged — the
// relay forwarding the bytes without interpreting them.
func TestRelayForwardsBlind(t *testing.T) {
	relayConn := mustListen(t)
	defer relayConn.Close()
	go NewServer(2*time.Second, nil, 0, 0).Run(relayConn)
	relayAddr := relayConn.LocalAddr().(*net.UDPAddr)
	dial := &net.UDPAddr{IP: net.IPv6loopback, Port: relayAddr.Port}

	a := mustListen(t)
	defer a.Close()
	b := mustListen(t)
	defer b.Close()

	const token = "pair-token"
	if err := BindLeg(a, dial, token, 2*time.Second); err != nil {
		t.Fatalf("A bind: %v", err)
	}
	if err := BindLeg(b, dial, token, 2*time.Second); err != nil {
		t.Fatalf("B bind: %v", err)
	}

	payload := []byte("opaque encrypted bytes \x00\x01\x02")
	if _, err := a.WriteToUDP(payload, dial); err != nil {
		t.Fatal(err)
	}

	b.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := b.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("B did not receive forwarded datagram: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("payload altered in transit: %q", buf[:n])
	}
}

// TestRelayDropsUnboundSource ensures the relay never forwards from a source it
// has not heard a bind from (anti-reflector).
func TestRelayDropsUnboundSource(t *testing.T) {
	relayConn := mustListen(t)
	defer relayConn.Close()
	go NewServer(2*time.Second, nil, 0, 0).Run(relayConn)
	relayAddr := relayConn.LocalAddr().(*net.UDPAddr)
	dial := &net.UDPAddr{IP: net.IPv6loopback, Port: relayAddr.Port}

	stranger := mustListen(t)
	defer stranger.Close()
	// No bind: a data packet should simply be dropped (no reply, no forward).
	stranger.WriteToUDP([]byte("hello"), dial)
	stranger.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := stranger.ReadFromUDP(make([]byte, 1500)); err == nil {
		t.Fatal("relay replied to an unbound source (reflector risk)")
	}
}

func mustListen(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestChainOrder(t *testing.T) {
	partner := protocol.Peer{
		Candidates: []protocol.Candidate{{Addr: "203.0.113.1:51820"}},
		Relay:      "relay.example:51821",
	}
	chain := Chain(partner, nil, partner.Relay, nil)
	if len(chain) != 2 {
		t.Fatalf("want direct+relay, got %d: %+v", len(chain), chain)
	}
	if chain[0].Kind != Direct {
		t.Fatal("direct must be tried first")
	}
	if chain[1].Kind != Relayed || chain[1].RelayEndpoint != "relay.example:51821" {
		t.Fatalf("relay must be the fallback: %+v", chain[1])
	}
}

func TestChainCachedOnlyWhenNoLiveCandidates(t *testing.T) {
	cached := &protocol.Peer{Candidates: []protocol.Candidate{{Addr: "198.51.100.7:51820"}}}
	// Server gave live candidates → cached is NOT appended.
	live := protocol.Peer{Candidates: []protocol.Candidate{{Addr: "203.0.113.9:51820"}}}
	if got := Chain(live, nil, "", cached); len(got) != 1 {
		t.Fatalf("cached should be skipped when live exists: %+v", got)
	}
	// Server gave nothing → cached candidates are the last resort.
	if got := Chain(protocol.Peer{}, nil, "", cached); len(got) != 1 || got[0].Desc == "" {
		t.Fatalf("cached path expected: %+v", got)
	}
}
