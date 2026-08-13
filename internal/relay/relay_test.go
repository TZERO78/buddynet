package relay

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tzero78/buddynet/pkg/protocol"
)

// sessTok is a realistically-sized session token (22 base64url chars, what
// role.sessionToken derives from 16 bytes of SHA-256).
const sessTok = "AAAAAAAAAAAAAAAAAAAAAA"

func TestParseBind(t *testing.T) {
	pkt := MarshalBind(Bind{SessionToken: sessTok})
	b, ok := ParseBind(pkt)
	if !ok || b.SessionToken != sessTok {
		t.Fatalf("round trip failed: %+v ok=%v", b, ok)
	}
	if _, ok := ParseBind([]byte("random QUIC bytes")); ok {
		t.Fatal("non-bind data must not parse as a bind")
	}
	if _, ok := ParseBind(MarshalBind(Bind{SessionToken: ""})); ok {
		t.Fatal("empty session token must be rejected")
	}
	// A short token is guessable — and it is the ONLY thing splicing two legs
	// together — so the parser refuses anything under MinSessionTokenLen. This also
	// keeps every admitted bind larger than the challenge it may draw.
	short := strings.Repeat("x", MinSessionTokenLen-1)
	if _, ok := ParseBind(MarshalBind(Bind{SessionToken: short})); ok {
		t.Fatalf("a %d-character session token must be rejected", len(short))
	}
	if _, ok := ParseBind(MarshalBind(Bind{SessionToken: strings.Repeat("x", MinSessionTokenLen)})); !ok {
		t.Fatal("a token at exactly MinSessionTokenLen must be accepted")
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
	if _, ok := ParseChallenge(MarshalBind(Bind{SessionToken: sessTok})); ok {
		t.Fatal("a bind must not parse as a challenge")
	}
}

// TestRelayBindNeedsCookie verifies the return-routability gate: a bind without a
// valid cookie draws only a challenge and binds NO leg, so a spoofed source can
// never have traffic laundered to it (the relay's anti-reflection guarantee).
func TestRelayBindNeedsCookie(t *testing.T) {
	relayConn := mustListen(t)
	defer relayConn.Close()
	go New(Config{TTL: 2 * time.Second}).Run(relayConn)
	dial := &net.UDPAddr{IP: net.IPv6loopback, Port: relayConn.LocalAddr().(*net.UDPAddr).Port}

	victim := mustListen(t)
	defer victim.Close()
	// One uncookied bind (what a spoofer would send "from" the victim): the relay
	// must answer with a challenge, never an ack, and bind no leg.
	// A realistic 22-char session token (base64 of 16 bytes), as buddy.go mints.
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
	if err := BindLeg(attacker, dial, sessTok, 2*time.Second, nil); err != nil {
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
	go New(Config{TTL: 2 * time.Second}).Run(relayConn)
	relayAddr := relayConn.LocalAddr().(*net.UDPAddr)
	dial := &net.UDPAddr{IP: net.IPv6loopback, Port: relayAddr.Port}

	a := mustListen(t)
	defer a.Close()
	b := mustListen(t)
	defer b.Close()

	const token = "pair-token-long-enough-1"
	if err := BindLeg(a, dial, token, 2*time.Second, nil); err != nil {
		t.Fatalf("A bind: %v", err)
	}
	if err := BindLeg(b, dial, token, 2*time.Second, nil); err != nil {
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
	go New(Config{TTL: 2 * time.Second}).Run(relayConn)
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

// Anti-amplification as a PROPERTY, not as a spot check: for every session token
// the parser accepts, the challenge it may draw must be strictly smaller than the
// bind. The old tests only ever used a realistic 22-character token, so the
// smallest accepted bind (17 bytes against a 23-byte challenge) went unnoticed.
//
// WHAT THIS DOES NOT COVER: the `len(chal) < reqLen` gate in Server.bind. Since
// MinSessionTokenLen was introduced (same commit), the smallest ADMITTED bind is
// already larger than the challenge, so removing that gate leaves this test green
// — it holds the property, not the gate. The gate is defense in depth, kept
// because the property must not depend on one constant staying where it is; it
// has no mutation coverage of its own and none is claimed.
func TestChallengeIsSmallerThanEveryAcceptedBind(t *testing.T) {
	s := New(Config{TTL: 2 * time.Second})
	chal := len(MarshalChallenge(s.freshCookie(net.IPv4(198, 51, 100, 7))))
	for n := 1; n <= protocol.MaxFieldLen; n++ {
		pkt := MarshalBind(Bind{SessionToken: strings.Repeat("x", n)})
		if _, ok := ParseBind(pkt); !ok {
			continue // refused by the parser: it can never draw a challenge
		}
		if chal >= len(pkt) {
			t.Fatalf("a %d-character token yields a %d-byte bind but a %d-byte challenge — amplifier",
				n, len(pkt), chal)
		}
	}
}
