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
}

// TestRelayForwardsBlind starts a real relay and two client sockets, binds both
// legs under one token, and checks a datagram from A reaches B unchanged — the
// relay forwarding the bytes without interpreting them.
func TestRelayForwardsBlind(t *testing.T) {
	relayConn := mustListen(t)
	defer relayConn.Close()
	go NewServer(2*time.Second, nil).Run(relayConn)
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
	go NewServer(2*time.Second, nil).Run(relayConn)
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
