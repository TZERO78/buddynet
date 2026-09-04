package role

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/tunnel"
	"github.com/tzero78/buddynet/pkg/protocol"
)

// goodPeer is a roster entry exactly as a healthy server produces one.
func goodPeer(t *testing.T) protocol.Peer {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Peer{
		ID:        randomID(),
		PubKey:    bcrypto.PubKeyB64(pub),
		VirtualIP: bcrypto.VirtualIPString(pub),
		Name:      "alice",
		Candidates: []protocol.Candidate{
			{Addr: "203.0.113.7:51820"},
			{Addr: "[2001:db8::7]:51820", V6: true},
		},
		Relay: "relay.example.net:51821",
	}
}

// The buddy-side field checks mirror what the server validates before signing:
// a healthy roster passes, and each way a hostile server could abuse a field is
// refused on its own.
func TestCheckRosterPeer(t *testing.T) {
	if err := checkRosterPeer(goodPeer(t)); err != nil {
		t.Fatalf("healthy roster entry refused: %v", err)
	}
	many := make([]protocol.Candidate, maxRosterCands+1)
	for i := range many {
		many[i] = protocol.Candidate{Addr: fmt.Sprintf("203.0.113.%d:1000", i+1)}
	}
	cases := []struct {
		name string
		mut  func(*protocol.Peer)
		want string // substring of the error
	}{
		{"id with newline forges a log line", func(p *protocol.Peer) { p.ID = "x\nSECURITY: event=forged" }, "peer id"},
		{"empty id", func(p *protocol.Peer) { p.ID = "" }, "peer id"},
		{"overlong id", func(p *protocol.Peer) { p.ID = strings.Repeat("a", protocol.MaxFieldLen+1) }, "peer id"},
		{"name with terminal escape", func(p *protocol.Peer) { p.Name = "a\x1b[2Jb" }, "peer name"},
		{"name in the reserved fingerprint shape", func(p *protocol.Peer) { p.Name = "deadbeef" }, "peer name"},
		{"empty name is fine", func(p *protocol.Peer) { p.Name = "" }, ""},
		{"too many candidates", func(p *protocol.Peer) { p.Candidates = many }, "exceed the limit"},
		{"hostname candidate would resolve DNS", func(p *protocol.Peer) { p.Candidates = []protocol.Candidate{{Addr: "victim.example:53"}} }, "literal IP:port"},
		{"port zero", func(p *protocol.Peer) { p.Candidates = []protocol.Candidate{{Addr: "203.0.113.7:0"}} }, "unicast"},
		{"unspecified address", func(p *protocol.Peer) { p.Candidates = []protocol.Candidate{{Addr: "0.0.0.0:51820"}} }, "unicast"},
		{"multicast address", func(p *protocol.Peer) { p.Candidates = []protocol.Candidate{{Addr: "224.0.0.1:51820"}} }, "unicast"},
		{"v4-mapped unspecified", func(p *protocol.Peer) { p.Candidates = []protocol.Candidate{{Addr: "[::ffff:0.0.0.0]:51820"}} }, "unicast"},
		{"no candidates is fine (relay-only pairing)", func(p *protocol.Peer) { p.Candidates = nil }, ""},
		{"overlong relay", func(p *protocol.Peer) { p.Relay = strings.Repeat("r", protocol.MaxFieldLen+1) }, "relay"},
	}
	for _, tc := range cases {
		p := goodPeer(t)
		tc.mut(&p)
		err := checkRosterPeer(p)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: unexpected refusal: %v", tc.name, err)
		case tc.want != "" && err == nil:
			t.Errorf("%s: accepted, want refusal", tc.name)
		case tc.want != "" && !strings.Contains(err.Error(), tc.want):
			t.Errorf("%s: error %q does not mention %q", tc.name, err, tc.want)
		}
	}
}

// End to end against a server that signs whatever it likes: a roster whose
// signature verifies but whose partner id carries a newline must be refused by
// buddyRegister, with no partner returned. Before this check the buddy accepted
// the entry and logged the id verbatim.
func TestBuddyRegisterRefusesInvalidSignedRoster(t *testing.T) {
	nd, srvPriv := testNode(t)
	srvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srvConn.Close()
	cs, err := tunnel.ListenControl(srvConn, srvPriv, 10*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	const rendezvous = "roster-check-token"
	hostile := goodPeer(t)
	hostile.ID = "x\nSECURITY: event=forged"
	go func() {
		for {
			req, err := cs.Accept(context.Background())
			if err != nil {
				return
			}
			// Sign exactly what a real server would, over the hostile entry.
			reply := signedPeerList(srvPriv, rendezvous, []protocol.Peer{hostile})
			b, _ := json.Marshal(reply)
			req.Reply(b)
		}
	}()

	cliConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cliConn.Close()
	cfg := BuddyConfig{Server: srvConn.LocalAddr().String()}
	partner, _, rerr := buddyRegister(cliConn, []*net.UDPAddr{srvConn.LocalAddr().(*net.UDPAddr)}, cfg, nd, rendezvous, 5*time.Second, nil)
	if rerr == nil {
		t.Fatalf("hostile roster accepted: partner id %q", partner.ID)
	}
	if !strings.Contains(rerr.Error(), "invalid roster") {
		t.Fatalf("refused for the wrong reason: %v", rerr)
	}
	if partner.PubKey != "" {
		t.Fatalf("a refused roster must not yield a partner, got key %s", keyTag(partner.PubKey))
	}
}
