package role

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/ratelimit"
	"github.com/tzero78/buddynet/internal/relay"
	"github.com/tzero78/buddynet/internal/tunnel"
)

// The relay endpoint comes from local trust only: --peer-relay wins, otherwise
// a server offer is taken exactly when it sits on the --server host, compared
// as a string and never resolved.
func TestTrustedRelay(t *testing.T) {
	cases := []struct {
		name, local, server, advertised string
		wantEndpoint                    string
		wantSkipped                     bool
	}{
		{"same host, other port", "", "vps.example:51820", "vps.example:51821", "vps.example:51821", false},
		{"foreign host", "", "vps.example:51820", "evil.example:51821", "", true},
		{"IP offered for a named server", "", "vps.example:51820", "203.0.113.5:51821", "", true},
		{"name offered for an IP server", "", "203.0.113.5:51820", "vps.example:51821", "", true},
		{"case and trailing dot fold", "", "VPS.Example.:51820", "vps.example:51821", "vps.example:51821", false},
		{"IPv6 literal spellings fold", "", "[2001:DB8::0001]:51820", "[2001:db8::1]:51821", "[2001:db8::1]:51821", false},
		{"v4-mapped equals v4", "", "[::ffff:203.0.113.5]:51820", "203.0.113.5:51821", "203.0.113.5:51821", false},
		{"--peer-relay beats a foreign offer", "relay.mine:51821", "vps.example:51820", "evil.example:51821", "relay.mine:51821", false},
		{"--peer-relay beats a same-host offer", "relay.mine:51821", "vps.example:51820", "vps.example:51821", "relay.mine:51821", false},
		{"--peer-relay with no offer", "relay.mine:51821", "vps.example:51820", "", "relay.mine:51821", false},
		{"malformed offer", "", "vps.example:51820", "no-port-here", "", true},
		{"offer without server (direct-ish config)", "", "", "vps.example:51821", "", true},
		{"nothing at all", "", "vps.example:51820", "", "", false},
	}
	for _, tc := range cases {
		got := trustedRelay(tc.local, tc.server, tc.advertised)
		if got.endpoint != tc.wantEndpoint {
			t.Errorf("%s: endpoint = %q, want %q", tc.name, got.endpoint, tc.wantEndpoint)
		}
		if (got.skipped != "") != tc.wantSkipped {
			t.Errorf("%s: skipped = %q, want skipped=%v", tc.name, got.skipped, tc.wantSkipped)
		}
		if got.skipped != "" && got.reason == "" {
			t.Errorf("%s: a skipped offer must carry a reason", tc.name)
		}
	}
}

// An untrusted offer is logged once per distinct value and the latch stays
// bounded, so a server rotating offers cannot turn every reconnect into a line.
func TestRelayOfferLatchLogsOncePerValue(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	var l relayOfferLatch
	o := trustedRelay("", "vps.example:51820", "evil.example:51821")
	for i := 0; i < 5; i++ {
		l.noteSkipped(o)
	}
	l.noteSkipped(trustedRelay("", "vps.example:51820", "other.example:51821"))
	l.noteSkipped(relayOffer{}) // nothing skipped: nothing logged
	got := strings.Count(buf.String(), "event=relay-offer-untrusted")
	if got != 2 {
		t.Fatalf("logged %d lines, want 2 (one per distinct value):\n%s", got, buf.String())
	}
	if !strings.Contains(buf.String(), `relay="evil.example:51821"`) || !strings.Contains(buf.String(), "--peer-relay") {
		t.Fatalf("line must name the offer (quoted) and the flag that would allow it:\n%s", buf.String())
	}
	for i := 0; i < 2*maxRelayOfferLatch; i++ {
		l.noteSkipped(trustedRelay("", "vps.example:51820", "h"+strings.Repeat("x", i%40)+":1"))
	}
	if n := len(l.seen); n > maxRelayOfferLatch {
		t.Fatalf("latch grew to %d entries, cap is %d", n, maxRelayOfferLatch)
	}
}

// --- integration: where do relay binds actually go? -------------------------

// relayTestServer runs the production control plane on loopback with a relay
// endpoint to advertise, returning its address and key.
func relayTestServer(t *testing.T, advertise string) (*net.UDPAddr, ed25519.PrivateKey) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); conn.Close() })
	rl := ratelimit.New(rlGlobalRate, rlSrcRate, rlMaxSources)
	go serveControlQUIC(ctx, conn, newHSRegistry(time.Minute), priv, nil, relayAdvert{endpoint: advertise}, rl, nil)
	return conn.LocalAddr().(*net.UDPAddr), priv
}

// ghostPartner registers under token and then stays silent: its candidate is a
// live socket that never answers a punch, so the buddy under test exhausts the
// direct path and has to fall back to whatever relay it trusts.
func ghostPartner(t *testing.T, srv *net.UDPAddr, srvPub ed25519.PublicKey, token string) string {
	t.Helper()
	nd, _ := testNode(t)
	nd.serverPub = srvPub
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	cli, err := tunnel.DialControl(ctx, c, srv, srvPub, nd.priv, controlIdleTimeout)
	if err != nil {
		cancel()
		t.Fatalf("ghost dial: %v", err)
	}
	t.Cleanup(func() { cli.Close(); c.Close(); cancel() })
	raw, err := buildRegister(BuddyConfig{}, nd, token, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Roundtrip(ctx, raw); err != nil {
		t.Fatalf("ghost register: %v", err)
	}
	return nd.pub
}

// byteSink is a UDP socket that counts what arrives and remembers the first
// datagram, standing in for an attacker's host or for a relay.
type byteSink struct {
	conn  *net.UDPConn
	bytes chan int
	first chan []byte
}

func newByteSink(t *testing.T) *byteSink {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	s := &byteSink{conn: c, bytes: make(chan int, 1024), first: make(chan []byte, 1)}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			select {
			case s.first <- append([]byte(nil), buf[:n]...):
			default:
			}
			s.bytes <- n
		}
	}()
	return s
}

func (s *byteSink) addr() string { return s.conn.LocalAddr().String() }

// received sums what arrived within d.
func (s *byteSink) received(d time.Duration) int {
	total := 0
	deadline := time.After(d)
	for {
		select {
		case n := <-s.bytes:
			total += n
		case <-deadline:
			return total
		}
	}
}

// runBuddyAgainstGhost starts the buddy under test against the server and a
// ghost partner; server is the --server string exactly as the operator would
// write it (the same-host rule compares that string).
func runBuddyAgainstGhost(t *testing.T, server string, srv *net.UDPAddr, priv ed25519.PrivateKey, peerRelay string) {
	t.Helper()
	srvPub := priv.Public().(ed25519.PublicKey)
	const token = "relay-trust-token"
	ghostPub := ghostPartner(t, srv, srvPub, token)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cfg := BuddyConfig{
		Server: server, ServerKey: bcrypto.PubKeyB64(srvPub), Token: token,
		PeerKey: ghostPub, PeerRelay: peerRelay,
		PunchDur: 300 * time.Millisecond, IdleTimeout: 60 * time.Second,
		Forward:    "127.0.0.1:1",
		KnownPeers: t.TempDir() + "/known_peers", PeersPath: t.TempDir() + "/peers.json",
	}
	go Buddy(ctx, cfg)
}

// A signed roster naming a relay on a host other than --server must never
// receive a packet from the buddy: the offer is skipped, logged once, and the
// attempt proceeds without a relayed path. On the previous code the buddy bound
// to it (A/B: this test fails there with bytes > 0).
func TestRelayOfferOnForeignHostGetsNoPackets(t *testing.T) {
	if testing.Short() {
		t.Skip("network integration test")
	}
	var buf syncBuf // the buddy logs from its own goroutine
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	attacker := newByteSink(t)
	srv, priv := relayTestServer(t, attacker.addr()) // "127.0.0.1:P"
	// --server is written as "localhost:P": a different host STRING for the same
	// loopback, which is exactly the comparison the rule makes (no resolution).
	runBuddyAgainstGhost(t, "localhost:"+portOf(t, srv.String()), srv, priv, "")

	if n := attacker.received(4 * time.Second); n != 0 {
		t.Fatalf("attacker-controlled relay received %d bytes; a roster offer must never be a target", n)
	}
	if !strings.Contains(buf.String(), "event=relay-offer-untrusted") {
		t.Fatalf("expected a SECURITY line for the skipped offer, log was:\n%s", buf.String())
	}
}

// With --peer-relay the operator names the relay; binds go there and nowhere
// else, whatever the server offers.
func TestPeerRelayFlagIsUsedInsteadOfOffer(t *testing.T) {
	if testing.Short() {
		t.Skip("network integration test")
	}
	attacker := newByteSink(t)
	mine := newByteSink(t)
	srv, priv := relayTestServer(t, attacker.addr())
	runBuddyAgainstGhost(t, "localhost:"+portOf(t, srv.String()), srv, priv, mine.addr())

	select {
	case pkt := <-mine.first:
		if !bytes.HasPrefix(pkt, []byte(relay.BindPrefix)) {
			t.Fatalf("configured relay got %q, want a relay bind", pkt[:min(len(pkt), 16)])
		}
	case <-time.After(6 * time.Second):
		t.Fatal("configured --peer-relay never received a bind")
	}
	if n := attacker.received(500 * time.Millisecond); n != 0 {
		t.Fatalf("server-offered relay received %d bytes although --peer-relay names another", n)
	}
}

// The same-host rule: an offer on the --server host (same string, another
// port) is trusted without any flag — the standard one-VPS deployment.
func TestRelayOfferOnServerHostIsUsed(t *testing.T) {
	if testing.Short() {
		t.Skip("network integration test")
	}
	rly := newByteSink(t) // 127.0.0.1:P2, same host as the server's 127.0.0.1:P1
	srv, priv := relayTestServer(t, rly.addr())
	runBuddyAgainstGhost(t, srv.String(), srv, priv, "")

	select {
	case pkt := <-rly.first:
		if !bytes.HasPrefix(pkt, []byte(relay.BindPrefix)) {
			t.Fatalf("relay got %q, want a relay bind", pkt[:min(len(pkt), 16)])
		}
	case <-time.After(6 * time.Second):
		t.Fatal("same-host relay offer was not used")
	}
}

func portOf(t *testing.T, hostport string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// syncBuf is a log sink safe to read while the buddy goroutine writes to it.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
