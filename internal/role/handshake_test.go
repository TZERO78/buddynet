package role

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/tzero78/buddynet/pkg/protocol"
)

func v4(port int) *net.UDPAddr { return &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: port} }
func v6(port int) *net.UDPAddr { return &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: port} }

func regMsg(token, id, pk string) protocol.Message {
	return protocol.Message{Type: protocol.TypeRegister, Ver: protocol.Version, Token: token, ID: id, PubKey: pk}
}

// --- registry / pairing logic ------------------------------------------

func TestUpsertPairsTwoDistinctPeers(t *testing.T) {
	r := newHSRegistry(time.Minute)

	_, partner, ok := r.upsert(regMsg("tok", "A", "pkA"), v4(1000))
	if !ok || partner != nil {
		t.Fatalf("first peer should park: ok=%v partner=%v", ok, partner)
	}

	self, partner, ok := r.upsert(regMsg("tok", "B", "pkB"), v4(2000))
	if !ok {
		t.Fatal("second peer rejected")
	}
	if self.id != "B" {
		t.Fatalf("self id = %q, want B", self.id)
	}
	if partner == nil || partner.id != "A" {
		t.Fatalf("partner = %v, want id A", partner)
	}
	if partner.pubkey != "pkA" {
		t.Fatalf("partner pubkey = %q, want pkA", partner.pubkey)
	}
}

func TestUpsertSameIDDoesNotSelfPair(t *testing.T) {
	r := newHSRegistry(time.Minute)
	r.upsert(regMsg("tok", "A", "pk"), v4(1000))
	// Same peer re-registering over its other stack must NOT pair with itself.
	_, partner, ok := r.upsert(regMsg("tok", "A", "pk"), v6(1000))
	if !ok {
		t.Fatal("re-register rejected")
	}
	if partner != nil {
		t.Fatalf("self-pairing happened: %v", partner)
	}
}

func TestUpsertRejectsThirdPeer(t *testing.T) {
	r := newHSRegistry(time.Minute)
	r.upsert(regMsg("tok", "A", ""), v4(1000))
	r.upsert(regMsg("tok", "B", ""), v4(2000))
	_, _, ok := r.upsert(regMsg("tok", "C", ""), v4(3000))
	if ok {
		t.Fatal("third peer on a token must be rejected (maxIDsPerToken)")
	}
}

func TestUpsertEvictsStalestOverMaxTokens(t *testing.T) {
	r := newHSRegistry(time.Minute)
	for i := 0; i < maxTokens; i++ {
		if _, _, ok := r.upsert(regMsg(fmt.Sprintf("tok-%d", i), "A", ""), v4(1000+i)); !ok {
			t.Fatalf("token %d unexpectedly rejected", i)
		}
	}
	// Make tok-0 clearly the stalest and tok-1 clearly fresh, so eviction is
	// deterministic: a source-spoofed one-shot token ages, a refreshed pair stays.
	for _, p := range r.waiting["tok-0"] {
		p.seen = time.Now().Add(-time.Hour)
	}
	for _, p := range r.waiting["tok-1"] {
		p.seen = time.Now()
	}

	// A new token must NOT be hard-rejected at the cap; it evicts the stalest.
	if _, _, ok := r.upsert(regMsg("fresh", "A", ""), v4(9999)); !ok {
		t.Fatal("new token rejected; eviction should have made room")
	}
	if len(r.waiting) != maxTokens {
		t.Fatalf("table size = %d, want %d (one in, one out)", len(r.waiting), maxTokens)
	}
	if _, ok := r.waiting["tok-0"]; ok {
		t.Fatal("stalest token (tok-0) should have been evicted")
	}
	if _, ok := r.waiting["fresh"]; !ok {
		t.Fatal("new token not inserted after eviction")
	}
	if _, ok := r.waiting["tok-1"]; !ok {
		t.Fatal("fresh token tok-1 wrongly evicted instead of the stalest")
	}
}

func TestObserveCapsCandidatesAndFlagsV6(t *testing.T) {
	p := &hsPeer{id: "A", cands: map[string]protocol.Candidate{}}
	p.observe(v4(1000)) // v4
	p.observe(v6(2000)) // v6
	if len(p.cands) != 2 {
		t.Fatalf("got %d candidates, want 2", len(p.cands))
	}
	var sawV6 bool
	for _, c := range p.cands {
		if c.V6 {
			sawV6 = true
		}
	}
	if !sawV6 {
		t.Fatal("IPv6 candidate not flagged V6")
	}
	// Adding beyond the cap must be ignored.
	for i := 0; i < maxCandsPerPeer+10; i++ {
		p.observe(v4(3000 + i))
	}
	if len(p.cands) > maxCandsPerPeer {
		t.Fatalf("candidates = %d, exceeds cap %d", len(p.cands), maxCandsPerPeer)
	}
}

func TestReapDropsStale(t *testing.T) {
	r := newHSRegistry(time.Minute)
	r.upsert(regMsg("tok", "A", ""), v4(1000))
	// Force the entry stale, then reap manually (don't wait for the ticker).
	r.mu.Lock()
	r.waiting["tok"]["A"].seen = time.Now().Add(-2 * time.Minute)
	for token, bucket := range r.waiting {
		for id, p := range bucket {
			if time.Since(p.seen) > r.ttl {
				delete(bucket, id)
			}
		}
		if len(bucket) == 0 {
			delete(r.waiting, token)
		}
	}
	n := len(r.waiting)
	r.mu.Unlock()
	if n != 0 {
		t.Fatalf("stale token not reaped, %d buckets remain", n)
	}
}

func TestValidField(t *testing.T) {
	cases := map[string]bool{
		"":                        false,
		"ok":                      true,
		string(make([]byte, 128)): true,  // exactly the limit
		string(make([]byte, 129)): false, // over the limit
	}
	for in, want := range cases {
		if got := validField(in); got != want {
			t.Errorf("validField(len %d) = %v, want %v", len(in), got, want)
		}
	}
}

func TestShortHashStableAndHidesToken(t *testing.T) {
	const secret = "super-secret-token"
	a, b := shortHash(secret), shortHash(secret)
	if a != b {
		t.Fatal("shortHash not deterministic")
	}
	if len(a) != 8 {
		t.Fatalf("shortHash len = %d, want 8", len(a))
	}
	if a == secret || len(a) >= len(secret) {
		t.Fatal("shortHash leaks the token")
	}
	if shortHash("other") == a {
		t.Fatal("shortHash collides on distinct tokens")
	}
}

// candidates() must sort, so the same endpoints observed in any order yield the
// identical roster the server signs and the buddy reconstructs.
func TestCandidatesAreCanonical(t *testing.T) {
	p1 := &hsPeer{cands: map[string]protocol.Candidate{}}
	p1.observe(v4(2000))
	p1.observe(v6(1000))
	p2 := &hsPeer{cands: map[string]protocol.Candidate{}}
	p2.observe(v6(1000))
	p2.observe(v4(2000))

	if !reflect.DeepEqual(p1.candidates(), p2.candidates()) {
		t.Fatalf("candidates not canonical:\n p1=%v\n p2=%v", p1.candidates(), p2.candidates())
	}
}

// --- end-to-end over a real UDP socket ---------------------------------

func TestIntegrationPairingOverUDP(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srvAddr := conn.LocalAddr().(*net.UDPAddr)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	reg := newHSRegistry(time.Minute)
	// Mirror Handshake's inner loop: read a datagram, hand it to handleRegister.
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			raw := make([]byte, n)
			copy(raw, buf[:n])
			handleRegister(conn, reg, priv, nil, "", src, raw) // nil authz = open mode
		}
	}()
	t.Cleanup(func() { cancel(); conn.Close() })

	dial := func() *net.UDPConn {
		c, err := net.DialUDP("udp", nil, srvAddr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		return c
	}
	register := func(c *net.UDPConn, token, id, pk string) {
		b, _ := json.Marshal(regMsg(token, id, pk))
		if _, err := c.Write(b); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	readReply := func(c *net.UDPConn) (protocol.Message, error) {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1500)
		n, err := c.Read(buf)
		if err != nil {
			return protocol.Message{}, err
		}
		var m protocol.Message
		return m, json.Unmarshal(buf[:n], &m)
	}

	a, b := dial(), dial()
	defer a.Close()
	defer b.Close()

	// A registers first and should get no reply yet (parked).
	register(a, "tok", "A", "pkA")
	a.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := a.Read(make([]byte, 1500)); err == nil {
		t.Fatal("A got a reply while still alone; expected to be parked")
	}

	// B registers and must immediately receive a signed PEER_LIST naming A.
	register(b, "tok", "B", "pkB")
	got, err := readReply(b)
	if err != nil {
		t.Fatalf("B read: %v", err)
	}
	if got.Type != protocol.TypePeerList || len(got.Peers) != 1 {
		t.Fatalf("B got %+v, want a one-peer PEER_LIST", got)
	}
	if got.Peers[0].ID != "A" || got.Peers[0].PubKey != "pkA" {
		t.Fatalf("B got peer %+v, want A/pkA", got.Peers[0])
	}
	if len(got.Peers[0].Candidates) < 1 {
		t.Fatal("B got no candidates for A")
	}
	// The server's signature must verify against its public key over the
	// canonical roster exactly as received.
	sig, err := base64.StdEncoding.DecodeString(got.Sig)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !ed25519.Verify(pub, protocol.PeerListPayload("tok", got.Ts, canonicalPeers(got.Peers)), sig) {
		t.Fatal("server signature did not verify")
	}
	// Tampering with the partner's public key must invalidate the signature.
	tampered := canonicalPeers(got.Peers)
	tampered[0].PubKey = "attacker-key"
	if ed25519.Verify(pub, protocol.PeerListPayload("tok", got.Ts, tampered), sig) {
		t.Fatal("signature still valid after tampering with the public key")
	}

	// A re-registers (retransmit) and now learns about B.
	register(a, "tok", "A", "pkA")
	got, err = readReply(a)
	if err != nil {
		t.Fatalf("A read: %v", err)
	}
	if len(got.Peers) != 1 || got.Peers[0].ID != "B" || got.Peers[0].PubKey != "pkB" {
		t.Fatalf("A got %+v, want peer B/pkB", got.Peers)
	}
}
