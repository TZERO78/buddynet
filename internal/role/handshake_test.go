package role

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/ratelimit"
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

// F4: in open mode (no allowlist) a buddy always signs its REGISTER, so when a
// signature is present we verify it — a registration claiming a public key it
// does not own (forged/mismatched signature) must be dropped, while a valid one
// (and a legacy unsigned one) is accepted.
func TestOpenModeProofOfPossession(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pkB64 := base64.StdEncoding.EncodeToString(pub)
	ts := time.Now().Unix()
	good := protocol.Message{Type: protocol.TypeRegister, Ver: protocol.Version, Token: "tok", ID: "A", PubKey: pkB64, Ts: ts}
	good.RegSig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, protocol.RegistrationPayload("tok", "A", pkB64, ts)))

	// Valid proof: accepted (parks awaiting a partner).
	if _, ok := pairRegister(newHSRegistry(time.Minute), nil, "", v4(1000), good); !ok {
		t.Fatal("valid open-mode registration must be accepted")
	}
	// Forged proof: a present-but-invalid signature is dropped.
	forged := good
	forged.RegSig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, protocol.RegistrationPayload("OTHER", "A", pkB64, ts)))
	if _, ok := pairRegister(newHSRegistry(time.Minute), nil, "", v4(1000), forged); ok {
		t.Fatal("open-mode registration with an invalid key-ownership proof must be dropped")
	}
	// Legacy unsigned registration: still accepted (token-gated, backward compatible).
	legacy := protocol.Message{Type: protocol.TypeRegister, Ver: protocol.Version, Token: "tok", ID: "A", PubKey: pkB64}
	if _, ok := pairRegister(newHSRegistry(time.Minute), nil, "", v4(1000), legacy); !ok {
		t.Fatal("legacy unsigned open-mode registration must still be accepted")
	}
}

// TestTokenSquatResidualAndApprovalModeBlock pins the live pentest result: a
// party that learned the token and registers with ITS OWN key passes the F4
// proof-of-possession check (it really owns that key), so in OPEN mode it pairs
// and receives buddy-a's signed PEER_LIST — the documented, inherent residual of
// a bearer-token rendezvous (the impersonation is still stopped downstream by
// --peer-key/TOFU+SAS; only --insecure turns it into a MITM). APPROVAL mode
// closes the squat entirely: the attacker key is not allowlisted, so there is no
// pairing and no roster/endpoint leak.
func TestTokenSquatResidualAndApprovalModeBlock(t *testing.T) {
	sign := func(priv ed25519.PrivateKey, token, id, pk string, ts int64) protocol.Message {
		m := protocol.Message{Type: protocol.TypeRegister, Ver: protocol.Version, Token: token, ID: id, PubKey: pk, Ts: ts}
		m.RegSig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, protocol.RegistrationPayload(token, id, pk, ts)))
		return m
	}
	aPub, aPriv, _ := ed25519.GenerateKey(rand.Reader)
	xPub, xPriv, _ := ed25519.GenerateKey(rand.Reader) // attacker's own key
	aB64 := base64.StdEncoding.EncodeToString(aPub)
	xB64 := base64.StdEncoding.EncodeToString(xPub)
	ts := time.Now().Unix()

	// OPEN mode: buddy-a parks, the squat pairs and gets a roster (the residual).
	open := newHSRegistry(time.Minute)
	if _, ok := pairRegister(open, nil, "", v4(1000), sign(aPriv, "tok", "A", aB64, ts)); !ok {
		t.Fatal("open mode: buddy-a should park")
	}
	peers, ok := pairRegister(open, nil, "", v4(2000), sign(xPriv, "tok", "X", xB64, ts))
	if !ok || len(peers) == 0 {
		t.Fatal("open mode: a token-holder squat is expected to pair (documented residual)")
	}

	// APPROVAL mode: only buddy-a is allowlisted; the squat is dropped.
	allow := filepath.Join(t.TempDir(), "authorized")
	if err := os.WriteFile(allow, []byte(aB64+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	authz, err := newAuthorizer(allow, srvPriv)
	if err != nil {
		t.Fatal(err)
	}
	reg := newHSRegistry(time.Minute)
	if _, ok := pairRegister(reg, authz, "", v4(1000), sign(aPriv, "tok", "A", aB64, ts)); !ok {
		t.Fatal("approval mode: allowlisted buddy-a should be accepted")
	}
	if peers, ok := pairRegister(reg, authz, "", v4(2000), sign(xPriv, "tok", "X", xB64, ts)); ok || len(peers) > 0 {
		t.Fatalf("approval mode must block the squat: ok=%v peers=%d", ok, len(peers))
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

func TestIntegrationPairingOverQUIC(t *testing.T) {
	srvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	srvPub := srvPriv.Public().(ed25519.PublicKey)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); srvConn.Close() })
	reg := newHSRegistry(time.Minute)
	rl := ratelimit.New(rlGlobalRate, rlSrcRate, rlMaxSources)
	go serveControlQUIC(ctx, srvConn, reg, srvPriv, nil, "", rl, nil)

	srvAddr := srvConn.LocalAddr().(*net.UDPAddr)
	type result struct {
		peer protocol.Peer
		err  error
	}

	// Two buddies register over QUIC under the same token; each must learn the
	// other. A parks until B arrives, exercising the polling path.
	run := func(out chan<- result) {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		pub := priv.Public().(ed25519.PublicKey)
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			out <- result{err: err}
			return
		}
		defer c.Close()
		cfg := BuddyConfig{QUIC: true}
		p, err := buddyRegisterQUIC(c, []*net.UDPAddr{srvAddr}, cfg, "tok",
			randomID(), bcrypto.PubKeyB64(pub), bcrypto.VirtualIPString(pub), priv, srvPub, 15*time.Second)
		out <- result{peer: p, err: err}
	}

	ach, bch := make(chan result, 1), make(chan result, 1)
	go run(ach)
	go run(bch)

	for i, ch := range []chan result{ach, bch} {
		select {
		case r := <-ch:
			if r.err != nil {
				t.Fatalf("buddy %d register over QUIC: %v", i, r.err)
			}
			if r.peer.PubKey == "" || r.peer.VirtualIP == "" {
				t.Fatalf("buddy %d got an empty partner: %+v", i, r.peer)
			}
		case <-time.After(20 * time.Second):
			t.Fatalf("buddy %d timed out pairing over QUIC", i)
		}
	}
}

func TestCookieValidatesSourceAndEpoch(t *testing.T) {
	cookieKey = deriveSubkey(bytes.Repeat([]byte{7}, ed25519.SeedSize), "buddynet-cookie-v1")
	ip := net.IPv4(203, 0, 113, 5)

	c := freshCookie(ip)
	if !validCookie(c, ip) {
		t.Fatal("a fresh cookie must validate for its own source IP")
	}
	if validCookie(c, net.IPv4(203, 0, 113, 6)) {
		t.Fatal("a cookie must not validate for a different source IP")
	}
	if validCookie("", ip) {
		t.Fatal("an empty cookie must never validate")
	}
	if validCookie("not-a-real-cookie", ip) {
		t.Fatal("a forged cookie must not validate")
	}
	// A cookie from two epochs ago is outside the accepted (now, now-1) window.
	old := computeCookie(ip, time.Now().UnixNano()/int64(cookieEpoch)-2)
	if validCookie(old, ip) {
		t.Fatal("a cookie older than the previous epoch must not validate")
	}
}

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
	// register performs the address-validation cookie round-trip transparently:
	// the first REGISTER is answered with a COOKIE challenge, which the second
	// REGISTER echoes. Callers then read the validated reply (parked or PEER_LIST).
	register := func(c *net.UDPConn, token, id, pk string) {
		b, _ := json.Marshal(regMsg(token, id, pk))
		if _, err := c.Write(b); err != nil {
			t.Fatalf("write: %v", err)
		}
		r, err := readReply(c)
		if err != nil || r.Type != protocol.TypeCookie || r.Cookie == "" {
			t.Fatalf("expected cookie challenge, got %+v (err %v)", r, err)
		}
		m := regMsg(token, id, pk)
		m.Cookie = r.Cookie
		b, _ = json.Marshal(m)
		if _, err := c.Write(b); err != nil {
			t.Fatalf("write: %v", err)
		}
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
