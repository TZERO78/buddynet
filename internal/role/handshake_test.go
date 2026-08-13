package role

import (
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
	"strings"
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

// signReg stamps a FRESH nonce on m and signs it, mirroring what buildRegister
// does on the buddy for every single registration attempt. Tests must go through
// this (rather than reusing one signed blob) for the same reason the client does:
// a repeated (key,nonce) is rejected as a replay.
func signReg(t *testing.T, priv ed25519.PrivateKey, m protocol.Message) protocol.Message {
	t.Helper()
	if m.Ver == 0 {
		m.Ver = protocol.Version
	}
	// A registration with no timestamp reads as 1970 and fails the freshness check.
	// buildRegister always stamps one, so this helper must too — otherwise a test
	// silently exercises a message no real client ever sends.
	if m.Ts == 0 {
		m.Ts = time.Now().Unix()
	}
	nonce, err := protocol.NewNonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	m.Nonce = nonce
	m.RegSig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, protocol.RegistrationPayload(m)))
	return m
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

// In open mode (no allowlist) the key-ownership proof is MANDATORY, not merely
// checked when it happens to be there. Under v7 every buddy signs, so an unsigned
// registration is never a legitimate client — and treating the proof as optional
// let whoever omitted the field register under someone else's public key, or under
// no key at all.
func TestOpenModeProofOfPossession(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pkB64 := base64.StdEncoding.EncodeToString(pub)
	ts := time.Now().Unix()
	good := signReg(t, priv, protocol.Message{Type: protocol.TypeRegister, Token: "tok", ID: "A", PubKey: pkB64, Ts: ts})

	// Valid proof: accepted (parks awaiting a partner).
	if _, ok := pairRegister(newHSRegistry(time.Minute), nil, "", v4(1000), good); !ok {
		t.Fatal("valid open-mode registration must be accepted")
	}
	// Forged proof: a present-but-invalid signature is dropped.
	forged := signReg(t, priv, protocol.Message{Type: protocol.TypeRegister, Token: "tok", ID: "A", PubKey: pkB64, Ts: ts})
	forged.Token = "OTHER-token-not-signed"
	if _, ok := pairRegister(newHSRegistry(time.Minute), nil, "", v4(1000), forged); ok {
		t.Fatal("open-mode registration with an invalid key-ownership proof must be dropped")
	}
	// UNSIGNED registration: refused. There is no v7 client that sends one, so the
	// only party that benefits from an optional proof is one that wants to claim a
	// key it does not hold.
	unsigned := protocol.Message{Type: protocol.TypeRegister, Ver: protocol.Version, Token: "tok", ID: "A", PubKey: pkB64}
	if _, ok := pairRegister(newHSRegistry(time.Minute), nil, "", v4(1000), unsigned); ok {
		t.Fatal("an unsigned open-mode registration was accepted — the key-ownership proof is optional again")
	}
}

// The concrete attack the mandatory proof closes: a party that knows the token
// omits reg_sig and registers under the VICTIM's public key. The server would sign
// a roster naming the victim's identity at the attacker's endpoints.
func TestUnsignedRegisterCannotClaimAForeignKey(t *testing.T) {
	victimPub, _, _ := ed25519.GenerateKey(rand.Reader)
	partnerPub, partnerPriv, _ := ed25519.GenerateKey(rand.Reader)
	vB64 := base64.StdEncoding.EncodeToString(victimPub)
	pB64 := base64.StdEncoding.EncodeToString(partnerPub)
	reg := newHSRegistry(time.Minute)

	if _, ok := pairRegister(reg, nil, "", v4(1000), signReg(t, partnerPriv, protocol.Message{
		Type: protocol.TypeRegister, Token: "tok", ID: "P", PubKey: pB64, Ts: time.Now().Unix()})); !ok {
		t.Fatal("setup: the honest peer should park")
	}
	forgery := protocol.Message{Type: protocol.TypeRegister, Ver: protocol.Version, Token: "tok",
		ID: "ATTACKER", PubKey: vB64, VirtualIP: bcrypto.VirtualIPString(victimPub), Ts: time.Now().Unix()}
	if _, ok := pairRegister(reg, nil, "", v4(2000), forgery); ok {
		t.Fatal("an unsigned registration claiming a foreign public key was accepted")
	}
}

// The same hole without any key at all: deriveVIP returns early for an empty
// PubKey, so a made-up virtual IP was signed into the roster and both of the
// token's slots filled — a pairing DoS costing the attacker no cryptography.
func TestKeylessRegisterCannotSquatASlot(t *testing.T) {
	aPub, aPriv, _ := ed25519.GenerateKey(rand.Reader)
	aB64 := base64.StdEncoding.EncodeToString(aPub)
	reg := newHSRegistry(time.Minute)

	if _, ok := pairRegister(reg, nil, "", v4(1000), signReg(t, aPriv, protocol.Message{
		Type: protocol.TypeRegister, Token: "tok", ID: "A", PubKey: aB64, Ts: time.Now().Unix()})); !ok {
		t.Fatal("setup: the honest peer should park")
	}
	squat := protocol.Message{Type: protocol.TypeRegister, Ver: protocol.Version, Token: "tok",
		ID: "SQUAT", VirtualIP: "10.66.1.1", Ts: time.Now().Unix()}
	if _, ok := pairRegister(reg, nil, "", v4(2000), squat); ok {
		t.Fatal("a keyless registration took a token slot and had its claimed virtual IP signed")
	}
	// And the real partner still finds room.
	bPub, bPriv, _ := ed25519.GenerateKey(rand.Reader)
	if _, ok := pairRegister(reg, nil, "", v4(3000), signReg(t, bPriv, protocol.Message{
		Type: protocol.TypeRegister, Token: "tok", ID: "B",
		PubKey: base64.StdEncoding.EncodeToString(bPub), Ts: time.Now().Unix()})); !ok {
		t.Fatal("the real partner was locked out of its own token")
	}
}

// requireV7Fields must sit AFTER the version check: an older client carries no
// nonce, and rejecting it structurally would replace the "update buddynet"
// diagnostic with a silent timeout — the side-by-side rollout in docs/PROTOCOL.md
// depends on that message.
func TestOldClientStillGetsTheVersionDiagnostic(t *testing.T) {
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	enc, err := bcrypto.SealCode("tok", srvPriv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	old := protocol.Message{Type: protocol.TypeRegister, Ver: protocol.Version - 1,
		TokenEnc: enc, ID: "OLD", PubKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))}
	if _, ok := parseRegister(mustMarshal(t, old)); !ok {
		t.Fatal("an older registration must still PARSE, or it can never be told to update")
	}
	if requireV7Fields(old) {
		t.Fatal("a registration without a nonce must not pass the field check")
	}
}

func mustMarshal(t *testing.T, m protocol.Message) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestTokenSquatResidualAndApprovalModeBlock pins the live pentest result: a
// party that learned the token and registers with ITS OWN key passes the F4
// proof-of-possession check (it really owns that key), so in OPEN mode it pairs
// and receives buddy-a's signed PEER_LIST — the documented, inherent residual of
// a bearer-token rendezvous (the impersonation is still stopped downstream by
// --peer-key/TOFU+SAS; only --lab turns it into a MITM). APPROVAL mode
// closes the squat entirely: the attacker key is not allowlisted, so there is no
// pairing and no roster/endpoint leak.
func TestTokenSquatResidualAndApprovalModeBlock(t *testing.T) {
	sign := func(priv ed25519.PrivateKey, token, id, pk string, ts int64) protocol.Message {
		return signReg(t, priv, protocol.Message{Type: protocol.TypeRegister, Token: token, ID: id, PubKey: pk, Ts: ts})
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

// TestIntrusionWarningLatchesOncePerTokenAndStaysBounded guards the squat-
// detection logging against turning a foreign-registration flood into one log
// line per packet: the immediate WARNING must fire at most once per token, and
// the per-token pubkey history must stay bounded regardless of flood volume.
func TestIntrusionWarningLatchesOncePerTokenAndStaysBounded(t *testing.T) {
	r := newHSRegistry(time.Minute)
	r.upsert(regMsg("tok", "A", "pkA"), v4(1000))
	r.upsert(regMsg("tok", "B", "pkB"), v4(2000))

	// Open-mode squat flood: many foreign identities on the same full token (each
	// hits the slot-full rejection path).
	for i := 0; i < 500; i++ {
		r.upsert(regMsg("tok", fmt.Sprintf("X%d", i), fmt.Sprintf("pkX%d", i)), v4(3000+i))
	}
	// Key-rotation flood reusing an existing slot exercises the new-pubkey path.
	for i := 0; i < 500; i++ {
		r.upsert(regMsg("tok", "A", fmt.Sprintf("pkA%d", i)), v4(1000))
	}

	if got := len(r.seenPKs["tok"]); got > maxIDsPerToken+1 {
		t.Fatalf("seenPKs must stay bounded, got %d (want <= %d)", got, maxIDsPerToken+1)
	}
	if got := len(r.intruderWarned); got != 1 {
		t.Fatalf("intrusion warning must latch exactly once per token, got %d entries", got)
	}
}

// TestReplayIsLoggedAndCounted locks the P0 fix: a replayed approval-mode
// registration is no longer silent — it is dropped AND increments the replay
// counter that feeds the stats ALERT line.
func TestReplayIsLoggedAndCounted(t *testing.T) {
	hsStats.replay.Store(0)
	t.Cleanup(func() { hsStats.replay.Store(0) })

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pkB64 := base64.StdEncoding.EncodeToString(pub)
	allow := filepath.Join(t.TempDir(), "authorized")
	if err := os.WriteFile(allow, []byte(pkB64+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	authz, err := newAuthorizer(allow, srvPriv)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Now().Unix()
	m := signReg(t, priv, protocol.Message{Type: protocol.TypeRegister, Token: "tok", ID: "A", PubKey: pkB64, Ts: ts})

	reg := newHSRegistry(time.Minute)
	if _, ok := pairRegister(reg, authz, "", v4(1000), m); !ok {
		t.Fatal("first allowlisted registration should be accepted")
	}
	if _, ok := pairRegister(reg, authz, "", v4(2000), m); ok {
		t.Fatal("a replayed registration (same key+nonce) must be dropped")
	}
	if got := hsStats.replay.Load(); got != 1 {
		t.Fatalf("replay counter = %d, want 1 (replay must be counted, not silent)", got)
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
		"":                           false,
		"ok":                         true,
		"AbC-123_xyz":                true, // base64url, what every generator emits
		strings.Repeat("a", 128):     true, // exactly the limit
		strings.Repeat("a", 129):     false,
		string(make([]byte, 128)):    false, // 128 NUL bytes: the old check called this VALID
		"ok\nSECURITY: event=forged": false, // the log-injection payload
		"ok\rSECURITY: event=forged": false,
		"tab\there":                  false,
		"space here":                 false,
		"semi;colon":                 false,
		"quote\"here":                false,
		"ünïcode":                    false,
	}
	for in, want := range cases {
		if got := validField(in); got != want {
			t.Errorf("validField(%q) = %v, want %v", in, got, want)
		}
	}
}

// The concrete attack: REGISTER.ID is written into the PAIRED line, so an id
// carrying a newline used to forge a second line in the operator's audit trail —
// in the exact format the project's own log schema uses for security events.
func TestRegisterIDCannotInjectALogLine(t *testing.T) {
	const evil = "ok\nSECURITY: event=forged-by-attacker detail=\"injected\""
	if validField(evil) {
		t.Fatal("an id with a newline is still accepted at the boundary")
	}
	// And it cannot even reach the pairing core: parseRegister rejects it.
	raw, err := json.Marshal(protocol.Message{
		Type: protocol.TypeRegister, Ver: protocol.Version, Token: "tok", ID: evil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parseRegister(raw); ok {
		t.Fatal("a registration with a control character in its id was parsed")
	}
}

// The pairing is announced ONCE, at the transition. A waiting buddy re-registers
// about once a second for as long as the tunnel lives, so logging on every
// registration wrote a line per second per pair in NORMAL operation — and let
// anyone who knows a token turn that into a flood.
func TestPairedIsLoggedOncePerToken(t *testing.T) {
	aPub, aPriv, _ := ed25519.GenerateKey(rand.Reader)
	xPub, xPriv, _ := ed25519.GenerateKey(rand.Reader)
	aB64 := base64.StdEncoding.EncodeToString(aPub)
	xB64 := base64.StdEncoding.EncodeToString(xPub)
	tokenLogKey = []byte("test-log-key")

	reg := newHSRegistry(time.Minute)
	if _, ok := pairRegister(reg, nil, "", v4(1000), signReg(t, aPriv, protocol.Message{
		Type: protocol.TypeRegister, Token: "tok", ID: "A", PubKey: aB64})); !ok {
		t.Fatal("setup: first peer should park")
	}
	out := captureLog(t, func() {
		for i := 0; i < 20; i++ {
			pairRegister(reg, nil, "", v4(2000), signReg(t, xPriv, protocol.Message{
				Type: protocol.TypeRegister, Token: "tok", ID: "X", PubKey: xB64}))
		}
	})
	if n := strings.Count(out, "PAIRED:"); n != 1 {
		t.Fatalf("20 registrations on a paired token produced %d PAIRED lines, want 1", n)
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
	go serveControlQUIC(ctx, srvConn, reg, srvPriv, nil, relayAdvert{}, rl, nil)

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
		cfg := BuddyConfig{}
		nd := &node{id: randomID(), pub: bcrypto.PubKeyB64(pub), vip: bcrypto.VirtualIPString(pub), priv: priv, serverPub: srvPub}
		p, _, err := buddyRegister(c, []*net.UDPAddr{srvAddr}, cfg, nd, "tok", 15*time.Second, nil)
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
