package role

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/ratelimit"
	"github.com/tzero78/buddynet/internal/tunnel"
	"github.com/tzero78/buddynet/pkg/protocol"
)

// enrollServer starts an approval-mode handshake server on QUIC and returns its
// address, the allowlist path and the authorizer the operator's approve would
// write into.
func enrollServer(t *testing.T, allowed ...string) (*net.UDPAddr, ed25519.PublicKey, string, *authorizer, *hsRegistry) {
	t.Helper()
	srvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)

	path := filepath.Join(t.TempDir(), "authorized")
	var body string
	for _, k := range allowed {
		body += k + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	authz, err := newAuthorizer(path, srvPriv)
	if err != nil {
		t.Fatalf("newAuthorizer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); srvConn.Close() })
	rl := ratelimit.New(rlGlobalRate, rlSrcRate, rlMaxSources)
	reg := newHSRegistry(time.Minute)
	go serveControlQUIC(ctx, srvConn, reg, srvPriv, authz, relayAdvert{}, rl, nil)

	return srvConn.LocalAddr().(*net.UDPAddr), srvPriv.Public().(ed25519.PublicKey), path, authz, reg
}

// enrollClient registers once over QUIC and reports whether the server answered
// with a PEER_LIST (i.e. it was authorized at all) rather than dropping it.
func enrollClient(t *testing.T, srvAddr *net.UDPAddr, srvPub ed25519.PublicKey, nd *node, code string) bool {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cli, err := tunnel.DialControl(ctx, c, srvAddr, srvPub, nd.priv, controlIdleTimeout)
	if err != nil {
		t.Fatalf("an unknown client must still complete the TLS handshake (enrollment): %v", err)
	}
	defer cli.Close()

	raw, err := buildRegister(BuddyConfig{Code: code}, nd, "tok", "")
	if err != nil {
		t.Fatal(err)
	}
	rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
	defer rcancel()
	resp, err := cli.Roundtrip(rctx, raw)
	if err != nil || len(resp) == 0 {
		return false
	}
	var m protocol.Message
	return json.Unmarshal(resp, &m) == nil && m.Type == protocol.TypePeerList && m.Sig != ""
}

// An allowlisted client registers normally; an unknown client with no code is
// refused; an unknown client WITH a valid code is recorded as pending — and once
// the operator approves it, its very next attempt succeeds with no restart.
func TestQUICEnrollmentLifecycle(t *testing.T) {
	stranger, _ := testNode(t)
	srvAddr, srvPub, allowPath, authz, _ := enrollServer(t)
	stranger.serverPub = srvPub

	// 1. Unknown key, no code: refused, and nothing is recorded.
	if enrollClient(t, srvAddr, srvPub, stranger, "") {
		t.Fatal("an unknown client without an enrollment code must be refused")
	}
	// Under the lock: the server goroutine writes a.pend from its own goroutine,
	// so reading the map bare races it (the race detector catches this on a loaded
	// CI runner and rarely on a quiet laptop).
	authz.mu.RLock()
	pending := len(authz.pend)
	authz.mu.RUnlock()
	if pending != 0 {
		t.Fatal("a codeless stranger must not create a pending enrollment")
	}

	// 2. Unknown key WITH a code: still refused (not yet approved), but now pending.
	const code = "ENROLL-CODE-1234"
	if enrollClient(t, srvAddr, srvPub, stranger, code) {
		t.Fatal("an un-approved client must not pair, even with a valid code")
	}
	authz.mu.RLock()
	entry, ok := authz.pend[shortHash(code)]
	authz.mu.RUnlock()
	if !ok {
		t.Fatal("a valid enrollment code did not reach the application layer — enrollment is broken")
	}
	if entry.Key != stranger.pub {
		t.Fatalf("pending entry bound to %q, want the enrolling key %q", entry.Key, stranger.pub)
	}

	// 3. The operator approves BY KEY — the pending set is memory-only since
	// v5.0.0, so the log line is what carries the key to them. The hot reload
	// picks the approval up.
	if err := ApproveKey(allowPath, stranger.pub, "code:"+shortHash(code)); err != nil {
		t.Fatalf("ApproveKey: %v", err)
	}
	if err := authz.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !authz.allowed(stranger.pub) {
		t.Fatal("the approved key is not on the allowlist after reload")
	}

	// 4. The SAME client, without restarting, now registers successfully — its next
	//    attempt carries a fresh nonce, so approval takes effect immediately.
	if !enrollClient(t, srvAddr, srvPub, stranger, code) {
		t.Fatal("an approved client must register on its next attempt, with no restart")
	}
}

// An allowlisted client is served from the start.
func TestQUICAllowlistedClientRegisters(t *testing.T) {
	nd, _ := testNode(t)
	srvAddr, srvPub, _, _, _ := enrollServer(t, nd.pub)
	nd.serverPub = srvPub
	if !enrollClient(t, srvAddr, srvPub, nd, "") {
		t.Fatal("an allowlisted client was not served")
	}
}

// A REGISTER must claim exactly the key its TLS connection authenticated with.
// Otherwise an attacker holding key X could bind an enrollment code (or a
// registration) to victim key Y.
func TestRegistrationMustMatchTLSKey(t *testing.T) {
	attacker, _ := testNode(t)
	victim, _ := testNode(t)

	m := protocol.Message{PubKey: attacker.pub}
	if !registrationMatchesTLSKey(m, attacker.priv.Public().(ed25519.PublicKey)) {
		t.Fatal("a registration under its own authenticated key must be accepted")
	}
	m.PubKey = victim.pub
	if registrationMatchesTLSKey(m, attacker.priv.Public().(ed25519.PublicKey)) {
		t.Fatal("a registration claiming another key than the TLS handshake proved was accepted")
	}
	for name, bad := range map[string]protocol.Message{
		"empty pubkey":     {PubKey: ""},
		"not base64":       {PubKey: "@@@@"},
		"wrong key length": {PubKey: "c2hvcnQ="},
	} {
		if registrationMatchesTLSKey(bad, attacker.priv.Public().(ed25519.PublicKey)) {
			t.Fatalf("%s was accepted as a key match", name)
		}
	}
	if registrationMatchesTLSKey(protocol.Message{PubKey: attacker.pub}, nil) {
		t.Fatal("a connection with no authenticated key must never match")
	}
}

// The binding must hold over a REAL QUIC connection, not just in the predicate:
// an attacker connects with its own key and sends a REGISTER that is perfectly
// valid on its own terms — correctly signed by the VICTIM's private key, naming
// the victim's public key, carrying a valid enrollment code. The only thing wrong
// with it is that it did not come over the victim's connection.
//
// It must be dropped, the connection closed, and nothing recorded for either key.
func TestQUICRegistrationClaimingAnotherKeyIsDropped(t *testing.T) {
	attacker, _ := testNode(t)
	victim, _ := testNode(t)
	srvAddr, srvPub, allowPath, authz, reg := enrollServer(t)
	attacker.serverPub, victim.serverPub = srvPub, srvPub

	allowBefore, err := os.ReadFile(allowPath)
	if err != nil {
		t.Fatal(err)
	}
	hsStats.keyMismatch.Store(0)
	t.Cleanup(func() { hsStats.keyMismatch.Store(0) })

	c, lerr := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if lerr != nil {
		t.Fatal(lerr)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The TLS handshake authenticates the ATTACKER's key.
	cli, err := tunnel.DialControl(ctx, c, srvAddr, srvPub, attacker.priv, controlIdleTimeout)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cli.Close()

	// Positive control first, on this very connection: the attacker's OWN
	// registration is processed (it lands in pending), so anything that fails
	// below fails because of the mismatch and nothing else.
	const ownCode = "ATTACKER-OWN-CODE"
	ownReg, err := buildRegister(BuddyConfig{Code: ownCode}, attacker, "tok", "")
	if err != nil {
		t.Fatal(err)
	}
	rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
	_, err = cli.Roundtrip(rctx, ownReg)
	rcancel()
	if err != nil {
		t.Fatalf("the attacker's own registration should have been processed: %v", err)
	}
	authz.mu.RLock()
	_, ownPending := authz.pend[shortHash(ownCode)]
	authz.mu.RUnlock()
	if !ownPending {
		t.Fatal("positive control failed: a well-formed registration did not reach the app layer")
	}

	// Now the impersonation. Signed by the victim's key, sent over the attacker's
	// authenticated connection.
	const victimCode = "VICTIM-CODE-XYZ"
	forged, err := buildRegister(BuddyConfig{Code: victimCode}, victim, "tok", "")
	if err != nil {
		t.Fatal(err)
	}
	fctx, fcancel := context.WithTimeout(ctx, 5*time.Second)
	resp, ferr := cli.Roundtrip(fctx, forged)
	fcancel()
	if ferr == nil && len(resp) > 0 {
		t.Fatalf("a registration claiming another key was answered: %q", resp)
	}

	// Nothing may have been recorded for the victim.
	authz.mu.RLock()
	_, victimPending := authz.pend[shortHash(victimCode)]
	pendCount := len(authz.pend)
	authz.mu.RUnlock()
	if victimPending {
		t.Fatal("an enrollment code was pended against a key that never authenticated")
	}
	if pendCount != 1 {
		t.Fatalf("pending holds %d entries, want only the attacker's own", pendCount)
	}

	// The allowlist must be byte-for-byte untouched: an impersonation attempt may
	// never move a key towards being authorized.
	allowAfter, rerr := os.ReadFile(allowPath)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !bytes.Equal(allowBefore, allowAfter) {
		t.Fatalf("the allowlist changed during an impersonation attempt: %q -> %q", allowBefore, allowAfter)
	}
	if authz.allowed(victim.pub) || authz.allowed(attacker.pub) {
		t.Fatal("an impersonation attempt authorized a key")
	}

	// No peer state either: the victim must not appear in the pairing registry, so
	// no roster, no endpoint and no token slot can be attributed to it.
	reg.mu.Lock()
	waiting := len(reg.waiting)
	var sawVictim bool
	for _, bucket := range reg.waiting {
		for _, p := range bucket {
			if p.pubkey == victim.pub {
				sawVictim = true
			}
		}
	}
	reg.mu.Unlock()
	if sawVictim {
		t.Fatal("the impersonated key was persisted into the pairing registry")
	}
	if waiting != 0 {
		t.Fatalf("the registry holds %d token slot(s) after two refused registrations", waiting)
	}

	// The security counter must record it — a silent drop gives the operator nothing.
	if got := hsStats.keyMismatch.Load(); got != 1 {
		t.Fatalf("key-mismatch counter = %d, want 1 (the event must be counted, not silent)", got)
	}

	// And the connection itself must be gone, not merely unanswered: a follow-up
	// request on it must fail.
	nctx, ncancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer ncancel()
	again, err := buildRegister(BuddyConfig{}, attacker, "tok", "")
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := cli.Roundtrip(nctx, again); err == nil && len(resp) > 0 {
		t.Fatal("the connection survived an impersonation attempt; it must be closed")
	}
}

// A stranger cannot bind an enrollment code to somebody else's public key: the
// code is inside the registration signature AND the registration is bound to the
// TLS-authenticated key, so the pending entry can only ever name the enrolling key.
func TestEnrollmentCannotTargetAnotherKey(t *testing.T) {
	victim, _ := testNode(t)
	attacker, _ := testNode(t)
	srvAddr, srvPub, _, authz, _ := enrollServer(t)
	victim.serverPub, attacker.serverPub = srvPub, srvPub

	const code = "VICTIM-CODE"
	if enrollClient(t, srvAddr, srvPub, attacker, code) {
		t.Fatal("an un-approved client must not pair")
	}
	authz.mu.RLock()
	entry := authz.pend[shortHash(code)]
	authz.mu.RUnlock()
	if entry.Key == victim.pub {
		t.Fatal("an enrollment code was bound to a key that did not present it")
	}
	if entry.Key != attacker.pub {
		t.Fatalf("pending entry names %q, want the key that actually enrolled", entry.Key)
	}
}

// Unknown keys are rate-limited far more tightly than allowlisted ones, so a
// stranger flood cannot spend an approved buddy's budget or fill the pending DB.
func TestEnrollmentRateLimitIsStricterThanNormal(t *testing.T) {
	if rlEnrollSrcRate >= rlSrcRate || rlEnrollGlobalRate >= rlGlobalRate {
		t.Fatalf("enrollment limits (%d/%d) must be stricter than the normal ones (%d/%d)",
			rlEnrollGlobalRate, rlEnrollSrcRate, rlGlobalRate, rlSrcRate)
	}
	nd, srvPriv := testNode(t)
	authz := newTestAuthorizer(t, srvPriv) // allowlist is EMPTY: nd is unknown
	reg := newHSRegistry(time.Minute)

	hsStats.enrollLimited.Store(0)
	t.Cleanup(func() { hsStats.enrollLimited.Store(0) })

	// Burst well past the per-source enrollment allowance from one address.
	for i := 0; i < 200; i++ {
		m := unmarshalRegister(t, mustBuild(t, nd), srvPriv)
		if _, ok := pairRegister(reg, authz, "", v4(1000), m); ok {
			t.Fatal("an unknown key must never pair")
		}
	}
	if hsStats.enrollLimited.Load() == 0 {
		t.Fatal("a stranger flood was not rate-limited on the enrollment path")
	}
}

// The bounded replay cache evicts its oldest entry when full (it must never fail
// open), so whoever can insert into it can push others out. Only APPROVED keys
// may therefore occupy a slot — otherwise an outsider, who can mint unlimited
// self-signed valid registrations, could flush the cache and re-open the replay
// window on a real buddy.
func TestUnapprovedKeysCannotOccupyTheReplayCache(t *testing.T) {
	approved, srvPriv := testNode(t)
	authz := newTestAuthorizer(t, srvPriv, approved.pub)
	reg := newHSRegistry(time.Minute)

	// An approved buddy registers once; that attempt must stay protected.
	victim := unmarshalRegister(t, mustBuild(t, approved), srvPriv)
	if _, ok := pairRegister(reg, authz, "", v4(1000), victim); !ok {
		t.Fatal("the approved registration should have been accepted")
	}

	// A stranger now hammers the server with valid, self-signed registrations —
	// far more than the cache can hold.
	//
	// The enrollment limiter has to come OFF for the flood to be a flood: at 2/s
	// per source it admits about four of these before the loop is done, so with it
	// in place the cache never fills and this test asserted its property over an
	// almost-empty map. A real attacker is not bounded by the test's wall clock.
	stranger, _ := testNode(t)
	stranger.serverPub = approved.serverPub
	authz.enroll = nil
	for i := 0; i < maxReplayRegs+64; i++ {
		m := unmarshalRegister(t, mustBuild(t, stranger), srvPriv)
		if _, ok := pairRegister(reg, authz, "", v4(2000), m); ok {
			t.Fatal("an unapproved key must never be accepted")
		}
	}

	authz.mu.RLock()
	size := len(authz.recentRegs)
	authz.mu.RUnlock()
	if size != 1 {
		t.Fatalf("replay cache holds %d entries after a stranger flood, want only the approved buddy's 1 — "+
			"unapproved keys can evict real entries", size)
	}
	// The approved buddy's captured registration must still be caught as a replay.
	if _, ok := pairRegister(reg, authz, "", v4(3000), victim); ok {
		t.Fatal("a stranger flood flushed the replay cache and re-opened the replay window")
	}
}

// An unknown key never reaches the registry: no pairing slot, no roster entry.
func TestUnknownKeyIsNotStored(t *testing.T) {
	nd, srvPriv := testNode(t)
	authz := newTestAuthorizer(t, srvPriv)
	reg := newHSRegistry(time.Minute)

	m := unmarshalRegister(t, mustBuild(t, nd), srvPriv)
	if _, ok := pairRegister(reg, authz, "", v4(1000), m); ok {
		t.Fatal("an unknown key must not be accepted")
	}
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if len(reg.waiting) != 0 {
		t.Fatalf("an unknown key occupied %d token slot(s)", len(reg.waiting))
	}
}

// The pending log line must never carry the cleartext enrollment code: the code
// is a BEARER SECRET and the log may be shipped off-box. The public key is a
// non-secret identifier and is printed in full on purpose — it is the
// copy-pasteable `approve` command the operator needs.
func TestEnrollmentLogsNoSecrets(t *testing.T) {
	nd, srvPriv := testNode(t)
	authz := newTestAuthorizer(t, srvPriv)
	const code = "SUPER-SECRET-CODE"

	sealed, err := bcrypto.SealCode(code, srvPriv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	out := captureLog(t, func() { authz.recordPending(sealed, nd.pub) })
	if contains(out, code) {
		t.Fatalf("the cleartext enrollment code was logged: %q", out)
	}
	if !contains(out, shortHash(code)) {
		t.Fatalf("expected the non-reversible code tag in the log line, got %q", out)
	}
	if !contains(out, keyTag(nd.pub)) {
		t.Fatalf("expected a key tag in the log line, got %q", out)
	}
	// And nothing about the enrolment reaches the disk at all: the server keeps no
	// runtime state, so there is no file that could hold the code in any form.
	if _, err := os.Stat(authz.path + ".pending"); !os.IsNotExist(err) {
		t.Fatalf("the server created a pending file (%v) — enrolments must stay in memory", err)
	}
}

// captureLog collects everything fn writes to the standard logger.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)
	fn()
	return buf.String()
}

func contains(haystack, needle string) bool {
	return needle != "" && strings.Contains(haystack, needle)
}

// The approval transition must not open a replay window. An unapproved key's
// registration never enters the replay cache (that is what keeps outsiders from
// flushing it), so a registration captured BEFORE approval would otherwise be
// replayable for the rest of its freshness window once the operator approves.
func TestPreApprovalRegistrationIsNotReplayableAfterApproval(t *testing.T) {
	nd, srvPriv := testNode(t)
	path := filepath.Join(t.TempDir(), "authorized")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	authz, err := newAuthorizer(path, srvPriv)
	if err != nil {
		t.Fatal(err)
	}
	reg := newHSRegistry(time.Minute)

	// Captured while the key is still unapproved.
	captured := unmarshalRegister(t, mustBuild(t, nd), srvPriv)
	if _, ok := pairRegister(reg, authz, "", v4(1000), captured); ok {
		t.Fatal("an unapproved key must not pair")
	}

	// Time passes before the operator acts. REGISTER timestamps are unix seconds,
	// so a capture in the SAME second as the approval is inherently
	// indistinguishable from a fresh attempt; anything beyond that is caught.
	time.Sleep(1100 * time.Millisecond)

	// The operator approves; the hot reload picks the key up.
	if err := ApproveKey(path, nd.pub, "late"); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	authz.pollOnce()
	if !authz.allowed(nd.pub) {
		t.Fatal("the key was not approved")
	}

	// The captured registration is still inside its freshness window. Replaying it
	// from the ATTACKER's source must not be accepted.
	if _, ok := pairRegister(reg, authz, "", v4(6666), captured); ok {
		t.Fatal("a registration captured before approval was accepted after approval — " +
			"the approval transition opens a replay window")
	}

	// A genuinely fresh registration from the now-approved client must work.
	fresh := unmarshalRegister(t, mustBuild(t, nd), srvPriv)
	if _, ok := pairRegister(reg, authz, "", v4(1000), fresh); !ok {
		t.Fatal("the approved client cannot register with a fresh attempt")
	}
}

// The approval-transition defence must not rest on the CLIENT'S timestamp. An
// attacker can pre-send a registration dated at the far edge of the accepted skew
// (now + regSkew - 1s); it arrives while the key is still unapproved, but its
// self-asserted ts lies AFTER the approval that follows seconds later. A check
// that only compares ts against the approval instant waves it through, so the
// window is not one second but the whole positive clock skew.
func TestFutureDatedPreApprovalRegistrationIsNotReplayable(t *testing.T) {
	nd, srvPriv := testNode(t)
	path := filepath.Join(t.TempDir(), "authorized")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	authz, err := newAuthorizer(path, srvPriv)
	if err != nil {
		t.Fatal(err)
	}
	reg := newHSRegistry(time.Minute)

	// 1. Captured while unapproved, dated at the far edge of the accepted window.
	captured := signReg(t, nd.priv, protocol.Message{
		Type:      protocol.TypeRegister,
		Role:      protocol.RoleBuddy,
		Token:     "tok",
		ID:        nd.id,
		PubKey:    nd.pub,
		VirtualIP: nd.vip,
		Ts:        time.Now().Add(regSkew - time.Second).Unix(),
	})
	if !verifyRegistration(captured, regSkew) {
		t.Fatal("test setup: the future-dated registration should still be within the skew window")
	}
	if _, ok := pairRegister(reg, authz, "", v4(1000), captured); ok {
		t.Fatal("an unapproved key must not pair")
	}

	// 2. The operator approves.
	if err := ApproveKey(path, nd.pub, "late"); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	authz.pollOnce()
	if !authz.allowed(nd.pub) {
		t.Fatal("the key was not approved")
	}

	// 3./4. The very same registration, same nonce, replayed from the attacker's
	// source. Its ts is AFTER the approval, so only a record of the nonce itself
	// can catch it.
	if _, ok := pairRegister(reg, authz, "", v4(6666), captured); ok {
		t.Fatal("a future-dated registration captured before approval was accepted after approval — " +
			"the approval check trusts the client's timestamp")
	}
}

// The two replay caches must be strictly separated: a flood of unapproved keys
// fills only the pre-auth cache and may never displace an approved buddy's entry.
// That separation is what lets us remember outsiders' nonces at all — the reason
// they were originally excluded was precisely that they could evict.
func TestPreAuthFloodCannotEvictApprovedEntries(t *testing.T) {
	approved, srvPriv := testNode(t)
	authz := newTestAuthorizer(t, srvPriv, approved.pub)
	reg := newHSRegistry(time.Minute)

	// One approved registration, which must stay protected for its whole window.
	victim := unmarshalRegister(t, mustBuild(t, approved), srvPriv)
	if _, ok := pairRegister(reg, authz, "", v4(1000), victim); !ok {
		t.Fatal("the approved registration should have been accepted")
	}

	// A stranger floods far past the pre-auth cache's capacity. As above, the
	// limiter comes off so the flood actually reaches the cache — otherwise the
	// eviction path this test exists for is never executed at all.
	stranger, _ := testNode(t)
	stranger.serverPub = approved.serverPub
	authz.enroll = nil
	for i := 0; i < maxPreAuthRegs+256; i++ {
		m := unmarshalRegister(t, mustBuild(t, stranger), srvPriv)
		if _, ok := pairRegister(reg, authz, "", v4(2000), m); ok {
			t.Fatal("an unapproved key must never pair")
		}
	}

	authz.mu.RLock()
	approvedEntries, preAuthEntries := len(authz.recentRegs), len(authz.preAuthRegs)
	authz.mu.RUnlock()

	if approvedEntries != 1 {
		t.Fatalf("approved cache holds %d entries after a stranger flood, want 1 — the caches are not separated", approvedEntries)
	}
	if preAuthEntries > maxPreAuthRegs {
		t.Fatalf("pre-auth cache grew to %d, past its cap of %d", preAuthEntries, maxPreAuthRegs)
	}
	// The point of the flood: the cache must actually have FILLED, or the eviction
	// path below is never exercised and the assertion that follows is vacuous.
	if preAuthEntries < maxPreAuthRegs {
		t.Fatalf("pre-auth cache only reached %d of %d entries — the flood never filled it, "+
			"so this test proves nothing about eviction", preAuthEntries, maxPreAuthRegs)
	}
	// The decisive assertion: the approved buddy's registration is STILL caught.
	if _, ok := pairRegister(reg, authz, "", v4(3000), victim); ok {
		t.Fatal("a pre-auth flood evicted an approved buddy's replay entry")
	}
}

// A structurally broken request costs the CONNECTION, not just the request. No
// buddy ever sends one, so a peer that does is broken or probing — and a
// connection kept alive across refusals is a control-plane slot held for free.
func TestMalformedRequestDropsTheConnection(t *testing.T) {
	nd, _ := testNode(t)
	srvAddr, srvPub, _, _, _ := enrollServer(t, nd.pub)
	nd.serverPub = srvPub

	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cli, err := tunnel.DialControl(ctx, c, srvAddr, srvPub, nd.priv, controlIdleTimeout)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cli.Close()

	// Positive control on this very connection: a well-formed registration works,
	// so anything failing below fails for the reason under test.
	rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
	resp, err := cli.Roundtrip(rctx, mustBuild(t, nd))
	rcancel()
	if err != nil || len(resp) == 0 {
		t.Fatalf("positive control failed: a valid registration was not answered (%v)", err)
	}

	// Now something that cannot parse.
	bctx, bcancel := context.WithTimeout(ctx, 5*time.Second)
	cli.Roundtrip(bctx, []byte("this is not a registration"))
	bcancel()

	// The connection must be gone, not merely the request unanswered.
	nctx, ncancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer ncancel()
	if resp, err := cli.Roundtrip(nctx, mustBuild(t, nd)); err == nil && len(resp) > 0 {
		t.Fatal("the connection survived a malformed request; it must be closed")
	}
}
