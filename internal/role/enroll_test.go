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
func enrollServer(t *testing.T, allowed ...string) (*net.UDPAddr, ed25519.PublicKey, string, *authorizer) {
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
	go serveControlQUIC(ctx, srvConn, newHSRegistry(time.Minute), srvPriv, authz, "", rl, nil)

	return srvConn.LocalAddr().(*net.UDPAddr), srvPriv.Public().(ed25519.PublicKey), path, authz
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
	srvAddr, srvPub, allowPath, authz := enrollServer(t)
	stranger.serverPub = srvPub

	// 1. Unknown key, no code: refused, and nothing is recorded.
	if enrollClient(t, srvAddr, srvPub, stranger, "") {
		t.Fatal("an unknown client without an enrollment code must be refused")
	}
	if len(authz.pend) != 0 {
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

	// 3. The operator approves by code; the hot reload picks it up.
	if err := AllowClient(allowPath, code); err != nil {
		t.Fatalf("AllowClient: %v", err)
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
	srvAddr, srvPub, _, _ := enrollServer(t, nd.pub)
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

// A stranger cannot bind an enrollment code to somebody else's public key: the
// code is inside the registration signature AND the registration is bound to the
// TLS-authenticated key, so the pending entry can only ever name the enrolling key.
func TestEnrollmentCannotTargetAnotherKey(t *testing.T) {
	victim, _ := testNode(t)
	attacker, _ := testNode(t)
	srvAddr, srvPub, _, authz := enrollServer(t)
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
		m := unmarshalRegister(t, mustBuild(t, nd, ""), srvPriv)
		if _, ok := pairRegister(reg, authz, "", v4(1000), m); ok {
			t.Fatal("an unknown key must never pair")
		}
	}
	if hsStats.enrollLimited.Load() == 0 {
		t.Fatal("a stranger flood was not rate-limited on the enrollment path")
	}
}

// An unknown key never reaches the registry: no pairing slot, no roster entry.
func TestUnknownKeyIsNotStored(t *testing.T) {
	nd, srvPriv := testNode(t)
	authz := newTestAuthorizer(t, srvPriv)
	reg := newHSRegistry(time.Minute)

	m := unmarshalRegister(t, mustBuild(t, nd, ""), srvPriv)
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
	// The pending FILE must not hold the cleartext code either.
	data, err := os.ReadFile(authz.pendDB)
	if err != nil {
		t.Fatalf("read pending db: %v", err)
	}
	if contains(string(data), code) {
		t.Fatalf("the cleartext enrollment code was persisted: %q", data)
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
