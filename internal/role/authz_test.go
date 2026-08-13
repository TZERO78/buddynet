package role

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/pkg/protocol"
)

func TestAuthorizerApproveListRevoke(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key := base64.StdEncoding.EncodeToString(pub)

	// Missing file = empty allowlist, not an error.
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	a, err := newAuthorizer(path, srvPriv)
	if err != nil {
		t.Fatalf("newAuthorizer: %v", err)
	}
	if a.allowed(key) {
		t.Fatal("key allowed before approval")
	}

	if err := ApproveKey(path, key, "laptop"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := a.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !a.allowed(key) {
		t.Fatal("key not allowed after approval")
	}

	if err := RevokeKey(path, key); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := a.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if a.allowed(key) {
		t.Fatal("key still allowed after revoke")
	}
}

func TestEnrollByCodeFlow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized")
	srvPub, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientPub, _, _ := ed25519.GenerateKey(rand.Reader)
	clientKey := base64.StdEncoding.EncodeToString(clientPub)

	a, err := newAuthorizer(path, srvPriv)
	if err != nil {
		t.Fatalf("newAuthorizer: %v", err)
	}

	// Client seals its enrollment code to the server identity; server records it.
	enc, err := bcrypto.SealCode("ab56fe2", srvPub)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	a.recordPending(enc, clientKey)

	// The pending set is keyed by a HASH of the code, never the plaintext — the
	// code is a bearer secret and must not survive anywhere in recoverable form.
	a.mu.RLock()
	_, hashed := a.pend[shortHash("ab56fe2")]
	_, plain := a.pend["ab56fe2"]
	a.mu.RUnlock()
	if !hashed {
		t.Fatal("pending set does not contain the code hash")
	}
	if plain {
		t.Fatal("pending set is keyed by the plaintext enrollment code")
	}

	// v5.0.0: the pending set lives in MEMORY ONLY. The server must not create a
	// runtime database — that file, written by two processes, was the single cause
	// of every persistence bug this store ever had.
	if _, err := os.Stat(path + ".pending"); !os.IsNotExist(err) {
		t.Fatalf("the server wrote a pending file (%v) — it must keep no runtime state on disk", err)
	}

	// First-come-wins: a different key with the same code is ignored.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	otherKey := base64.StdEncoding.EncodeToString(otherPub)
	a.recordPending(enc, otherKey)
	a.mu.RLock()
	got := a.pend[shortHash("ab56fe2")].Key
	a.mu.RUnlock()
	if got != clientKey {
		t.Fatalf("a second key hijacked the code: %s", keyTag(got))
	}

	if a.allowed(clientKey) {
		t.Fatal("client allowed before approval")
	}
	// The operator approves BY KEY, from the log line the server printed.
	if err := ApproveKey(path, clientKey, "code:"+shortHash("ab56fe2")); err != nil {
		t.Fatalf("ApproveKey: %v", err)
	}
	if err := a.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !a.allowed(clientKey) {
		t.Fatal("client not allowed after approval")
	}
	// The approval label must carry the code HASH, never the cleartext code.
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "ab56fe2") {
		t.Fatalf("cleartext enrollment code leaked into the allowlist: %q", data)
	}
	if !strings.Contains(string(data), "code:"+shortHash("ab56fe2")) {
		t.Fatalf("expected a hashed code label, got: %q", data)
	}
}

func TestLogPendingMapIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized")
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	a, err := newAuthorizer(path, srvPriv)
	if err != nil {
		t.Fatalf("newAuthorizer: %v", err)
	}
	// An outsider can sign valid registrations with unlimited fresh keys. The
	// dedup map must not grow without bound.
	for i := 0; i < maxLoggedKeys*3; i++ {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		a.logPending(base64.StdEncoding.EncodeToString(pub), "th")
	}
	if got := len(a.logged); got > maxLoggedKeys {
		t.Fatalf("logged map = %d entries, exceeds cap %d", got, maxLoggedKeys)
	}
}

func TestRecordPendingMapIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized")
	srvPub, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	a, err := newAuthorizer(path, srvPriv)
	if err != nil {
		t.Fatalf("newAuthorizer: %v", err)
	}
	// An outsider can seal unlimited valid codes to our public key. The pending
	// set (and the file it rewrites) must stay bounded.
	for i := 0; i < maxPending+64; i++ {
		clientPub, _, _ := ed25519.GenerateKey(rand.Reader)
		enc, err := bcrypto.SealCode(fmt.Sprintf("code-%d", i), srvPub)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		a.recordPending(enc, base64.StdEncoding.EncodeToString(clientPub))
	}
	if got := len(a.pend); got > maxPending {
		t.Fatalf("pending map = %d entries, exceeds cap %d", got, maxPending)
	}
}

func TestReplayedDetectsRepeatAndStaysBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized")
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	a, err := newAuthorizer(path, srvPriv)
	if err != nil {
		t.Fatalf("newAuthorizer: %v", err)
	}
	// First sighting is fresh; the same key reusing the same nonce is a replay.
	if a.replayed("key-A", "nonce-1") {
		t.Fatal("first sighting wrongly flagged as replay")
	}
	if !a.replayed("key-A", "nonce-1") {
		t.Fatal("repeat of the same (key,nonce) not detected as replay")
	}
	// The same key with a FRESH nonce is ordinary polling, not a replay — this is
	// what lets a buddy re-register once a second while waiting for its partner.
	if a.replayed("key-A", "nonce-2") {
		t.Fatal("same key with a new nonce must not be flagged as replay")
	}
	// The same nonce under a different key is a different registration entirely.
	if a.replayed("key-B", "nonce-1") {
		t.Fatal("different key with the same nonce must not be flagged as replay")
	}
	// A missing field (open/legacy mode) is never treated as a replay.
	if a.replayed("", "nonce-1") || a.replayed("key-A", "") {
		t.Fatal("an incomplete (key,nonce) wrongly flagged as replay")
	}
	// A flood of distinct nonces must not grow the cache without bound.
	for i := 0; i < maxReplayRegs*3; i++ {
		a.replayed("key-A", fmt.Sprintf("flood-%d", i))
	}
	if got := len(a.recentRegs); got > maxReplayRegs {
		t.Fatalf("replay cache = %d entries, exceeds cap %d", got, maxReplayRegs)
	}
}

func TestApproveRejectsBadKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized")
	if err := ApproveKey(path, "not-a-valid-key", ""); err == nil {
		t.Fatal("approve should reject a malformed key")
	}
}

func TestVerifyRegistration(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	signed := func(token, id string, ts int64, signer ed25519.PrivateKey) protocol.Message {
		return signReg(t, signer, protocol.Message{Type: protocol.TypeRegister, Token: token, ID: id, PubKey: pubB64, Ts: ts})
	}

	if !verifyRegistration(signed("tok", "A", time.Now().Unix(), priv), time.Minute) {
		t.Fatal("valid registration rejected")
	}
	// Tampered token invalidates the signature.
	bad := signed("tok", "A", time.Now().Unix(), priv)
	bad.Token = "other"
	if verifyRegistration(bad, time.Minute) {
		t.Fatal("tampered token accepted")
	}
	// A missing or malformed nonce is refused before the signature is even checked.
	for name, nonce := range map[string]string{"missing": "", "too short": "AAA", "bad alphabet": "!!!!!!!!!!!!!!!!!!!!!!"} {
		m := signed("tok", "A", time.Now().Unix(), priv)
		m.Nonce = nonce
		if verifyRegistration(m, time.Minute) {
			t.Fatalf("registration with a %s nonce accepted", name)
		}
	}
	// Stale timestamp rejected.
	if verifyRegistration(signed("tok", "A", time.Now().Add(-5*time.Minute).Unix(), priv), time.Minute) {
		t.Fatal("stale registration accepted")
	}
	// Signature by a different key (claiming pubB64 without owning it) rejected.
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	if verifyRegistration(signed("tok", "A", time.Now().Unix(), attacker), time.Minute) {
		t.Fatal("forged signature accepted")
	}
}
