package role

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
)

// newWatchedAuthorizer returns an authorizer over path (which may not exist) plus
// the server key needed to build registrations against it.
func newWatchedAuthorizer(t *testing.T, path string) *authorizer {
	t.Helper()
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	a, err := newAuthorizer(path, srvPriv)
	if err != nil {
		t.Fatalf("newAuthorizer: %v", err)
	}
	return a
}

// Starting with no allowlist file must be FAIL-CLOSED: approval mode is on
// (--authorized was passed) and nobody is authorized. It must never mean
// "open mode".
func TestMissingAllowlistIsFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist")
	a := newWatchedAuthorizer(t, path)

	if a.count() != 0 {
		t.Fatalf("a missing allowlist loaded %d keys", a.count())
	}
	if a.allowed(pubKeyB64(t)) {
		t.Fatal("a missing allowlist authorized a key — this must be fail-closed")
	}
	// And the server still runs in approval mode: the authorizer exists at all,
	// which is what pairRegister keys the decision off.
	nd, srvPriv := testNode(t)
	a.selfPriv = srvPriv
	m := unmarshalRegister(t, mustBuild(t, nd, ""), srvPriv)
	if _, ok := pairRegister(newHSRegistry(time.Minute), a, "", v4(1000), m); ok {
		t.Fatal("a registration was accepted with an empty allowlist — the server fell open")
	}
}

// Deleting the allowlist while the server runs must EMPTY the loaded allowlist,
// not leave the last-loaded keys authorized forever. Recreating it loads the
// entries again.
func TestDeletingAllowlistClearsItAndRecreatingRestoresIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized")
	keyA := pubKeyB64(t)
	if err := os.WriteFile(path, []byte(keyA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := newWatchedAuthorizer(t, path)
	if !a.allowed(keyA) {
		t.Fatal("the approved key is not authorized to begin with")
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	out := captureLog(t, a.pollOnce)
	if a.count() != 0 || a.allowed(keyA) {
		t.Fatal("deleting the allowlist left keys authorized — `rm` silently revoked nothing")
	}
	if !strings.Contains(out, "WARNING") {
		t.Fatalf("the disappearance was not reported clearly: %q", out)
	}

	// The warning must not repeat on every poll (this runs every couple of seconds).
	quiet := captureLog(t, func() {
		for i := 0; i < 5; i++ {
			a.pollOnce()
		}
	})
	if strings.Contains(quiet, "WARNING") {
		t.Fatalf("the missing-allowlist warning repeats on every poll: %q", quiet)
	}

	// Restoring the file re-authorizes its entries — and says so.
	if err := os.WriteFile(path, []byte(keyA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	back := captureLog(t, a.pollOnce)
	if !a.allowed(keyA) {
		t.Fatal("recreating the allowlist did not reload its entries")
	}
	if !strings.Contains(back, "restored") {
		t.Fatalf("the restoration was not logged: %q", back)
	}

	// A second disappearance must be reported again (the latch resets).
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if again := captureLog(t, a.pollOnce); !strings.Contains(again, "WARNING") {
		t.Fatalf("a later disappearance was not reported: %q", again)
	}
}

// Revoking ONE key must still take effect by hot reload, without disturbing the
// others.
func TestRevokingOneKeyHotReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized")
	keyA, keyB := pubKeyB64(t), pubKeyB64(t)
	if err := os.WriteFile(path, []byte(keyA+" alice\n"+keyB+" bob\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := newWatchedAuthorizer(t, path)
	if !a.allowed(keyA) || !a.allowed(keyB) {
		t.Fatal("both keys should start authorized")
	}

	if err := RevokeKey(path, keyB); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	// RevokeKey rewrites via rename; make sure the mtime differs from the one we
	// recorded, so the poll is guaranteed to see a change on a coarse clock.
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	a.pollOnce()

	if a.allowed(keyB) {
		t.Fatal("a revoked key is still authorized after the hot reload")
	}
	if !a.allowed(keyA) {
		t.Fatal("revoking one key dropped the others")
	}
}

func pubKeyB64(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return bcrypto.PubKeyB64(pub)
}
