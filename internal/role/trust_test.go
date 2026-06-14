package role

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The trust store must index by a hash of the token, never the token itself —
// it's a bearer secret and shouldn't sit in clear on disk.
func TestTrustStoreDoesNotStorePlaintextToken(t *testing.T) {
	buddyPub, _, _ := ed25519.GenerateKey(rand.Reader)
	store := filepath.Join(t.TempDir(), "known_peers")
	const token = "super-secret-token-value-xyz"

	tofu := &trustPolicy{storePath: store}
	if err := tofu.check(token, buddyPub); err != nil {
		t.Fatalf("first connect should learn: %v", err)
	}

	data, err := os.ReadFile(store)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	if strings.Contains(string(data), token) {
		t.Fatalf("trust store leaks the plaintext token:\n%s", data)
	}
	if !strings.Contains(string(data), tokenKey(token)) {
		t.Fatalf("trust store should index by the token hash; got:\n%s", data)
	}

	// Sanity: lookups still work via the hash, and re-learning is idempotent.
	if err := tofu.check(token, buddyPub); err != nil {
		t.Fatalf("same key should still match after hashing: %v", err)
	}
}

// A pinned --peer-key must reject any other identity, and TOFU must refuse a
// changed key for a known token (SSH-style).
func TestTrustPinAndChangeRejected(t *testing.T) {
	pinned, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)

	pin := &trustPolicy{pinned: pinned}
	if err := pin.check("tok", pinned); err != nil {
		t.Fatalf("pinned key should be accepted: %v", err)
	}
	if err := pin.check("tok", other); err == nil {
		t.Fatal("a non-pinned key must be rejected")
	}

	store := filepath.Join(t.TempDir(), "known_peers")
	tofu := &trustPolicy{storePath: store}
	if err := tofu.check("tok", pinned); err != nil {
		t.Fatalf("first connect should learn: %v", err)
	}
	if err := tofu.check("tok", other); err == nil {
		t.Fatal("a changed key for a known token must be refused")
	}
}

// --insecure accepts anything, and TOFU keys are tracked per token (a different
// token learns independently rather than clashing).
func TestTrustInsecureAndIndependentToken(t *testing.T) {
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	b, _, _ := ed25519.GenerateKey(rand.Reader)

	if err := (&trustPolicy{insecure: true}).check("tok", a); err != nil {
		t.Fatalf("insecure should accept anything: %v", err)
	}

	store := filepath.Join(t.TempDir(), "known_peers")
	tofu := &trustPolicy{storePath: store}
	if err := tofu.check("tok", a); err != nil {
		t.Fatalf("TOFU first connect should learn: %v", err)
	}
	if err := tofu.check("tok", b); err == nil {
		t.Fatal("TOFU must refuse a changed key for a known token")
	}
	// A different token is independent and learns separately.
	if err := tofu.check("tok2", b); err != nil {
		t.Fatalf("TOFU new token should learn: %v", err)
	}
}
