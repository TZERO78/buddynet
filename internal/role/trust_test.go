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
	needSAS, err := tofu.decide(token, buddyPub)
	if err != nil || !needSAS {
		t.Fatalf("first contact should need SAS: needSAS=%v err=%v", needSAS, err)
	}
	if err := tofu.confirm(token, buddyPub); err != nil {
		t.Fatalf("confirm: %v", err)
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

	// After confirm, the same key is known and needs no further SAS.
	needSAS, err = tofu.decide(token, buddyPub)
	if err != nil || needSAS {
		t.Fatalf("known key should match silently: needSAS=%v err=%v", needSAS, err)
	}
}

// A pinned --peer-key must accept only itself (no SAS), and TOFU must refuse a
// changed key for a known token (SSH-style).
func TestTrustPinAndChangeRejected(t *testing.T) {
	pinned, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)

	pin := &trustPolicy{pinned: pinned}
	if needSAS, err := pin.decide("tok", pinned); err != nil || needSAS {
		t.Fatalf("pinned key should be accepted without SAS: needSAS=%v err=%v", needSAS, err)
	}
	if _, err := pin.decide("tok", other); err == nil {
		t.Fatal("a non-pinned key must be rejected")
	}

	store := filepath.Join(t.TempDir(), "known_peers")
	tofu := &trustPolicy{storePath: store}
	if _, err := tofu.decide("tok", pinned); err != nil {
		t.Fatalf("first contact should not error: %v", err)
	}
	if err := tofu.confirm("tok", pinned); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if _, err := tofu.decide("tok", other); err == nil {
		t.Fatal("a changed key for a known token must be refused")
	}
}

// --lab accepts anything without SAS, and TOFU keys are tracked per token
// (a different token learns independently rather than clashing).
func TestTrustInsecureAndIndependentToken(t *testing.T) {
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	b, _, _ := ed25519.GenerateKey(rand.Reader)

	if needSAS, err := (&trustPolicy{insecure: true}).decide("tok", a); err != nil || needSAS {
		t.Fatalf("insecure should accept anything without SAS: needSAS=%v err=%v", needSAS, err)
	}

	store := filepath.Join(t.TempDir(), "known_peers")
	tofu := &trustPolicy{storePath: store}
	if _, err := tofu.decide("tok", a); err != nil {
		t.Fatalf("first contact should not error: %v", err)
	}
	if err := tofu.confirm("tok", a); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if _, err := tofu.decide("tok", b); err == nil {
		t.Fatal("TOFU must refuse a changed key for a known token")
	}
	// A different token is independent and needs its own first-contact SAS.
	if needSAS, err := tofu.decide("tok2", b); err != nil || !needSAS {
		t.Fatalf("new token should need SAS: needSAS=%v err=%v", needSAS, err)
	}
}

// confirm must NOT persist for a pinned or insecure policy (nothing to learn).
func TestConfirmNoopForPinnedAndInsecure(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	store := filepath.Join(t.TempDir(), "known_peers")

	if err := (&trustPolicy{pinned: pub, storePath: store}).confirm("tok", pub); err != nil {
		t.Fatalf("confirm (pinned): %v", err)
	}
	if err := (&trustPolicy{insecure: true, storePath: store}).confirm("tok", pub); err != nil {
		t.Fatalf("confirm (insecure): %v", err)
	}
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatal("pinned/insecure confirm should not create a trust store")
	}
}
