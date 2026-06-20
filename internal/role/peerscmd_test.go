package role

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
)

func TestPeersAddDedupAndParse(t *testing.T) {
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	aB64 := bcrypto.PubKeyB64(a)
	path := filepath.Join(t.TempDir(), "sub", "peers") // dir created by add

	if err := PeersAdd(path, aB64, "boot-a"); err != nil {
		t.Fatalf("add: %v", err)
	}
	// Adding the same key again must not duplicate it.
	if err := PeersAdd(path, aB64, "boot-a"); err != nil {
		t.Fatalf("re-add: %v", err)
	}
	specs, err := loadPeersFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("want 1 spec after dup add, got %d", len(specs))
	}
	if !specs[0].pin.Equal(a) || specs[0].token != "boot-a" {
		t.Fatalf("spec = %+v", specs[0])
	}

	if err := PeersAdd(path, "not-a-key", ""); err == nil {
		t.Fatal("add must reject a bad key")
	}
}

// PeersRemove must revoke BOTH places: the manifest line and the stored session
// secret. Removing only one would leave the supervisor reconnecting.
func TestPeersRemoveRevokesBoth(t *testing.T) {
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	b, _, _ := ed25519.GenerateKey(rand.Reader)
	aB64, bB64 := bcrypto.PubKeyB64(a), bcrypto.PubKeyB64(b)

	dir := t.TempDir()
	peers := filepath.Join(dir, "peers")
	known := filepath.Join(dir, "known_peers")

	for _, k := range []string{aB64, bB64} {
		if err := PeersAdd(peers, k, "tok"); err != nil {
			t.Fatalf("add %s: %v", k, err)
		}
	}
	// a is paired (has a session); b is not.
	if err := saveSession(known, "tok", aB64, "secret-a"); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	if err := PeersRemove(peers, known, aB64); err != nil {
		t.Fatalf("remove a: %v", err)
	}

	// a gone from the manifest, b kept.
	specs, _ := loadPeersFile(peers)
	if len(specs) != 1 || !specs[0].pin.Equal(b) {
		t.Fatalf("after remove, manifest = %+v (want only b)", specs)
	}
	// a's session revoked (no reconnect path left).
	if _, ok, _ := loadSessionFor(known, a); ok {
		t.Fatal("PeersRemove left a's session secret behind — not revoked")
	}

	// Removing a key we don't know is a no-op, not an error.
	c, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := PeersRemove(peers, known, bcrypto.PubKeyB64(c)); err != nil {
		t.Fatalf("remove unknown: %v", err)
	}
}

func TestPeersListSmoke(t *testing.T) {
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	peers := filepath.Join(dir, "peers")
	known := filepath.Join(dir, "known_peers")
	if err := PeersAdd(peers, bcrypto.PubKeyB64(a), "boot-a"); err != nil {
		t.Fatal(err)
	}
	// Should not error with a manifest present and no sessions.
	if err := PeersList(peers, known, ""); err != nil {
		t.Fatalf("list: %v", err)
	}
	// Should not error when nothing exists yet.
	if err := PeersList(filepath.Join(dir, "absent"), filepath.Join(dir, "absent2"), ""); err != nil {
		t.Fatalf("list empty: %v", err)
	}
}

// PeersRemove must accept the short 6-char KEY shown by `peers list` (a unique
// prefix), reject an ambiguous one, and keep an unknown full key a no-op.
func TestPeersRemoveByShortKey(t *testing.T) {
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	aB64 := bcrypto.PubKeyB64(a)
	dir := t.TempDir()
	peers := filepath.Join(dir, "peers")
	known := filepath.Join(dir, "known_peers")
	if err := PeersAdd(peers, aB64, "tok"); err != nil {
		t.Fatalf("add: %v", err)
	}

	// An unknown short prefix is an error (typo must not silently no-op).
	if err := PeersRemove(peers, known, "zzz999"); err == nil {
		t.Fatal("remove of unknown prefix should error")
	}

	// The 6-char form resolves back to the full key and removes it.
	if err := PeersRemove(peers, known, aB64[:6]); err != nil {
		t.Fatalf("remove by short key: %v", err)
	}
	if specs, _ := loadPeersFile(peers); len(specs) != 0 {
		t.Fatalf("manifest not emptied by short-key remove: %+v", specs)
	}
}

// An ambiguous prefix (two buddies sharing leading base64 chars) must error
// rather than remove the wrong buddy. We synthesise the collision by matching on
// the empty prefix, which matches every known buddy.
func TestPeersRemoveAmbiguousPrefix(t *testing.T) {
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	b, _, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	peers := filepath.Join(dir, "peers")
	known := filepath.Join(dir, "known_peers")
	for _, k := range []string{bcrypto.PubKeyB64(a), bcrypto.PubKeyB64(b)} {
		if err := PeersAdd(peers, k, "tok"); err != nil {
			t.Fatalf("add: %v", err)
		}
	}
	if err := PeersRemove(peers, known, ""); err == nil {
		t.Fatal("empty/ambiguous prefix should error, not remove a buddy")
	}
	if specs, _ := loadPeersFile(peers); len(specs) != 2 {
		t.Fatalf("ambiguous remove must change nothing, got %d specs", len(specs))
	}
}
