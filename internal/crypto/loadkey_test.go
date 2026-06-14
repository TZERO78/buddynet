package crypto

import (
	"path/filepath"
	"testing"
)

func TestLoadOrCreateKeyPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id.key")

	first, created, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !created {
		t.Fatal("first load should report created=true")
	}
	second, created, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if created {
		t.Fatal("second load should report created=false (loaded existing)")
	}
	if !first.Equal(second) {
		t.Fatal("reloaded key differs from the persisted one")
	}

	// Empty path yields a fresh ephemeral key each call.
	a, _, _ := LoadOrCreateKey("")
	b, _, _ := LoadOrCreateKey("")
	if a.Equal(b) {
		t.Fatal("ephemeral keys should not be identical")
	}
}
