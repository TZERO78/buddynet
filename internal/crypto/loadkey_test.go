package crypto

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A key file written with a trailing newline (e.g. `echo "$SEED" > id.key` or an
// editor) must still load, not be rejected as bad base64 — otherwise the node
// would silently regenerate a fresh identity and change its address.
func TestLoadKeyToleratesTrailingNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id.key")
	first, _, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	reloaded, created, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("reload with trailing newline failed: %v", err)
	}
	if created {
		t.Fatal("a key with a trailing newline must load, not regenerate")
	}
	if !first.Equal(reloaded) {
		t.Fatal("reloaded key differs from the persisted one")
	}
}

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

// LoadOrCreateKey must emit a WARNING when the key file's permissions are wider
// than 0600, so operators notice accidental chmod mistakes before they matter.
func TestLoadKeyWarnsInsecurePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id.key")
	if _, _, err := LoadOrCreateKey(path); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	if _, _, err := LoadOrCreateKey(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !strings.Contains(buf.String(), "WARNING") {
		t.Fatal("expected WARNING log about insecure key file permissions")
	}
}
