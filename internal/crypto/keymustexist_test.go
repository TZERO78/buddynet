package crypto

// Creating an identity must be an EXPLICIT act. A server that invents one after
// its key went missing — an unmounted volume, a typo in --key, a fresh container
// that was expected to inherit a key — is a DIFFERENT server to every buddy that
// pinned the old one, and they all refuse it as a possible MITM. From inside the
// process a genuine first run and a lost key are indistinguishable, so the only
// safe answer is to refuse and let the operator say which it is.
//
// These tests pin the split: LoadKey never writes, CreateKey never overwrites.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadKeyRefusesMissingFileAndWritesNothing is the regression gate for the
// finding: the failure mode was a server coming up happily on an empty but
// writable path.
func TestLoadKeyRefusesMissingFileAndWritesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id.key")

	_, _, err := LoadKey(path)
	if !errors.Is(err, ErrKeyMissing) {
		t.Fatalf("LoadKey on a missing file returned %v, want ErrKeyMissing", err)
	}
	// The error must name the path: the operator's next move is to check whether
	// THAT path is the mount they expected.
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("the error does not name the key path, so it is not actionable: %v", err)
	}
	// And nothing may have been created — the whole point.
	if _, serr := os.Stat(path); !os.IsNotExist(serr) {
		t.Fatalf("LoadKey created a key file at %s — a server must never mint an identity", path)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("LoadKey left %d file(s) behind in a directory that must stay empty", len(entries))
	}
}

// TestLoadKeyLoadsAnExistingKeyUnchanged is the positive control: the refusal
// above must be about the MISSING file, not about LoadKey being broken.
func TestLoadKeyLoadsAnExistingKeyUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id.key")
	created, err := CreateKey(path)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	loaded, wasCreated, err := LoadKey(path)
	if err != nil {
		t.Fatalf("LoadKey on an existing key: %v", err)
	}
	if wasCreated {
		t.Fatal("LoadKey reported created=true for a key it loaded from disk")
	}
	if !loaded.Equal(created) {
		t.Fatal("LoadKey returned a different key than CreateKey wrote")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("LoadKey rewrote the key file; loading must never touch it")
	}
}

// TestCreateKeyRefusesToReplaceAnIdentity: `init` run twice must fail, not re-key
// a node whose buddies have pinned it. (O_EXCL gives this; the test makes sure a
// future refactor cannot lose it.)
func TestCreateKeyRefusesToReplaceAnIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id.key")
	first, err := CreateKey(path)
	if err != nil {
		t.Fatalf("first CreateKey: %v", err)
	}
	before, _ := os.ReadFile(path)

	second, err := CreateKey(path)
	if err == nil {
		t.Fatal("CreateKey replaced an existing identity — buddies pin this key")
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("CreateKey on an existing file returned %v, want an ErrExist so callers can report it precisely", err)
	}
	if second != nil {
		t.Fatal("CreateKey returned a key alongside its error")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("the failed CreateKey modified the existing key file")
	}
	// And the original still loads.
	again, _, err := LoadKey(path)
	if err != nil || !again.Equal(first) {
		t.Fatalf("the original identity did not survive a refused CreateKey: %v", err)
	}
}

// TestLoadOrCreateKeyStillCreatesForTheBuddyPath: the buddy role keeps its
// one-command first run. If this ever fails, the split was applied too widely.
func TestLoadOrCreateKeyStillCreatesForTheBuddyPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id.key")
	priv, created, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}
	if !created {
		t.Fatal("LoadOrCreateKey reported created=false on a fresh path")
	}
	again, created2, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("second LoadOrCreateKey: %v", err)
	}
	if created2 {
		t.Fatal("LoadOrCreateKey regenerated an existing key")
	}
	if !again.Equal(priv) {
		t.Fatal("LoadOrCreateKey returned a different key on the second call")
	}
}

// TestEmptyPathIsEphemeralForBoth: "no --key" is the documented ephemeral mode
// and must not become an error — it touches no disk either way.
func TestEmptyPathIsEphemeralForBoth(t *testing.T) {
	priv, created, err := LoadKey("")
	if err != nil || priv == nil || !created {
		t.Fatalf("LoadKey(\"\") = (%v, %v, %v), want an ephemeral key", priv != nil, created, err)
	}
	if c, err := CreateKey(""); err != nil || c == nil {
		t.Fatalf("CreateKey(\"\") = (%v, %v), want an ephemeral key", c != nil, err)
	}
}
