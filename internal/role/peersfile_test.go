package role

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestLoadPeersFile(t *testing.T) {
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	b, _, _ := ed25519.GenerateKey(rand.Reader)
	aB64, bB64 := bcrypto.PubKeyB64(a), bcrypto.PubKeyB64(b)

	path := filepath.Join(t.TempDir(), "peers")
	writeFile(t, path, "# a manifest\n\n"+
		aB64+" boot-a\n"+
		"   "+bB64+"   \n") // b without a token (reconnect-only)

	specs, err := loadPeersFile(path)
	if err != nil {
		t.Fatalf("loadPeersFile: %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("want 2 specs, got %d", len(specs))
	}
	if !specs[0].pin.Equal(a) || specs[0].token != "boot-a" {
		t.Fatalf("spec[0] = %+v", specs[0])
	}
	if !specs[1].pin.Equal(b) || specs[1].token != "" {
		t.Fatalf("spec[1] should be token-less: %+v", specs[1])
	}
}

func TestLoadPeersFileRejectsBadInput(t *testing.T) {
	good := bcrypto.PubKeyB64(func() ed25519.PublicKey { p, _, _ := ed25519.GenerateKey(rand.Reader); return p }())
	cases := map[string]string{
		"bad key":         "not-a-key boot\n",
		"too many fields": good + " tok extra\n",
		"duplicate key":   good + " t1\n" + good + " t2\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "peers")
			writeFile(t, path, content)
			if _, err := loadPeersFile(path); err == nil {
				t.Fatalf("%s: expected an error", name)
			}
		})
	}
}

func TestLoadPeersFileYAML(t *testing.T) {
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	b, _, _ := ed25519.GenerateKey(rand.Reader)
	c, _, _ := ed25519.GenerateKey(rand.Reader)
	aB64, bB64, cB64 := bcrypto.PubKeyB64(a), bcrypto.PubKeyB64(b), bcrypto.PubKeyB64(c)

	path := filepath.Join(t.TempDir(), "peers.yaml")
	writeFile(t, path, `# a manifest
buddies:
  - name: alice
    key: `+aB64+`
    token: boot-a
    expose: [873, "udp/51820"]
  - key: `+bB64+`
    expose: all
  - key: `+cB64+`
`)
	specs, err := loadPeersFile(path)
	if err != nil {
		t.Fatalf("loadPeersFile: %v", err)
	}
	if len(specs) != 3 {
		t.Fatalf("want 3 specs, got %d", len(specs))
	}
	if !specs[0].pin.Equal(a) || specs[0].token != "boot-a" || specs[0].name != "alice" {
		t.Fatalf("spec[0] = %+v", specs[0])
	}
	if specs[0].expose == nil || specs[0].expose.String() != "tcp/873,udp/51820" {
		t.Fatalf("spec[0].expose = %v", specs[0].expose)
	}
	if specs[1].expose == nil || !specs[1].expose.All {
		t.Fatalf("spec[1] should be expose:all, got %+v", specs[1].expose)
	}
	if specs[2].expose != nil {
		t.Fatalf("spec[2] should inherit (nil expose), got %v", specs[2].expose)
	}
}

func TestLoadPeersFileYAMLRejectsBadInput(t *testing.T) {
	good := bcrypto.PubKeyB64(func() ed25519.PublicKey { p, _, _ := ed25519.GenerateKey(rand.Reader); return p }())
	cases := map[string]string{
		"unknown field":  "buddies:\n  - key: " + good + "\n    tokken: oops\n",
		"missing key":    "buddies:\n  - name: alice\n",
		"bad key":        "buddies:\n  - key: not-a-key\n",
		"duplicate key":  "buddies:\n  - key: " + good + "\n  - key: " + good + "\n",
		"bad expose":     "buddies:\n  - key: " + good + "\n    expose: [notaport]\n",
		"empty expose":   "buddies:\n  - key: " + good + "\n    expose: []\n",
		"expose scalar":  "buddies:\n  - key: " + good + "\n    expose: 873\n",
		"bad name chars": "buddies:\n  - key: " + good + "\n    name: \"a b\"\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "peers.yaml")
			writeFile(t, path, content)
			if _, err := loadPeersFile(path); err == nil {
				t.Fatalf("%s: expected an error", name)
			}
		})
	}
}

// A legacy manifest converts in place; the YAML result parses to the same
// specs, and `peers add/remove` refuse the legacy format before migration.
func TestPeersMigrate(t *testing.T) {
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	b, _, _ := ed25519.GenerateKey(rand.Reader)
	aB64, bB64 := bcrypto.PubKeyB64(a), bcrypto.PubKeyB64(b)

	dir := t.TempDir()
	path := filepath.Join(dir, "peers")
	known := filepath.Join(dir, "known_peers")
	writeFile(t, path, aB64+" boot-a\n"+bB64+"\n")

	if err := PeersAdd(path, known, bB64, "", "", ""); err == nil {
		t.Fatal("peers add on a legacy manifest must refuse and point at migrate")
	}
	if err := PeersMigrate(path, known); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	specs, err := loadPeersFile(path)
	if err != nil {
		t.Fatalf("reload after migrate: %v", err)
	}
	if len(specs) != 2 || !specs[0].pin.Equal(a) || specs[0].token != "boot-a" || specs[1].token != "" {
		t.Fatalf("migrated specs = %+v", specs)
	}
	// Idempotent: a second migrate is a no-op, and the file stays writable.
	if err := PeersMigrate(path, known); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	c, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := PeersAdd(path, known, bcrypto.PubKeyB64(c), "boot-c", "carol", "tcp/8080"); err != nil {
		t.Fatalf("add after migrate: %v", err)
	}
	specs, err = loadPeersFile(path)
	if err != nil || len(specs) != 3 {
		t.Fatalf("after add: specs=%d err=%v", len(specs), err)
	}
	if specs[2].name != "carol" || specs[2].expose == nil || specs[2].expose.String() != "tcp/8080" {
		t.Fatalf("added spec = %+v", specs[2])
	}
}

func TestLoadPeersFileEmptyPath(t *testing.T) {
	specs, err := loadPeersFile("")
	if err != nil || specs != nil {
		t.Fatalf("empty path: specs=%v err=%v", specs, err)
	}
}

// assemblePeers unions the manifest with stored sessions: a session for a key
// already in the manifest is folded in (the manifest entry wins), and a session
// for a key NOT in the manifest is kept as a reconnect-only peer.
func TestAssemblePeersUnion(t *testing.T) {
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	b, _, _ := ed25519.GenerateKey(rand.Reader)
	c, _, _ := ed25519.GenerateKey(rand.Reader)
	aB64, bB64, cB64 := bcrypto.PubKeyB64(a), bcrypto.PubKeyB64(b), bcrypto.PubKeyB64(c)

	dir := t.TempDir()
	manifest := filepath.Join(dir, "peers")
	writeFile(t, manifest, aB64+" boot-a\n"+bB64+" boot-b\n")

	known := filepath.Join(dir, "known_peers")
	// a is already paired (session); c is a previously paired peer not in the manifest.
	if err := saveSession(known, "t", aB64, "secret-a"); err != nil {
		t.Fatal(err)
	}
	if err := saveSession(known, "t", cB64, "secret-c"); err != nil {
		t.Fatal(err)
	}

	specs, err := assemblePeers(BuddyConfig{PeersFile: manifest, KnownPeers: known})
	if err != nil {
		t.Fatalf("assemblePeers: %v", err)
	}
	got := map[string]string{}
	for _, s := range specs {
		got[bcrypto.PubKeyB64(s.pin)] = s.token
	}
	if len(got) != 3 {
		t.Fatalf("want 3 peers (a,b,c), got %d: %v", len(got), got)
	}
	if _, ok := got[aB64]; !ok {
		t.Fatal("manifest peer a missing")
	}
	if got[bB64] != "boot-b" {
		t.Fatalf("b token = %q, want boot-b", got[bB64])
	}
	if _, ok := got[cB64]; !ok {
		t.Fatal("session-only peer c must be kept as reconnect-only")
	}
	if got[cB64] != "" {
		t.Fatalf("c should be token-less, got %q", got[cB64])
	}
}

// The migrate backup carries the legacy manifest's bootstrap tokens. A .bak
// planted beforehand — as a symlink elsewhere, or as a world-readable file —
// must neither be written through nor keep its mode: the backup is written like
// every other state file, to a temp name and renamed into place at 0600.
func TestPeersMigrateBackupIsNotWrittenThroughAPlantedFile(t *testing.T) {
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	aB64 := bcrypto.PubKeyB64(a)

	dir := t.TempDir()
	path := filepath.Join(dir, "peers")
	known := filepath.Join(dir, "known_peers")
	writeFile(t, path, aB64+" boot-a\n")

	// A planted symlink: the backup must replace it, not follow it.
	target := filepath.Join(dir, "elsewhere")
	writeFile(t, target, "untouched\n")
	if err := os.Symlink(target, path+".bak"); err != nil {
		t.Fatal(err)
	}
	if err := PeersMigrate(path, known); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "untouched\n" {
		t.Fatalf("backup was written THROUGH the planted symlink: target now %q", got)
	}
	fi, err := os.Lstat(path + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("backup is still the planted symlink")
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %o, want 0600", fi.Mode().Perm())
	}
	if got, _ := os.ReadFile(path + ".bak"); !strings.Contains(string(got), "boot-a") {
		t.Fatalf("backup does not hold the legacy manifest: %q", got)
	}

	// A planted world-readable file: the mode must end up 0600, not inherited.
	path2 := filepath.Join(dir, "peers2")
	writeFile(t, path2, aB64+" boot-a\n")
	if err := os.WriteFile(path2+".bak", []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := PeersMigrate(path2, known); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	fi, _ = os.Stat(path2 + ".bak")
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup over a 0644 file kept mode %o, want 0600", fi.Mode().Perm())
	}
}
