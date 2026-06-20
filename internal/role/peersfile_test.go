package role

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
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
