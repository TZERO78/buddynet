package role

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
)

// A group/other-readable allowlist is tightened to 0600 on read (F-1).
func TestReadAuthorizedTightensPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized")
	pub := bcrypto.PubKeyB64(genKey(t))
	if err := os.WriteFile(path, []byte(pub+" label\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readAuthorized(path); err != nil {
		t.Fatalf("readAuthorized: %v", err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perms = %o, want 600", fi.Mode().Perm())
	}
}

// AllowClient must persist a NON-reversible code tag, never the cleartext
// enrollment code, in the allowlist label (F-3).
func TestAllowClientLabelIsHashed(t *testing.T) {
	dir := t.TempDir()
	authorized := filepath.Join(dir, "authorized")
	pending := authorized + ".pending"
	key := bcrypto.PubKeyB64(genKey(t))
	const code = "SECRET-CODE-1234"

	// Seed a pending enrollment keyed by the code hash (as recordPending would).
	line := fmt.Sprintf("%s %s %d\n", shortHash(code), key, time.Now().Unix())
	if err := os.WriteFile(pending, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AllowClient(authorized, code); err != nil {
		t.Fatalf("AllowClient: %v", err)
	}
	data, _ := os.ReadFile(authorized)
	if strings.Contains(string(data), code) {
		t.Fatalf("cleartext enrollment code leaked into the allowlist: %q", data)
	}
	if !strings.Contains(string(data), "code:"+shortHash(code)) {
		t.Fatalf("expected a hashed code label, got: %q", data)
	}
}

// A huge allowlist is capped so it cannot build an unbounded map (F-2).
func TestReadAuthorizedCapsKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	// Cheap distinct valid-shaped pubkeys (validPubKey only checks base64 + length),
	// so we don't pay for 100k real key generations.
	for i := 0; i < maxAuthorizedKeys+50; i++ {
		var b [ed25519.PublicKeySize]byte
		binary.LittleEndian.PutUint64(b[:], uint64(i))
		fmt.Fprintln(f, base64.StdEncoding.EncodeToString(b[:]))
	}
	f.Close()
	keys, _, err := readAuthorized(path)
	if err != nil {
		t.Fatalf("readAuthorized: %v", err)
	}
	if len(keys) > maxAuthorizedKeys {
		t.Fatalf("allowlist not capped: %d keys", len(keys))
	}
}
