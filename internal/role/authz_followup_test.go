package role

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

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
