package role

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
)

// genDistinctVIPKeys returns n keys whose virtual IPs are all distinct, so a
// count-limit test is never perturbed by an incidental VIP collision.
func genDistinctVIPKeys(t *testing.T, n int) []ed25519.PublicKey {
	t.Helper()
	out := make([]ed25519.PublicKey, 0, n)
	seen := map[string]bool{}
	for len(out) < n {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		if vip := bcrypto.VirtualIPString(pub); !seen[vip] {
			seen[vip] = true
			out = append(out, pub)
		}
	}
	return out
}

func writePeersKeys(t *testing.T, path string, keys []ed25519.PublicKey) {
	t.Helper()
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(bcrypto.PubKeyB64(k) + "\n")
	}
	writeFile(t, path, b.String())
}

// assemblePeers must accept exactly MaxBuddies and refuse MaxBuddies+1.
func TestMaxBuddiesEnforced(t *testing.T) {
	dir := t.TempDir()

	ok := filepath.Join(dir, "ok")
	writePeersKeys(t, ok, genDistinctVIPKeys(t, MaxBuddies))
	specs, err := assemblePeers(BuddyConfig{PeersFile: ok})
	if err != nil {
		t.Fatalf("MaxBuddies should assemble cleanly, got: %v", err)
	}
	if len(specs) != MaxBuddies {
		t.Fatalf("want %d specs, got %d", MaxBuddies, len(specs))
	}

	over := filepath.Join(dir, "over")
	writePeersKeys(t, over, genDistinctVIPKeys(t, MaxBuddies+1))
	if _, err := assemblePeers(BuddyConfig{PeersFile: over}); err == nil {
		t.Fatal("MaxBuddies+1 must be refused fail-closed")
	}
}

// Two distinct keys mapping to the same VIP must be rejected at assembly.
func TestVIPCollisionDetected(t *testing.T) {
	// Grind two keys onto the same 16-bit VIP — cheap: birthday bound puts a
	// collision within a few hundred keys for the 65534-value space.
	byVIP := map[string]ed25519.PublicKey{}
	var a, b ed25519.PublicKey
	for i := 0; i < 1_000_000 && b == nil; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		vip := bcrypto.VirtualIPString(pub)
		if prev, ok := byVIP[vip]; ok {
			a, b = prev, pub
		} else {
			byVIP[vip] = pub
		}
	}
	if b == nil {
		t.Skip("no VIP collision found (improbable) — skipping")
	}

	path := filepath.Join(t.TempDir(), "peers")
	writePeersKeys(t, path, []ed25519.PublicKey{a, b})
	_, err := assemblePeers(BuddyConfig{PeersFile: path})
	if err == nil || !strings.Contains(err.Error(), "VIP collision") {
		t.Fatalf("want a VIP collision error, got: %v", err)
	}

	// 48 distinct-VIP keys must NOT trip the collision check.
	okPath := filepath.Join(t.TempDir(), "peers")
	writePeersKeys(t, okPath, genDistinctVIPKeys(t, MaxBuddies))
	if _, err := assemblePeers(BuddyConfig{PeersFile: okPath}); err != nil {
		t.Fatalf("distinct-VIP set must not trip collision check: %v", err)
	}
}

// Regression guard: the documented design limit is 48.
func TestMaxBuddiesConstantDocument(t *testing.T) {
	if MaxBuddies != 48 {
		t.Fatalf("MaxBuddies changed from 48 to %d — update this test if intentional", MaxBuddies)
	}
}
