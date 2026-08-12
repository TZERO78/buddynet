package role

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tzero78/buddynet/internal/atomicfile"
	bcrypto "github.com/tzero78/buddynet/internal/crypto"
)

// Durability of the two state files the CLIENT still writes: the session store
// (known_peers) and anything going through atomicfile. The server's pending file
// and its tests went with it in v5.0.0 — pending enrolments live in memory only.

// Several buddy workers store a session concurrently; none may be lost. The
// read-modify-write is serialised, and the write itself is atomic.
func TestConcurrentSessionSavesKeepEveryPartner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_peers")
	const n = 16

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		partner := bcrypto.PubKeyB64(pub)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if serr := saveSession(path, "invite-"+partner, partner, "secret-"+partner); serr != nil {
				t.Errorf("saveSession: %v", serr)
			}
		}(i)
	}
	wg.Wait()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(l) != "" {
			lines++
		}
	}
	if lines != n {
		t.Fatalf("session store holds %d of %d partners — concurrent saves lost sessions", lines, n)
	}
}

// No writer may leave a temp file behind, and none may collide on a shared temp
// name: two processes sharing a state file (server + operator CLI, or two servers

// during a protocol migration) used to write the SAME path+".tmp".

func TestAtomicWriteLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state")

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := writeStateForTest(path, i); err != nil {
				t.Errorf("write: %v", err)
			}
		}(i)
	}
	wg.Wait()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("a temp file survived the write: %s", e.Name())
		}
	}
	// And the surviving file is one writer's COMPLETE content, never a mix.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "writer-") || !strings.HasSuffix(string(data), "-end") {
		t.Fatalf("the file is torn: %q", data)
	}
}

// writeStateForTest writes a self-describing payload so a torn file is visible.
func writeStateForTest(path string, i int) error {
	body := "writer-" + strings.Repeat(string(rune('a'+i%26)), 4096) + "-end"
	return atomicfile.Write(path, []byte(body), 0o600)
}

// A lock we cannot take must REFUSE the write, not fall back to an unsynchronised
// one: the moment the lock is contended is exactly the moment another process is
// mid-update. The earlier lockAllowlist returned a no-op unlock on failure, so
// the caller wrote anyway — best-effort in the one case where best-effort is

// wrong.

// only what it added itself, rather than overwriting with its own map.

// nothing.

//  4. the server's next write merges its queued A — and must not bring it back.
