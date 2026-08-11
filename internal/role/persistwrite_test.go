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

// A pending entry lost from the FILE must come back. recordPending only wrote
// when the entry was NEW, so once the file lost it, the client re-registering
// every second found "already in the map" and changed nothing: `allowclient
// <CODE>` stayed broken until the TTL expired or the server restarted.
func TestLostPendingEntryIsRewritten(t *testing.T) {
	nd, srvPriv := testNode(t)
	authz := newTestAuthorizer(t, srvPriv)
	sealed, err := bcrypto.SealCode("LEGIT-CODE", srvPriv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	authz.recordPending(sealed, nd.pub)
	if data, rerr := os.ReadFile(authz.pendDB); rerr != nil || len(data) == 0 {
		t.Fatalf("the first registration did not persist: %v %q", rerr, data)
	}

	// The file loses the entry — a failed write, or a concurrent writer that
	// clobbered it.
	if err := os.WriteFile(authz.pendDB, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	authz.mu.Lock()
	authz.pendDirty = true
	authz.mu.Unlock()

	// The client keeps re-registering, exactly as a real enrolling buddy does.
	authz.recordPending(sealed, nd.pub)

	data, err := os.ReadFile(authz.pendDB)
	if err != nil || len(data) == 0 {
		t.Fatalf("a lost pending entry was never rewritten (%v, %q) — allowclient stays broken", err, data)
	}
	if !strings.Contains(string(data), nd.pub) {
		t.Fatalf("the rewritten file does not name the enrolling key: %q", data)
	}
}

// Concurrent pending writes must all survive: the snapshot is taken inside the
// write lock, so a slower writer cannot rename an older set over a newer one.
func TestConcurrentPendingWritesKeepEveryEntry(t *testing.T) {
	nd, srvPriv := testNode(t)
	authz := newTestAuthorizer(t, srvPriv)
	pub := srvPriv.Public().(ed25519.PublicKey)

	const n = 24
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		code := "CONCURRENT-CODE-" + string(rune('a'+i))
		sealed, err := bcrypto.SealCode(code, pub)
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() { defer wg.Done(); authz.recordPending(sealed, nd.pub) }()
	}
	wg.Wait()

	data, err := os.ReadFile(authz.pendDB)
	if err != nil {
		t.Fatal(err)
	}
	onDisk := 0
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(l) != "" {
			onDisk++
		}
	}
	authz.mu.RLock()
	inMem := len(authz.pend)
	authz.mu.RUnlock()
	if onDisk != inMem {
		t.Fatalf("%d entries in memory but %d on disk — a write was lost (the CLI reads the FILE)", inMem, onDisk)
	}
	if inMem != n {
		t.Fatalf("only %d of %d concurrent enrollments were recorded at all", inMem, n)
	}
}

// The session store is a read-modify-write, and MultiPeer runs one worker per
// buddy: without serialisation the last writer drops every session another worker
// stored in between.
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
