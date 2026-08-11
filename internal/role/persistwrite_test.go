package role

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

// A lock we cannot take must REFUSE the write, not fall back to an unsynchronised
// one: the moment the lock is contended is exactly the moment another process is
// mid-update. The earlier lockAllowlist returned a no-op unlock on failure, so
// the caller wrote anyway — best-effort in the one case where best-effort is
// wrong.
func TestPendingWriteFailsClosedWhenTheLockCannotBeTaken(t *testing.T) {
	nd, srvPriv := testNode(t)
	authz := newTestAuthorizer(t, srvPriv)
	pub := srvPriv.Public().(ed25519.PublicKey)

	first, err := bcrypto.SealCode("FIRST-CODE", pub)
	if err != nil {
		t.Fatal(err)
	}
	authz.recordPending(first, nd.pub)
	before, err := os.ReadFile(authz.pendDB)
	if err != nil || len(before) == 0 {
		t.Fatalf("setup: the first entry must be on disk (%v)", err)
	}

	// 1. Lock acquisition fails, deterministically.
	saved := acquireLock
	var attempts int
	acquireLock = func(string) (func(), error) {
		attempts++
		return nil, errors.New("simulated: lock held by another process")
	}
	t.Cleanup(func() { acquireLock = saved })

	second, err := bcrypto.SealCode("SECOND-CODE", pub)
	if err != nil {
		t.Fatal(err)
	}
	authz.recordPending(second, nd.pub)

	if attempts == 0 {
		t.Fatal("the write path never tried to take the lock")
	}
	// 2./3. The file is untouched — no unprotected atomic write happened.
	after, err := os.ReadFile(authz.pendDB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("the pending file was written without the lock:\n before %q\n after  %q", before, after)
	}
	// And no stray temp file was left behind either.
	entries, err := os.ReadDir(filepath.Dir(authz.pendDB))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("an unprotected write left a temp file: %s", e.Name())
		}
	}
	// 4. The state is dirty, so the next attempt will retry.
	authz.mu.RLock()
	dirty := authz.pendDirty
	authz.mu.RUnlock()
	if !dirty {
		t.Fatal("a refused write did not mark the pending state dirty — the entry would never be retried")
	}

	// 5. With the lock available again, the CURRENT full snapshot is persisted —
	//    both codes, not just the one that failed.
	acquireLock = saved
	authz.recordPending(second, nd.pub)
	final, err := os.ReadFile(authz.pendDB)
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"FIRST-CODE", "SECOND-CODE"} {
		if !strings.Contains(string(final), shortHash(code)) {
			t.Errorf("after the lock came back, %s is missing from the file: %q", code, final)
		}
	}
	authz.mu.RLock()
	stillDirty := authz.pendDirty
	authz.mu.RUnlock()
	if stillDirty {
		t.Error("the state is still dirty after a successful write")
	}
}

// The lock orders the writes; it does not make the server's memory the truth.
// This is the sequence a working flock does NOT prevent:
//
//  1. the server holds an older state in memory,
//  2. the CLI (`allowclient`) modifies the same file correctly, under the lock,
//  3. the server then takes the lock,
//  4. the server writes its stale memory,
//  5. the CLI's change is lost — the approved code is RESURRECTED as pending.
//
// The server must therefore read the file under the lock and merge, contributing
// only what it added itself, rather than overwriting with its own map.
func TestServerWriteDoesNotResurrectAnApprovedCode(t *testing.T) {
	nd, srvPriv := testNode(t)
	authz := newTestAuthorizer(t, srvPriv)
	pub := srvPriv.Public().(ed25519.PublicKey)
	allowPath := authz.path

	const approved = "CODE-TO-APPROVE"
	sealedApproved, err := bcrypto.SealCode(approved, pub)
	if err != nil {
		t.Fatal(err)
	}

	// 1. The server learns the pending code and persists it.
	authz.recordPending(sealedApproved, nd.pub)
	if data, rerr := os.ReadFile(authz.pendDB); rerr != nil || !strings.Contains(string(data), shortHash(approved)) {
		t.Fatalf("setup: the pending entry is not on disk (%v, %q)", rerr, data)
	}

	// 2. The operator approves it. AllowClient removes it from the file, under the
	//    same lock the server uses.
	if err := AllowClient(allowPath, approved); err != nil {
		t.Fatalf("AllowClient: %v", err)
	}
	afterApprove, err := os.ReadFile(authz.pendDB)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(afterApprove), shortHash(approved)) {
		t.Fatalf("setup: allowclient did not remove the entry: %q", afterApprove)
	}

	// 3./4. The server still has it in memory and now writes — triggered by a
	//       SECOND, unrelated client enrolling, exactly as in production. A
	//       different key on purpose: an entry whose key the operator has already
	//       approved is dropped by design, so reusing nd.pub here would test that
	//       rule instead of the resurrection it is meant to catch.
	other, err := bcrypto.SealCode("SOME-OTHER-CODE", pub)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := testNode(t)
	authz.recordPending(other, second.pub)

	// 5. The approved code must NOT be back.
	final, err := os.ReadFile(authz.pendDB)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(final), shortHash(approved)) {
		t.Errorf("the server's stale memory resurrected an already-approved code:\n%q\n"+
			"the operator's `allowclient` was undone by the next registration", final)
	}
	// ...and the unrelated entry the server was actually persisting is there.
	if !strings.Contains(string(final), shortHash("SOME-OTHER-CODE")) {
		t.Errorf("the server's own new entry was lost in the merge: %q", final)
	}
	// The in-memory view is realigned too, or the next write would resurrect it.
	authz.mu.RLock()
	_, stillInMemory := authz.pend[shortHash(approved)]
	authz.mu.RUnlock()
	if stillInMemory {
		t.Error("the approved code is still in the server's map — the next write brings it back")
	}
}

// Retiring a contribution by KEY alone is not enough. recordPending does not hold
// writeMu, so it can update the same code while a write is in flight:
//
//  1. the writer takes code A with Seen=T1,
//  2. recordPending updates A to Seen=T2 during the write,
//  3. the write finishes,
//  4. the writer must NOT retire A — T2 was never written.
//
// Deleting by key would discard T2 silently, and nothing would ever write it: the
// client re-registering finds A already in the map (isNew=false) and contributes
// nothing.
func TestRetiringAContributionComparesTheValue(t *testing.T) {
	nd, srvPriv := testNode(t)
	authz := newTestAuthorizer(t, srvPriv)
	sealed, err := bcrypto.SealCode("SAME-CODE", srvPriv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	h := shortHash("SAME-CODE")
	newer := pendingEntry{Key: nd.pub, Seen: time.Now().Add(90 * time.Second)}

	saved := duringPendWrite
	var fired bool
	duringPendWrite = func() {
		if fired {
			return
		}
		fired = true
		// Step 2: the same code is updated while the write is in flight.
		authz.mu.Lock()
		authz.pend[h] = newer
		authz.pendAdded[h] = newer
		authz.mu.Unlock()
	}
	t.Cleanup(func() { duringPendWrite = saved })

	authz.recordPending(sealed, nd.pub) // step 1 + 3
	if !fired {
		t.Fatal("the hook never ran — the test did not exercise a write at all")
	}

	authz.mu.RLock()
	queued, stillQueued := authz.pendAdded[h]
	authz.mu.RUnlock()
	if !stillQueued {
		t.Fatal("the newer entry was retired although it was never written — " +
			"retiring by key alone drops an update that arrived during the write")
	}
	if !queued.Seen.Equal(newer.Seen) {
		t.Fatalf("queued entry is %v, want the newer %v", queued.Seen, newer.Seen)
	}
}

// A CLI-confirmed approval wins over a contribution that is still QUEUED, not
// just over a stale in-memory entry:
//
//  1. A is already on disk,
//  2. a write fails, so A is queued in pendAdded and the state is dirty,
//  3. `allowclient` approves A and removes it, under the file lock,
//  4. the server's next write merges its queued A — and must not bring it back.
func TestApprovalBeatsAQueuedContribution(t *testing.T) {
	nd, srvPriv := testNode(t)
	authz := newTestAuthorizer(t, srvPriv)
	pub := srvPriv.Public().(ed25519.PublicKey)
	const code = "QUEUED-CODE"
	sealed, err := bcrypto.SealCode(code, pub)
	if err != nil {
		t.Fatal(err)
	}

	// 1. On disk.
	authz.recordPending(sealed, nd.pub)
	// 2. A failed write leaves it queued and the state dirty.
	authz.mu.Lock()
	authz.pendAdded[shortHash(code)] = authz.pend[shortHash(code)]
	authz.pendDirty = true
	authz.mu.Unlock()

	// 3. The operator approves it.
	if err := AllowClient(authz.path, code); err != nil {
		t.Fatalf("AllowClient: %v", err)
	}

	// 4. The next write must not resurrect it. Another client's enrollment is what
	//    triggers the write in production.
	other, _ := testNode(t)
	otherSealed, err := bcrypto.SealCode("UNRELATED-CODE", pub)
	if err != nil {
		t.Fatal(err)
	}
	authz.recordPending(otherSealed, other.pub)

	data, err := os.ReadFile(authz.pendDB)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), shortHash(code)) {
		t.Errorf("a QUEUED contribution undid the operator's approval:\n%q", data)
	}
	authz.mu.RLock()
	_, stillQueued := authz.pendAdded[shortHash(code)]
	authz.mu.RUnlock()
	if stillQueued {
		t.Error("the approved code is still queued — it would be written at the next opportunity")
	}
}
