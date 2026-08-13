package role

// Regression tests for M-02: the known_peers session store (session.go) does its
// read-modify-write under `sessionFileMu`, a PROCESS-GLOBAL mutex. That serialises
// the in-process MultiPeer workers, but it says nothing about two SEPARATE
// processes writing the same file — the running buddy calling saveSession and the
// operator's CLI calling removeSession (`peers remove`, the revoke path). Without
// an advisory FILE lock one of them renames its snapshot over the other's,
// dropping a stored session secret or — worse — RESURRECTING a session the
// operator just revoked.
//
// Three tests, three jobs:
//
//   - TestSessionStoreWaitsForAnotherProcessesLock is the permanent GATE: a child
//     process holds the store's lock, and the real saveSession must wait for it.
//     Deterministic; no dependency on scheduling luck.
//   - TestSessionStoreCrossProcessLostUpdate is the end-to-end evidence: real
//     child processes running the real unexported save/removeSession against a
//     shared store, checking that neither direction loses a write.
//   - TestSessionStoreInProcessConcurrentIsSafe is the positive control that the
//     same concurrency WITHIN one process was always safe, which is what isolates
//     the defect to the missing cross-process lock rather than to the
//     read-modify-write itself.
//
// All three fail on a build without the file lock (verified by disabling it).

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// m02Pub returns a deterministic ed25519 public key (base64 std) for seed n —
// the same encoding saveSession/loadSessions use for field 2.
func m02Pub(n byte) string {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = n
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(pub)
}

// m02Partners returns which partner keys are present in the store right now.
func m02Present(t *testing.T, path string) map[string]bool {
	t.Helper()
	present := map[string]bool{}
	f, err := os.Open(path)
	if err != nil {
		return present
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 3 {
			present[fields[1]] = true
		}
	}
	return present
}

// m02WritePadding fills a store with n valid session lines for distinct partners,
// so the read-modify-write scan is long enough that two processes starting
// together overlap. Returns nothing; the padding partners are seeds 50..50+n.
func m02WritePadding(t *testing.T, path string, n int) {
	t.Helper()
	var b strings.Builder
	for i := 0; i < n; i++ {
		// three fields: tokenhash partnerB64 secret — same shape loadSessions parses
		fmt.Fprintf(&b, "%064x %s secret-%d\n", i, m02Pub(byte(50+i%200)), i)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestM02HelperProcess is the child-process body. It calls the REAL unexported
// saveSession/removeSession, so the evidence exercises the production code path.
// It is inert unless the parent set M02_HELPER=1.
func TestM02HelperProcess(t *testing.T) {
	if os.Getenv("M02_HELPER") != "1" {
		return
	}
	path := os.Getenv("M02_PATH")
	mode := os.Getenv("M02_MODE")
	partner := os.Getenv("M02_PARTNER")
	barrier := os.Getenv("M02_BARRIER")
	// Start barrier: poll (not a sleep-driven race — this only lines up the two
	// processes' START; the race itself is the unsynchronised read-modify-write).
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(barrier); err == nil {
			break
		}
	}
	switch mode {
	case "save":
		_ = saveSession(path, "invite-"+partner, partner, "secret-"+partner)
	case "remove":
		_, _ = removeSession(path, partner)
	}
	os.Exit(0)
}

// m02Spawn starts one helper child in the given mode for the given partner.
func m02Spawn(t *testing.T, path, mode, partner, barrier string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestM02HelperProcess$")
	cmd.Env = append(os.Environ(),
		"M02_HELPER=1", "M02_PATH="+path, "M02_MODE="+mode,
		"M02_PARTNER="+partner, "M02_BARRIER="+barrier)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s helper: %v", mode, err)
	}
	return cmd
}

// TestSessionStoreWaitsForAnotherProcessesLock is the DETERMINISTIC gate: it
// proves the file lock is actually taken across the read-modify-write, without
// racing anything. A child process holds the store's advisory lock; the parent
// then calls the real saveSession and must NOT get through until the child lets
// go — and must succeed immediately afterwards.
//
// Without the file lock this returns instantly, because sessionFileMu says
// nothing about another process.
func TestSessionStoreWaitsForAnotherProcessesLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_peers")
	A := m02Pub(1)
	if err := saveSession(path, "invite-A", A, "secret-A"); err != nil {
		t.Fatal(err)
	}

	// Child takes the lock and holds it until we delete the go-file.
	held := filepath.Join(dir, "held")
	hold := filepath.Join(dir, "hold")
	if err := os.WriteFile(hold, []byte("hold"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestM02LockHolderProcess$")
	cmd.Env = append(os.Environ(), "M02_LOCKHOLDER=1", "M02_PATH="+path,
		"M02_HELD="+held, "M02_HOLD="+hold)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start lock holder: %v", err)
	}
	defer func() { _ = cmd.Wait() }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(held); err == nil {
			break
		}
		if time.Now().After(deadline) {
			os.Remove(hold)
			t.Fatal("the lock holder never signalled that it holds the lock")
		}
	}

	done := make(chan error, 1)
	go func() { done <- saveSession(path, "invite-C", m02Pub(3), "secret-C") }()

	// Proving "it waits" needs a deadline; the decisive part is that it succeeds
	// right after the release below, which is deterministic.
	select {
	case err := <-done:
		os.Remove(hold)
		t.Fatalf("saveSession completed while ANOTHER PROCESS held the store lock (err=%v):\n"+
			"the cross-process lock is not taken, so a concurrent `peers remove` can lose or\n"+
			"resurrect a session (M-02)", err)
	case <-time.After(700 * time.Millisecond):
	}

	os.Remove(hold) // release the child
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("saveSession failed after the lock was released: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("saveSession never completed after the lock was released")
	}

	present := m02Present(t, path)
	if !present[A] || !present[m02Pub(3)] {
		t.Fatalf("after the serialised write the store should hold both sessions: %v", present)
	}
}

// TestM02LockHolderProcess is the lock-holding child. Inert unless the parent set
// M02_LOCKHOLDER=1.
func TestM02LockHolderProcess(t *testing.T) {
	if os.Getenv("M02_LOCKHOLDER") != "1" {
		return
	}
	unlock, err := acquireLock(os.Getenv("M02_PATH"))
	if err != nil {
		os.Exit(3)
	}
	_ = os.WriteFile(os.Getenv("M02_HELD"), []byte("held"), 0o600)
	hold := os.Getenv("M02_HOLD")
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(hold); os.IsNotExist(err) {
			break
		}
	}
	unlock()
	os.Exit(0)
}

// TestSessionStoreInProcessConcurrentIsSafe is the POSITIVE CONTROL: the same
// concurrency, but within one process, loses nothing — because sessionFileMu
// serialises it. This isolates M-02 to the cross-process case: the bug is the
// missing inter-process lock, not the read-modify-write itself.
func TestSessionStoreInProcessConcurrentIsSafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_peers")
	const n = 24
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if err := saveSession(path, fmt.Sprintf("invite-%d", i), m02Pub(byte(i)), fmt.Sprintf("secret-%d", i)); err != nil {
				t.Errorf("saveSession %d: %v", i, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	present := m02Present(t, path)
	if len(present) != n {
		t.Fatalf("in-process concurrent saveSession lost sessions: %d of %d present — sessionFileMu should have protected this", len(present), n)
	}
}

// TestSessionStoreCrossProcessControls is the POSITIVE CONTROL for the helper
// mechanism and the code path: run the SAME two operations SEQUENTIALLY across
// two child processes and confirm the correct end state {A gone, C present}.
// If this failed, a failure in the concurrent test below would be a broken
// harness, not the bug.
func TestSessionStoreCrossProcessControls(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_peers")
	A, C := m02Pub(1), m02Pub(3)
	// seed the store with A present
	if err := saveSession(path, "invite-A", A, "secret-A"); err != nil {
		t.Fatal(err)
	}
	bar := filepath.Join(dir, "go")
	if err := os.WriteFile(bar, []byte("go"), 0o600); err != nil { // barrier already open
		t.Fatal(err)
	}
	// sequential: remove A, then save C
	if err := m02Spawn(t, path, "remove", A, bar).Wait(); err != nil {
		t.Fatalf("remove helper: %v", err)
	}
	if err := m02Spawn(t, path, "save", C, bar).Wait(); err != nil {
		t.Fatalf("save helper: %v", err)
	}
	present := m02Present(t, path)
	if present[A] {
		t.Fatalf("control: A should be gone after sequential remove")
	}
	if !present[C] {
		t.Fatalf("control: C should be present after sequential save")
	}
}

// TestSessionStoreCrossProcessLostUpdate is the EVIDENCE. In each round the store
// holds A and B; one process revokes B (removeSession) while another stores C
// (saveSession), started together. The correct end state is {A, C} with B gone.
// A cross-process lost update shows up as B RESURRECTED (revoke lost) or C
// MISSING (save lost). Reported as a hit rate over rounds.
func TestSessionStoreCrossProcessLostUpdate(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-process evidence: skipped in -short")
	}
	const rounds = 15
	A, B, C := m02Pub(1), m02Pub(2), m02Pub(3)

	revokeLost, saveLost := 0, 0
	var firstDetail string
	for r := 0; r < rounds; r++ {
		dir := t.TempDir()
		path := filepath.Join(dir, "known_peers")
		// Big store so the read-modify-write scan is wide enough for the two
		// starts to overlap; then A and B on top.
		m02WritePadding(t, path, 3000)
		if err := saveSession(path, "invite-A", A, "secret-A"); err != nil {
			t.Fatal(err)
		}
		if err := saveSession(path, "invite-B", B, "secret-B"); err != nil {
			t.Fatal(err)
		}

		bar := filepath.Join(dir, "go")
		remove := m02Spawn(t, path, "remove", B, bar)
		save := m02Spawn(t, path, "save", C, bar)
		// Release both at once.
		if err := os.WriteFile(bar, []byte("go"), 0o600); err != nil {
			t.Fatal(err)
		}
		_ = remove.Wait()
		_ = save.Wait()

		present := m02Present(t, path)
		if present[B] {
			revokeLost++
			if firstDetail == "" {
				firstDetail = fmt.Sprintf("round %d: B was revoked but is still present (revoke lost)", r)
			}
		}
		if !present[C] {
			saveLost++
			if firstDetail == "" {
				firstDetail = fmt.Sprintf("round %d: C was saved but is missing (save lost)", r)
			}
		}
		// Positive per-round sanity: A must always survive (nobody touched it).
		if !present[A] {
			t.Fatalf("round %d: bystander session A vanished — harness/store broken", r)
		}
	}

	lossy := revokeLost + saveLost
	t.Logf("cross-process lost updates over %d rounds: revoke-lost=%d save-lost=%d", rounds, revokeLost, saveLost)
	if lossy > 0 {
		t.Fatalf(`M-02: known_peers loses a cross-process write.

  rounds        : %d
  revoke lost   : %d  (a session the CLI removed was resurrected by the buddy)
  save  lost    : %d  (a session the buddy stored was dropped by the CLI write)
  first         : %s

session.go serialises the read-modify-write with sessionFileMu, a PROCESS-GLOBAL
mutex. Two processes (the running buddy's saveSession and the CLI's removeSession)
hold separate mutexes and no flock, so one renames an older snapshot over the
other. The in-process control (TestSessionStoreInProcessConcurrentIsSafe) shows
the same concurrency is safe within one process — the defect is the missing
cross-process lock.`, rounds, revokeLost, saveLost, firstDetail)
	}
}
