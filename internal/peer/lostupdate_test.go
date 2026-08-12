package peer

// Regression tests for M-01: Registry.Upsert used to mutate the map under r.mu,
// take a snapshot, RELEASE the lock, and only then call save(snapshot). Two
// concurrent upserts could therefore rename an older roster over a newer one:
//
//	A: lock, add A, snapshot [A],   unlock
//	B: lock, add B, snapshot [A,B], unlock
//	B: save [A,B]      <- file correct
//	A: save [A]        <- file loses B
//
// Not a data race in the Go race detector's sense (every map access is under the
// mutex) — a lost update on the persisted file. The in-memory registry stayed
// correct, so the loss only showed after a restart, which is exactly when
// peers.json matters: it is the offline link of the connection fallback chain.
//
// peers.json has ONE writer process (internal/role/connect.go is the only caller
// of Upsert; the `peers` CLI subcommands work on the manifest and known_peers and
// only READ this file), so ordering the in-process writers is sufficient and no
// file lock is involved. Multi-process writing is deliberately not supported — it
// would need more than an flock, since two processes hold divergent in-memory
// snapshots.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tzero78/buddynet/pkg/protocol"
)

// testPeer builds a distinct, realistic peer.
func testPeer(i int) protocol.Peer {
	return protocol.Peer{
		ID:        fmt.Sprintf("peer-%03d", i),
		PubKey:    fmt.Sprintf("pubkey-%03d", i),
		VirtualIP: fmt.Sprintf("10.66.%d.%d", i/256, i%256),
	}
}

// readPeersFile reads peers.json back the way a restarting node would.
func readPeersFile(t *testing.T, path string) []protocol.Peer {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var list []protocol.Peer
	if err := json.Unmarshal(data, &list); err != nil {
		t.Fatalf("peers.json is not valid JSON: %v", err)
	}
	return list
}

func ids(list []protocol.Peer) []string {
	out := make([]string, 0, len(list))
	for _, p := range list {
		out = append(out, p.ID)
	}
	sort.Strings(out)
	return out
}

// missing lists the IDs present in memory but absent from the file.
func missing(mem, disk []protocol.Peer) []string {
	have := map[string]bool{}
	for _, p := range disk {
		have[p.ID] = true
	}
	var out []string
	for _, p := range mem {
		if !have[p.ID] {
			out = append(out, p.ID)
		}
	}
	sort.Strings(out)
	return out
}

// TestUpsertSerialisesWritesUnderWriteMu is the permanent regression gate. It
// drives TWO REAL Upsert calls and uses the duringSave hook to hold the first
// write open, so the interleaving is chosen by the test rather than by the
// scheduler — no repetition, no probabilistic loop.
//
// On a build without writeMu, B runs straight past A (it only ever needed r.mu,
// which A has long released), writes [A,B], and A then overwrites it with its
// stale [A]. With writeMu, B waits for A's write to finish and its own snapshot
// therefore contains A.
func TestUpsertSerialisesWritesUnderWriteMu(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	var saves atomic.Int32
	firstInSave := make(chan struct{})  // A has its snapshot, has not written yet
	secondInSave := make(chan struct{}) // B reached the write — must not happen while A holds
	release := make(chan struct{})      // let A finish

	duringSave = func() {
		switch saves.Add(1) {
		case 1:
			close(firstInSave)
			<-release
		case 2:
			close(secondInSave)
		}
	}
	t.Cleanup(func() { duringSave = nil })

	errA := make(chan error, 1)
	go func() { errA <- r.Upsert(testPeer(1)) }()
	<-firstInSave // A is inside the write, holding writeMu

	errB := make(chan error, 1)
	go func() { errB <- r.Upsert(testPeer(2)) }()

	// B must NOT reach its own write while A's is in flight. Proving a negative
	// needs a deadline; it is generous, and the decisive assertion is the file
	// content after the join below, which is fully deterministic.
	select {
	case <-secondInSave:
		close(release)
		t.Fatal("a second Upsert started writing while the first write was still in flight:\n" +
			"writes are not serialised, so a slower writer can rename a stale roster over a newer one (M-01)")
	case <-errB:
		close(release)
		t.Fatal("a second Upsert COMPLETED while the first write was still in flight (M-01)")
	case <-time.After(500 * time.Millisecond):
		// B is parked on writeMu, as intended.
	}

	// Positive control: A really is mid-write, not finished — nothing has been
	// persisted yet, so the wait above was a wait and not a no-op.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("peers.json already exists while the first write is still held: %v", err)
	}

	close(release)
	if err := <-errA; err != nil {
		t.Fatalf("Upsert A: %v", err)
	}
	if err := <-errB; err != nil {
		t.Fatalf("Upsert B: %v", err)
	}

	if got := ids(readPeersFile(t, path)); len(got) != 2 {
		t.Fatalf(`M-01: the persisted roster lost a peer.

  in memory : %v
  on disk   : %v
  want      : both peers on disk

Upsert must hold writeMu across BOTH the snapshot and the write, or a writer that
snapshotted earlier can land later and undo a newer roster.`, ids(r.List()), got)
	}
}

// TestUpsertConcurrentDoesNotLosePeers runs the real Upsert concurrently with no
// test-controlled interleaving at all — belt and braces behind the deterministic
// gate above. It runs several independent rounds because a single round hit the
// old window in only ~55-80% of runs.
func TestUpsertConcurrentDoesNotLosePeers(t *testing.T) {
	const (
		n      = 32 // concurrent writers per round
		rounds = 12
	)
	var lossyRounds int
	var firstLoss string

	for round := 0; round < rounds; round++ {
		path := filepath.Join(t.TempDir(), "peers.json")
		r, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make([]error, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start // release them together
				errs[i] = r.Upsert(testPeer(i))
			}(i)
		}
		close(start)
		wg.Wait()

		// Positive control 1: every Upsert reported success.
		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d: Upsert %d returned an error: %v", round, i, err)
			}
		}
		// Positive control 2: the in-memory registry has all of them, so each call
		// really did its work and the only thing at issue is what reached the disk.
		mem := r.List()
		if len(mem) != n {
			t.Fatalf("round %d: in-memory registry holds %d of %d peers", round, len(mem), n)
		}

		onDisk := readPeersFile(t, path)
		if len(onDisk) != n {
			lossyRounds++
			if firstLoss == "" {
				firstLoss = fmt.Sprintf("round %d lost %d of %d peers (missing: %v)",
					round, n-len(onDisk), n, missing(mem, onDisk))
			}
		}
	}

	if lossyRounds > 0 {
		t.Fatalf(`M-01: concurrent Upserts lost peers from peers.json in %d of %d rounds.

  first loss : %s
  writers    : %d per round, all returning nil
  in memory  : complete in every round

The loss is purely in the persisted file: a snapshot taken before another writer's
was renamed over it.`, lossyRounds, rounds, firstLoss, n)
	}
}

// TestUpsertSequentialKeepsEveryPeer is the positive control for the test above:
// the same peers, upserted one after another, are all persisted. If this ever
// fails, the concurrent test's failure is not about concurrency.
func TestUpsertSequentialKeepsEveryPeer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	const n = 32
	for i := 0; i < n; i++ {
		if err := r.Upsert(testPeer(i)); err != nil {
			t.Fatal(err)
		}
	}
	if got := readPeersFile(t, path); len(got) != n {
		t.Fatalf("sequential upserts persisted %d of %d peers: %v", len(got), n, ids(got))
	}
}

// TestUpsertReportsWriteFailure: a write that cannot happen must surface as an
// error rather than being swallowed, or a node keeps running with a peer cache it
// silently failed to persist and finds out only after a restart.
func TestUpsertReportsWriteFailure(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	r, err := Open(filepath.Join(sub, "peers.json")) // opens fine: no file yet
	if err != nil {
		t.Fatal(err)
	}
	// Now make the parent a FILE, so the write cannot succeed. Doing this AFTER
	// Open keeps the failure in the write path, which is what is under test (and
	// keeps the test meaningful when run as root, where a chmod would not bite).
	if err := os.RemoveAll(sub); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sub, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.Upsert(testPeer(1)); err == nil {
		t.Fatal("Upsert reported success although the roster could not be written")
	}
	// The in-memory view still holds it: a failed write must not lose the peer for
	// the running process, only for the next restart.
	if got := r.List(); len(got) != 1 {
		t.Fatalf("in-memory registry dropped the peer after a failed write: %v", ids(got))
	}
}
