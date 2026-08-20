package role

// AUDIT 2026-08-20, finding A-02 (LOW / hardening): learnPeer writes the SAME
// known_peers file that saveSession/removeSession guard with an advisory FILE
// lock (lockFile, via the acquireLock indirection) plus sessionFileMu — but it
// takes NEITHER. It is a bare O_APPEND write.
//
// The project already closed exactly this class for saveSession/removeSession
// (finding M-02, see session_crossproc_test.go); learnPeer was not brought
// along. A TOFU line appended inside another process's read-modify-write window
// is dropped when that process renames its snapshot into place.
//
// The DIRECTION of failure is safe — a lost TOFU line makes the next connect
// demand a fresh SAS, i.e. more verification, not less — which is why this is
// rated hardening rather than a vulnerability. The real cost is availability: on
// an unattended TOFU node, trustPolicy.decide then returns needSAS=true and
// connect.go refuses with "first contact ... running non-interactively", so the
// tunnel stays down until a human runs it interactively.
//
// This test needs no sleeps and no scheduling luck: it takes the store lock the
// way every other writer of this file does, and shows learnPeer walks straight
// past it. The positive control shows saveSession — the same file, the same
// lock — correctly blocks.

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
)

// TestAuditLearnPeerIgnoresTheStoreLock: learnPeer completes and writes while
// the known_peers store lock is held by another holder.
func TestAuditLearnPeerIgnoresTheStoreLock(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "known_peers")
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	keyB64 := bcrypto.PubKeyB64(pub)

	if err := os.MkdirAll(filepath.Dir(store), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Hold the store lock exactly as saveSession/removeSession take it.
	unlock, err := acquireLock(store)
	if err != nil {
		t.Fatalf("acquireLock: %v", err)
	}
	defer unlock()

	done := make(chan error, 1)
	go func() { done <- learnPeer(store, "some-token", keyB64) }()

	select {
	case lerr := <-done:
		if lerr != nil {
			t.Fatalf("learnPeer errored for an unrelated reason: %v", lerr)
		}
	case <-time.After(3 * time.Second):
		t.Log("A-02 fixed: learnPeer waits for the store lock, like every other writer of this file")
		return
	}

	data, rerr := os.ReadFile(store)
	if rerr != nil {
		t.Fatalf("read store: %v", rerr)
	}
	if !strings.Contains(string(data), keyB64) {
		t.Fatalf("learnPeer returned nil but wrote nothing; store = %q", data)
	}
	t.Fatalf(`A-02 CONFIRMED — learnPeer bypasses the known_peers store lock.

learnPeer completed and wrote its TOFU line into %s while the advisory file lock
that saveSession and removeSession both take was HELD by another holder.

Every other writer of this file does a LOCKED read-modify-write; this one is a
bare O_APPEND (internal/role/trust.go, learnPeer). A TOFU line appended inside
another writer's read-modify-write window is lost when that writer renames its
snapshot into place — the same defect class as finding M-02, which was fixed for
saveSession/removeSession only.`, store)
}

// TestAuditStoreLockPositiveControl proves the lock and the harness work: the
// real saveSession, on the same file, DOES wait for the same lock. Without this
// the test above could be passing because the lock never engages at all.
func TestAuditStoreLockPositiveControl(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "known_peers")
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	keyB64 := bcrypto.PubKeyB64(pub)

	if err := os.MkdirAll(filepath.Dir(store), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	unlock, err := acquireLock(store)
	if err != nil {
		t.Fatalf("acquireLock: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- saveSession(store, "tok", keyB64, "secret") }()

	select {
	case serr := <-done:
		unlock()
		t.Fatalf("saveSession did NOT wait for the store lock (err=%v) — the lock "+
			"is not engaging, so the A-02 test above would prove nothing", serr)
	case <-time.After(500 * time.Millisecond):
		// Correct: it is parked on the lock.
	}
	unlock()
	if serr := <-done; serr != nil {
		t.Fatalf("saveSession after unlock: %v", serr)
	}
	if _, ok, _ := loadSessionFor(store, pub); !ok {
		t.Fatal("saveSession completed but stored nothing")
	}
	t.Log("positive control holds: saveSession waits for the store lock on the same file")
}
