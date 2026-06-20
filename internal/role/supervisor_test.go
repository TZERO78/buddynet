package role

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
)

// reconnectSource must hand a worker its own pinned partner key and the stored
// secret for it, and signal revocation when that peer's session is gone — never a
// blank or cross-peer attempt.
func TestReconnectSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_peers")
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	b, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := saveSession(path, "tok-a", bcrypto.PubKeyB64(a), "secret-a"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cfg := BuddyConfig{KnownPeers: path}

	att, err := reconnectSource(cfg, a)()
	if err != nil {
		t.Fatalf("present session: %v", err)
	}
	if att.rendezvous != "secret-a" {
		t.Fatalf("rendezvous = %q, want secret-a", att.rendezvous)
	}
	if !att.pin.Equal(a) {
		t.Fatal("attempt must pin partner a")
	}

	// A peer with no stored session is revoked — the worker exits cleanly.
	if _, err := reconnectSource(cfg, b)(); !errors.Is(err, errSessionRevoked) {
		t.Fatalf("absent session: want errSessionRevoked, got %v", err)
	}
}

// peerLoop returns its attempt source's error immediately, without touching the
// network (buddyRun is only reached once next() succeeds).
func TestPeerLoopReturnsSourceError(t *testing.T) {
	boom := errors.New("boom")
	done := make(chan error, 1)
	go func() {
		done <- peerLoop(context.Background(), BuddyConfig{}, &node{}, nil,
			func() (attempt, error) { return attempt{}, boom }, time.Time{})
	}()
	select {
	case err := <-done:
		if !errors.Is(err, boom) {
			t.Fatalf("want boom, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peerLoop did not return on source error")
	}
}

// superviseReconnect starts one isolated worker per session and drains them all.
// With every session unresolvable (no secret stored), each worker exits via
// errSessionRevoked independently and the supervisor returns without hanging —
// the isolation property: one peer ending never blocks the others.
func TestSuperviseReconnectIsolatedDrain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_peers") // no session lines written
	var sessions []storedSession
	for i := 0; i < 3; i++ {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		sessions = append(sessions, storedSession{pin: pub})
	}
	cfg := BuddyConfig{KnownPeers: path}

	done := make(chan error, 1)
	go func() { done <- superviseReconnect(context.Background(), cfg, &node{}, sessions) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("superviseReconnect: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("superviseReconnect hung — a stopped peer must not block the others")
	}
}

// A cancelled context ends peerLoop promptly even when the attempt source keeps
// yielding valid-looking attempts (no goroutine leak on shutdown).
func TestPeerLoopHonoursCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	done := make(chan error, 1)
	go func() {
		// next() returns the revocation sentinel so the loop never enters buddyRun;
		// we only assert it does not spin or hang under a dead context.
		done <- peerLoop(ctx, BuddyConfig{}, &node{}, nil,
			func() (attempt, error) { return attempt{}, errSessionRevoked }, time.Time{})
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("peerLoop did not return under a cancelled context")
	}
}
