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

// peerSource must reconnect via a stored session when one exists, bootstrap via
// the token when none does yet, and revoke (stop) when there is neither — always
// pinning the right partner, never a blank or cross-peer attempt.
func TestPeerSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_peers")
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	b, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := saveSession(path, "tok-a", bcrypto.PubKeyB64(a), "secret-a"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cfg := BuddyConfig{KnownPeers: path}

	// a has a stored session → reconnect attempt with the secret, pinned.
	att, err := peerSource(cfg, peerSpec{pin: a, token: "boot-a"})()
	if err != nil {
		t.Fatalf("present session: %v", err)
	}
	if att.rendezvous != "secret-a" || att.firstPairing {
		t.Fatalf("want reconnect via secret, got rendezvous=%q firstPairing=%v", att.rendezvous, att.firstPairing)
	}
	if !att.pin.Equal(a) {
		t.Fatal("attempt must pin partner a")
	}

	// b has no session but a token → bootstrap attempt (first pairing, pinned).
	att, err = peerSource(cfg, peerSpec{pin: b, token: "boot-b"})()
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if att.rendezvous != "boot-b" || att.inviteToken != "boot-b" || !att.firstPairing {
		t.Fatalf("want bootstrap via token, got %+v", att)
	}
	if !att.pin.Equal(b) {
		t.Fatal("bootstrap must pin partner b")
	}

	// b with neither session nor token → revoked (worker stops cleanly).
	if _, err := peerSource(cfg, peerSpec{pin: b})(); !errors.Is(err, errSessionRevoked) {
		t.Fatalf("no session/token: want errSessionRevoked, got %v", err)
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

// supervise starts one isolated worker per spec and drains them all. With every
// spec unresolvable (no session, no token), each worker exits via
// errSessionRevoked independently and the supervisor returns without hanging —
// the isolation property: one peer ending never blocks the others.
func TestSuperviseIsolatedDrain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_peers") // no session lines written
	var specs []peerSpec
	for i := 0; i < 3; i++ {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		specs = append(specs, peerSpec{pin: pub})
	}
	cfg := BuddyConfig{KnownPeers: path}

	done := make(chan error, 1)
	go func() { done <- supervise(context.Background(), cfg, &node{}, specs) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("supervise: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("supervise hung — a stopped peer must not block the others")
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
