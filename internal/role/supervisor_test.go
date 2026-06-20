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
	att, err := peerSource(cfg, peerSpec{pin: a, token: "boot-a"})(0)
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
	att, err = peerSource(cfg, peerSpec{pin: b, token: "boot-b"})(0)
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
	if _, err := peerSource(cfg, peerSpec{pin: b})(0); !errors.Is(err, errSessionRevoked) {
		t.Fatalf("no session/token: want errSessionRevoked, got %v", err)
	}
}

// A stored session that keeps failing to pair is presumed stale (the partner lost
// ITS copy after a one-sided restore or a remove+re-add): past the failure
// threshold the worker probes the manifest bootstrap token to recover the
// rendezvous, while STILL pinning the partner key — so the fallback cannot be
// abused to impersonate the partner. It must never fall back without a token (no
// common rendezvous), nor under --lab (the pin is what keeps it safe).
func TestPeerSourceStaleSessionFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_peers")
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := saveSession(path, "tok-a", bcrypto.PubKeyB64(a), "secret-a"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cfg := BuddyConfig{KnownPeers: path}
	src := peerSource(cfg, peerSpec{pin: a, token: "boot-a"})

	// Below the threshold: always the real session, never the token.
	for _, f := range []int{0, 1, 2} {
		if att, _ := src(f); att.rendezvous != "secret-a" || att.firstPairing {
			t.Fatalf("failures=%d: want session rendezvous, got %+v", f, att)
		}
	}
	// Past the threshold it alternates: an odd streak probes the bootstrap token
	// (pinned, first-pairing) so it can meet a partner that fell back to it...
	att, _ := src(3)
	if att.rendezvous != "boot-a" || att.inviteToken != "boot-a" || !att.firstPairing {
		t.Fatalf("stale session, odd streak: want bootstrap fallback, got %+v", att)
	}
	if !att.pin.Equal(a) {
		t.Fatal("fallback MUST still pin the partner key (no impersonation)")
	}
	// ...while an even streak keeps trying the real session (so a transient miss
	// that still has a live session on the other end recovers too).
	if att, _ := src(4); att.rendezvous != "secret-a" {
		t.Fatalf("stale session, even streak: want session retry, got %+v", att)
	}

	// No bootstrap token in the manifest → no common rendezvous to fall back to;
	// the session is the only option no matter how long it fails.
	noTok := peerSource(cfg, peerSpec{pin: a})
	if att, _ := noTok(9); att.rendezvous != "secret-a" {
		t.Fatalf("no token: must never fall back, got %+v", att)
	}

	// --lab → the pin no longer protects us, so the fallback is disabled.
	insecure := peerSource(BuddyConfig{KnownPeers: path, Insecure: true}, peerSpec{pin: a, token: "boot-a"})
	if att, _ := insecure(9); att.rendezvous != "secret-a" {
		t.Fatalf("insecure: must not fall back to a public token, got %+v", att)
	}
}

// peerLoop returns its attempt source's error immediately, without touching the
// network (buddyRun is only reached once next() succeeds).
func TestPeerLoopReturnsSourceError(t *testing.T) {
	boom := errors.New("boom")
	done := make(chan error, 1)
	go func() {
		done <- peerLoop(context.Background(), BuddyConfig{}, &node{}, nil,
			func(int) (attempt, error) { return attempt{}, boom }, time.Time{})
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

// supervise is a daemon loop: it starts one isolated worker per spec and keeps
// running (to serve reloads) even after workers exit, returning only on ctx
// cancel. With every spec unresolvable (no session, no token), each worker exits
// via errSessionRevoked independently; cancelling then drains them all without
// hanging — the isolation property: one peer ending never blocks the others.
func TestSuperviseIsolatedDrain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_peers") // no session lines written
	var specs []peerSpec
	for i := 0; i < 3; i++ {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		specs = append(specs, peerSpec{pin: pub})
	}
	cfg := BuddyConfig{KnownPeers: path}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervise(ctx, cfg, &node{}, specs) }()

	// The workers self-exit immediately; the supervisor must NOT return for that.
	select {
	case err := <-done:
		t.Fatalf("supervise returned before cancel (it is a daemon loop): %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("supervise: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("supervise hung on cancel — a stopped peer must not block the drain")
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
			func(int) (attempt, error) { return attempt{}, errSessionRevoked }, time.Time{})
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("peerLoop did not return under a cancelled context")
	}
}
