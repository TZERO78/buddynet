package role

// Tests for the A-01/A-02/A-12 fix: the local trust state (manifest, sessions,
// TOFU lines, revocations) is ONE state, written under ONE lock in a fixed
// order, and a revocation bites at every point where a buddy could come back.
//
// What each test is for:
//
//   - CrashConsistency: the revoke and the re-allow are multi-file operations. A
//     crash between any two steps must leave the SAFE side (refused), never
//     "revoked but still connectable".
//   - CrossProcess: the daemon and the CLI are two processes. A saveSession
//     racing a `peers remove` must not resurrect the revoked buddy — real child
//     process, no sleeps deciding the outcome.
//   - PeerLoop: a revoked buddy STOPS its worker, and — the half that makes the
//     first half mean something — a buddy that is not revoked does not.
//   - ReAllow: "in the manifest but revoked" is the normal shape of a re-allow
//     and must lift the revocation, not report "already listed".

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/peer"
)

// revStore seeds a manifest + session store with one buddy and returns the
// paths and the buddy's key.
func revStore(t *testing.T) (dir, manifest, known, keyB64 string) {
	t.Helper()
	pub, b64 := mustKey(t)
	_ = pub
	dir = t.TempDir()
	manifest = filepath.Join(dir, "peers.yaml")
	known = filepath.Join(dir, "known_peers")
	if err := PeersAdd(manifest, known, b64, "boot-token", "", ""); err != nil {
		t.Fatalf("PeersAdd: %v", err)
	}
	if err := saveSession(known, "boot-token", b64, "secret"); err != nil {
		t.Fatalf("saveSession: %v", err)
	}
	return dir, manifest, known, b64
}

// A revoke writes three files in a fixed order (tombstone, session, manifest).
// Each intermediate state must refuse the buddy — otherwise the "crash-safe
// ordering" is a claim, not a property.
func TestRevokeCrashConsistencyLeavesTheSafeSide(t *testing.T) {
	states := []struct {
		name string
		// build leaves the store in the state a crash at that point would.
		build func(t *testing.T, manifest, known, keyB64 string)
	}{
		{
			name: "crash after the tombstone (session and manifest still there)",
			build: func(t *testing.T, manifest, known, keyB64 string) {
				if err := withTrustStateLock(known, manifest, func() error {
					_, err := addRevokedLocked(trustBase(known, manifest), keyB64)
					return err
				}); err != nil {
					t.Fatalf("tombstone: %v", err)
				}
			},
		},
		{
			name: "crash after the session removal (manifest entry still there)",
			build: func(t *testing.T, manifest, known, keyB64 string) {
				if err := withTrustStateLock(known, manifest, func() error {
					if _, err := addRevokedLocked(trustBase(known, manifest), keyB64); err != nil {
						return err
					}
					_, err := removeSessionLocked(known, keyB64)
					return err
				}); err != nil {
					t.Fatalf("tombstone+session: %v", err)
				}
			},
		},
		{
			name: "the complete revoke",
			build: func(t *testing.T, manifest, known, keyB64 string) {
				if err := PeersRemove(manifest, known, keyB64); err != nil {
					t.Fatalf("PeersRemove: %v", err)
				}
			},
		},
	}
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			_, manifest, known, keyB64 := revStore(t)
			pin, err := bcrypto.DecodePubKey(keyB64)
			if err != nil {
				t.Fatal(err)
			}
			st.build(t, manifest, known, keyB64)
			cfg := BuddyConfig{PeersFile: manifest, KnownPeers: known}

			// 1. The attempt source stops the worker rather than retrying forever.
			_, aerr := peerSource(cfg, peerSpec{pin: pin, token: "boot-token"}, newScopeCell(nil))(0)
			if !errors.Is(aerr, errPeerRevoked) {
				t.Fatalf("attempt source returned %v, want errPeerRevoked", aerr)
			}
			// 2. A worker that somehow got through cannot persist a session.
			if serr := saveSession(known, "boot-token", keyB64, "resurrected"); !errors.Is(serr, errPeerRevoked) {
				t.Fatalf("saveSession returned %v, want a refusal (errPeerRevoked)", serr)
			}
			// 3. Nor can it come back through the trust-on-first-use door.
			if lerr := learnPeer(known, "boot-token", keyB64); !errors.Is(lerr, errPeerRevoked) {
				t.Fatalf("learnPeer returned %v, want a refusal (errPeerRevoked)", lerr)
			}
			// 4. And a SIGHUP does not reassemble it.
			specs, serr := assemblePeers(cfg)
			if serr != nil {
				t.Fatalf("assemblePeers: %v", serr)
			}
			for _, s := range specs {
				if s.pin.Equal(pin) {
					t.Fatal("assemblePeers still returns the revoked buddy")
				}
			}
		})
	}
}

// The re-allow runs the opposite way (manifest first, tombstone last), so its
// intermediate state is "configured but still revoked" — which must also refuse.
func TestReAllowIntermediateStateStillRefuses(t *testing.T) {
	_, manifest, known, keyB64 := revStore(t)
	pin, err := bcrypto.DecodePubKey(keyB64)
	if err != nil {
		t.Fatal(err)
	}
	if err := PeersRemove(manifest, known, keyB64); err != nil {
		t.Fatalf("PeersRemove: %v", err)
	}
	// Step 1 of the re-allow only: the manifest entry is back, the tombstone is
	// not yet lifted (a crash right here).
	if err := withTrustStateLock(known, manifest, func() error {
		specs, lerr := loadPeersFile(manifest)
		if lerr != nil {
			return lerr
		}
		return saveManifestLocked(manifest, append(specs, peerSpec{pin: pin, token: "boot-token"}))
	}); err != nil {
		t.Fatalf("partial re-allow: %v", err)
	}
	cfg := BuddyConfig{PeersFile: manifest, KnownPeers: known}
	if _, aerr := peerSource(cfg, peerSpec{pin: pin, token: "boot-token"}, newScopeCell(nil))(0); !errors.Is(aerr, errPeerRevoked) {
		t.Fatalf("configured-but-revoked must still refuse, got %v", aerr)
	}
	// Completing the re-allow makes it work again — otherwise this test would
	// pass for a build that simply never allows anyone.
	if err := PeersAllow(manifest, known, keyB64); err != nil {
		t.Fatalf("PeersAllow: %v", err)
	}
	att, aerr := peerSource(cfg, peerSpec{pin: pin, token: "boot-token"}, newScopeCell(nil))(0)
	if aerr != nil {
		t.Fatalf("after the lift the buddy must pair again, got %v", aerr)
	}
	if !att.firstPairing || att.rendezvous != "boot-token" {
		t.Fatalf("expected a fresh bootstrap attempt, got %+v", att)
	}
}

// TestRevocationHelperProcess is the child body for the cross-process test: the
// real PeersRemove, i.e. what `peers remove` runs. Inert unless REV_HELPER=1.
func TestRevocationHelperProcess(t *testing.T) {
	if os.Getenv("REV_HELPER") != "1" {
		return
	}
	manifest, known, key := os.Getenv("REV_MANIFEST"), os.Getenv("REV_KNOWN"), os.Getenv("REV_KEY")
	barrier := os.Getenv("REV_BARRIER")
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(barrier); err == nil {
			break
		}
	}
	_ = PeersRemove(manifest, known, key)
	os.Exit(0)
}

// The daemon (this process) keeps writing the buddy's session while the CLI
// (a real child process) revokes it. Whatever the interleaving, the outcome must
// be: revoked, and no session line left behind. That is the cross-process half
// of A-01 — the in-process mutex says nothing about a second process.
func TestRevocationBeatsAConcurrentSaveSession(t *testing.T) {
	dir, manifest, known, keyB64 := revStore(t)
	barrier := filepath.Join(dir, "go")

	cmd := exec.Command(os.Args[0], "-test.run=^TestRevocationHelperProcess$")
	cmd.Env = append(os.Environ(), "REV_HELPER=1",
		"REV_MANIFEST="+manifest, "REV_KNOWN="+known, "REV_KEY="+keyB64, "REV_BARRIER="+barrier)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start revoke helper: %v", err)
	}
	if err := os.WriteFile(barrier, []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Hammer the store the way a re-pairing worker would, until the child is done.
	done := make(chan struct{})
	go func() {
		defer close(done)
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			_ = saveSession(known, "boot-token", keyB64, "re-paired")
		}
	}()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("revoke helper: %v", err)
	}
	<-done

	revoked, err := isRevoked(trustBase(known, manifest), keyB64)
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("the revocation did not survive the concurrent writer")
	}
	if _, ok, _ := loadSessionFor(known, mustDecode(t, keyB64)); ok {
		t.Fatal("a session line for the revoked buddy survived — it was resurrected across processes")
	}
	specs, err := assemblePeers(BuddyConfig{PeersFile: manifest, KnownPeers: known})
	if err != nil {
		t.Fatalf("assemblePeers: %v", err)
	}
	if len(specs) != 0 {
		t.Fatalf("revoked buddy still assembled: %+v", specs)
	}
}

func mustDecode(t *testing.T, keyB64 string) ed25519.PublicKey {
	t.Helper()
	pin, err := bcrypto.DecodePubKey(keyB64)
	if err != nil {
		t.Fatal(err)
	}
	return pin
}

// errPeerRevoked must END the worker (peerLoop returns it, the supervisor logs
// peer-stopped) — and the positive control next to it: a peer that is NOT
// revoked keeps looping instead of stopping. Without the second half, the first
// only proves that something, somewhere, returns.
func TestPeerLoopStopsOnlyForARevokedPeer(t *testing.T) {
	dir := t.TempDir()
	reg, err := peer.Open(filepath.Join(dir, "peers.json"))
	if err != nil {
		t.Fatalf("peer cache: %v", err)
	}
	pub, _ := mustKey(t)
	nd := &node{id: "test", pub: "", priv: nil, trust: &trustPolicy{insecure: true}, reg: reg}
	cfg := BuddyConfig{KnownPeers: filepath.Join(dir, "known_peers")}

	// Revoked: the loop returns the error, promptly, without a reconnect wait.
	stopped := make(chan error, 1)
	go func() {
		stopped <- peerLoop(context.Background(), cfg, nd, nil,
			func(int) (attempt, error) { return attempt{}, errPeerRevoked }, time.Time{}, 0)
	}()
	select {
	case err := <-stopped:
		if !errors.Is(err, errPeerRevoked) {
			t.Fatalf("peerLoop returned %v, want errPeerRevoked", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peerLoop did not stop for a revoked peer")
	}

	// Not revoked: the same loop keeps going. It cannot connect (no server), so it
	// fails, waits, and only returns when the context is cancelled — nil, not an
	// error. That is "still running" as far as the supervisor is concerned.
	ctx, cancel := context.WithCancel(context.Background())
	kept := make(chan error, 1)
	go func() {
		kept <- peerLoop(ctx, cfg, nd, nil,
			func(int) (attempt, error) { return attempt{rendezvous: "tok", pin: pub}, nil }, time.Time{}, 0)
	}()
	select {
	case err := <-kept:
		cancel()
		t.Fatalf("peerLoop stopped for a peer that is not revoked (err=%v)", err)
	case <-time.After(500 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-kept:
		if err != nil {
			t.Fatalf("cancelled peerLoop returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("peerLoop did not return after the context was cancelled")
	}
}

// `peers add` on a revoked buddy is the re-allow, not "already listed". Both
// shapes: the ordinary one (revoke removed the manifest entry) and the crash
// shape (the entry is still there).
func TestPeersAddReAllowsARevokedBuddy(t *testing.T) {
	for _, keepEntry := range []bool{false, true} {
		name := "entry removed by the revoke"
		if keepEntry {
			name = "entry left behind by a crashed revoke"
		}
		t.Run(name, func(t *testing.T) {
			_, manifest, known, keyB64 := revStore(t)
			pin := mustDecode(t, keyB64)
			if keepEntry {
				if err := withTrustStateLock(known, manifest, func() error {
					_, aerr := addRevokedLocked(trustBase(known, manifest), keyB64)
					return aerr
				}); err != nil {
					t.Fatalf("tombstone: %v", err)
				}
			} else if err := PeersRemove(manifest, known, keyB64); err != nil {
				t.Fatalf("PeersRemove: %v", err)
			}

			if err := PeersAdd(manifest, known, keyB64, "boot-token", "", ""); err != nil {
				t.Fatalf("PeersAdd (re-allow): %v", err)
			}
			revoked, err := isRevoked(trustBase(known, manifest), keyB64)
			if err != nil {
				t.Fatal(err)
			}
			if revoked {
				t.Fatal("peers add left the buddy revoked — it is silently still locked out")
			}
			specs, err := assemblePeers(BuddyConfig{PeersFile: manifest, KnownPeers: known})
			if err != nil {
				t.Fatalf("assemblePeers: %v", err)
			}
			found := false
			for _, s := range specs {
				if s.pin.Equal(pin) {
					found = true
				}
			}
			if !found {
				t.Fatal("the re-allowed buddy is not back in the worker set")
			}
			// A duplicate entry would mean the crash shape was added twice.
			listed, err := loadPeersFile(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if len(listed) != 1 {
				t.Fatalf("manifest should hold exactly one entry, got %d", len(listed))
			}
		})
	}
}

// The plugin's node has no manifest, so lifting a revocation must work with the
// session store alone.
func TestPeersAllowWithoutAManifest(t *testing.T) {
	dir := t.TempDir()
	known := filepath.Join(dir, "known_peers")
	_, keyB64 := mustKey(t)
	if err := saveSession(known, "tok", keyB64, "secret"); err != nil {
		t.Fatalf("saveSession: %v", err)
	}
	if err := PeersRemove("", known, keyB64); err != nil {
		t.Fatalf("PeersRemove: %v", err)
	}
	if revoked, _ := isRevoked(known, keyB64); !revoked {
		t.Fatal("revoke without a manifest did not record the tombstone")
	}
	if err := PeersAllow("", known, keyB64); err != nil {
		t.Fatalf("PeersAllow: %v", err)
	}
	if revoked, _ := isRevoked(known, keyB64); revoked {
		t.Fatal("PeersAllow did not lift the revocation")
	}
	// And now a session may be stored again (the buddy re-pairs).
	if err := saveSession(known, "tok", keyB64, "secret2"); err != nil {
		t.Fatalf("after the lift, pairing must work again: %v", err)
	}
}

// The revocation file is data an operator may edit. It must survive a rewrite
// without restamping older entries, and ignore junk rather than failing closed
// on the whole list.
func TestRevocationFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	known := filepath.Join(dir, "known_peers")
	_, a := mustKey(t)
	_, b := mustKey(t)

	if err := withTrustStateLock(known, "", func() error {
		if _, err := addRevokedLocked(known, a); err != nil {
			return err
		}
		return os.WriteFile(revokedPath(known),
			[]byte("# comment\n"+a+"  # revoked 1999-01-01\nnot-a-key here\n"), 0o600)
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := withTrustStateLock(known, "", func() error {
		_, err := addRevokedLocked(known, b)
		return err
	}); err != nil {
		t.Fatalf("add second: %v", err)
	}
	data, err := os.ReadFile(revokedPath(known))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "1999-01-01") {
		t.Fatalf("rewriting the list restamped an older entry:\n%s", data)
	}
	for _, k := range []string{a, b} {
		if revoked, _ := isRevoked(known, k); !revoked {
			t.Fatalf("%s not revoked after the round trip:\n%s", keyTag(k), data)
		}
	}
	if fi, serr := os.Stat(revokedPath(known)); serr != nil {
		t.Fatal(serr)
	} else if fi.Mode().Perm() != 0o600 {
		t.Fatalf("revocation file mode %v, want 0600", fi.Mode().Perm())
	}
}
