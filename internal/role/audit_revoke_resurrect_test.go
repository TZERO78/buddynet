package role

// AUDIT 2026-08-20, finding A-01: a `peers remove` (revocation) can be UNDONE by
// the buddy process that is still running, and the undo SURVIVES the SIGHUP the
// CLI tells the operator to send.
//
// The mechanism, all in production code:
//
//   - PeersRemove drops the manifest entry AND the stored session line. Both
//     files are then correct — TestPeersRemoveRevokesBoth already proves that.
//   - But the RUNNING supervisor is not notified. Its worker for that buddy holds
//     a peerSpec captured at start, INCLUDING spec.token, in memory.
//   - peerSource reloads the session from disk each round (it is gone now) but
//     reads spec.token from that in-memory copy. With no session and a non-empty
//     token it returns bootstrap() — firstPairing=true — instead of
//     errSessionRevoked.
//   - A successful bootstrap re-pair calls saveSession, writing the revoked
//     partner's session line back.
//   - assemblePeers = manifest UNION sessions, so the next SIGHUP sees the
//     resurrected line and restarts the buddy as a "session-only" peer. The
//     revocation is now gone from both files' point of view and survives restart.
//
// The positive control at the end shows the same sequence is correctly refused
// once the worker is restarted from a freshly assembled spec (no token) — which
// isolates the defect to the stale in-memory token, not to the test setup.

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
)

// TestAuditRevokedPeerResurrectsViaStaleToken walks the full chain.
func TestAuditRevokedPeerResurrectsViaStaleToken(t *testing.T) {
	victimPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	keepPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	victim := bcrypto.PubKeyB64(victimPub)
	keep := bcrypto.PubKeyB64(keepPub)

	dir := t.TempDir()
	manifest := filepath.Join(dir, "peers.yaml")
	known := filepath.Join(dir, "known_peers")

	// Two buddies in the manifest, each with a bootstrap token (the ordinary
	// `peers add <key> <token>` shape).
	for _, k := range []string{victim, keep} {
		if err := PeersAdd(manifest, k, "boot-"+k[:4], "", ""); err != nil {
			t.Fatalf("PeersAdd %s: %v", k[:8], err)
		}
	}
	// Both are paired, so both have a stored session secret.
	if err := saveSession(known, "boot-"+victim[:4], victim, "secret-victim"); err != nil {
		t.Fatalf("seed victim session: %v", err)
	}
	if err := saveSession(known, "boot-"+keep[:4], keep, "secret-keep"); err != nil {
		t.Fatalf("seed keep session: %v", err)
	}

	// This is the spec the RUNNING supervisor's worker holds: assemblePeers built
	// it at start-up, before the revoke, so it carries the bootstrap token.
	specsAtStart, err := assemblePeers(BuddyConfig{PeersFile: manifest, KnownPeers: known})
	if err != nil {
		t.Fatalf("assemblePeers (start): %v", err)
	}
	var runningSpec peerSpec
	for _, s := range specsAtStart {
		if s.pin.Equal(victimPub) {
			runningSpec = s
		}
	}
	if runningSpec.pin == nil {
		t.Fatal("setup: victim not in the assembled spec set")
	}
	if runningSpec.token == "" {
		t.Fatal("setup: victim spec carries no bootstrap token — wrong precondition")
	}

	// --- the operator revokes -------------------------------------------------
	if err := PeersRemove(manifest, known, victim); err != nil {
		t.Fatalf("PeersRemove: %v", err)
	}
	// Sanity: both files are correct right now. This is exactly what the existing
	// TestPeersRemoveRevokesBoth asserts, and it holds.
	if _, ok, _ := loadSessionFor(known, victimPub); ok {
		t.Fatal("precondition: PeersRemove left the session behind")
	}
	if specs, _ := loadPeersFile(manifest); len(specs) != 1 || !specs[0].pin.Equal(keepPub) {
		t.Fatalf("precondition: manifest after remove = %+v, want only the kept buddy", specs)
	}

	// --- the still-running worker takes its next reconnect round --------------
	// It uses the LIVE production attempt source with its STALE in-memory spec.
	next := peerSource(BuddyConfig{KnownPeers: known}, runningSpec, newScopeCell(nil))
	att, aerr := next(0)
	if errors.Is(aerr, errSessionRevoked) {
		t.Fatal("FIXED: the running worker stopped after the revoke (errSessionRevoked)")
	}
	if aerr != nil {
		t.Fatalf("peerSource returned an unexpected error: %v", aerr)
	}
	if !att.firstPairing {
		t.Fatalf("expected a first-pairing bootstrap attempt, got %+v", att)
	}
	if att.rendezvous != runningSpec.token {
		t.Fatalf("attempt rendezvous = %q, want the stale bootstrap token %q", att.rendezvous, runningSpec.token)
	}
	t.Logf("A-01 step 1: after the revoke, the running worker still returns a "+
		"bootstrap attempt for the revoked buddy (firstPairing=%v, rendezvous=stale token)", att.firstPairing)

	// --- that attempt succeeds (the partner is online and still holds the token)
	// connect.go does exactly this on a firstPairing success.
	if err := saveSession(known, att.inviteToken, victim, "secret-victim-repaired"); err != nil {
		t.Fatalf("saveSession after re-pair: %v", err)
	}

	// --- the operator now sends the SIGHUP the CLI told them to send ----------
	after, err := assemblePeers(BuddyConfig{PeersFile: manifest, KnownPeers: known})
	if err != nil {
		t.Fatalf("assemblePeers (after SIGHUP): %v", err)
	}
	resurrected := false
	for _, s := range after {
		if s.pin.Equal(victimPub) {
			resurrected = true
			if s.token != "" {
				t.Fatalf("unexpected: resurrected spec carries a token %q", s.token)
			}
		}
	}
	if resurrected {
		t.Fatalf(`A-01 CONFIRMED — revocation undone and now persistent.

The revoked buddy %s is back in the supervisor's desired set as a SESSION-ONLY
peer after: peers remove -> (running worker re-pairs on its stale in-memory
bootstrap token) -> saveSession -> SIGHUP.

Both files were correct immediately after PeersRemove; the running process wrote
the session line back. assemblePeers unions manifest with stored sessions, so the
SIGHUP that is supposed to APPLY the revocation instead restarts the buddy, and
the resurrected session survives a full restart too.`, keyTag(victim))
	}
	t.Log("no resurrection — A-01 appears fixed")
}

// TestAuditRevokedPeerControlRestartedWorkerStops is the POSITIVE CONTROL. Same
// files, same helpers, same revoke — but the worker spec is taken from
// assemblePeers AFTER the revoke, i.e. the state a restarted process would have.
// It must stop with errSessionRevoked. If this control also resurrected, the test
// above would be proving something about the harness rather than about the stale
// in-memory token.
func TestAuditRevokedPeerControlRestartedWorkerStops(t *testing.T) {
	victimPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	victim := bcrypto.PubKeyB64(victimPub)

	dir := t.TempDir()
	manifest := filepath.Join(dir, "peers.yaml")
	known := filepath.Join(dir, "known_peers")

	if err := PeersAdd(manifest, victim, "boot-tok", "", ""); err != nil {
		t.Fatalf("PeersAdd: %v", err)
	}
	if err := saveSession(known, "boot-tok", victim, "secret-victim"); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if err := PeersRemove(manifest, known, victim); err != nil {
		t.Fatalf("PeersRemove: %v", err)
	}

	// A restarted process assembles its specs from disk: the victim is in neither
	// the manifest nor the session store, so it gets no worker at all.
	specs, err := assemblePeers(BuddyConfig{PeersFile: manifest, KnownPeers: known})
	if err != nil {
		t.Fatalf("assemblePeers: %v", err)
	}
	for _, s := range specs {
		if s.pin.Equal(victimPub) {
			t.Fatal("control: a restarted process still assembles a worker for the revoked buddy")
		}
	}

	// And even if a worker somehow existed with a TOKENLESS spec (the shape
	// assemblePeers produces for a session-only peer), it stops cleanly.
	_, aerr := peerSource(BuddyConfig{KnownPeers: known}, peerSpec{pin: victimPub}, newScopeCell(nil))(0)
	if !errors.Is(aerr, errSessionRevoked) {
		t.Fatalf("control: tokenless spec after revoke returned %v, want errSessionRevoked", aerr)
	}
	t.Log("positive control holds: a restarted worker refuses the revoked buddy; " +
		"the defect is specifically the STALE IN-MEMORY spec.token of a still-running worker")
}
