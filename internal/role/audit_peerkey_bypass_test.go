package role

// AUDIT 2026-08-20, finding A-03: on the single-peer path, `--peer-key` stops
// being consulted as soon as a session is stored. The effective pin becomes
// whatever key sits in known_peers, not the key the operator passed.
//
// The path, all production code at commit fa046a6:
//
//   buddy.go:236-239   --peer-key is parsed into trustPolicy.pinned.
//   buddy.go:391-396   nextAttempt: with a stored session it returns
//                      attempt{rendezvous: secret, pin: <key FROM THE STORE>}.
//                      cfg.PeerKey is not read here at all.
//   connect.go:84-89   if att.pin != nil { compare against att.pin }
//                      else if trust.decide(...)   <-- the ONLY place
//                                                      trustPolicy.pinned is
//                                                      enforced.
//   connect.go:123-130 the same if/else again on the cached-peer path.
//
// So once a session line exists, att.pin is never nil and trust.decide — and with
// it the operator's --peer-key — is never reached.
//
// Why this matters rather than being merely redundant: SECURITY.md §8.2 lists
// changing the pin as one of the four ways to revoke access —
//
//     "**`--peer-key` pin.** Change or remove the pin on the surviving side; the
//      revoked key is then refused on the next connect."
//
// That does not happen. The surviving side keeps connecting to the OLD key,
// because the stored session pin wins and the new --peer-key is ignored. The
// documented revocation silently does nothing until known_peers is edited or
// `peers remove` is run.
//
// The test uses only production functions: nextAttempt to show which key becomes
// the pin, and trustPolicy.decide to show that the operator's key would in fact
// have refused it.

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
)

func TestAuditPeerKeyIgnoredOnceASessionIsStored(t *testing.T) {
	// oldPub: the partner key recorded in the session store at first pairing.
	oldPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	// newPub: the key the operator now pins with --peer-key (a rotation, or a
	// deliberate re-pin to lock the old key out).
	newPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	oldB64, newB64 := bcrypto.PubKeyB64(oldPub), bcrypto.PubKeyB64(newPub)

	dir := t.TempDir()
	known := filepath.Join(dir, "known_peers")
	if err := saveSession(known, "invite-tok", oldB64, "stored-secret"); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	cfg := BuddyConfig{
		KnownPeers: known,
		PeerKey:    newB64, // the operator's --peer-key
		Token:      "invite-tok",
	}

	// 1. The real attempt source. Both pins are local and they contradict each
	//    other, so the FIXED behaviour is to refuse here — before buddyRun sends
	//    a REGISTER that would carry this node's token and endpoints to the
	//    server for a pairing that must not happen.
	att, err := nextAttempt(cfg)
	if err != nil {
		for _, want := range []string{oldB64, newB64, "peers remove"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("A-03 refusal does not mention %q — the operator cannot act on it:\n%v", want, err)
			}
		}
		t.Logf("A-03 fixed: nextAttempt refuses before registering:\n%v", err)
		return
	}
	if att.pin == nil {
		t.Skip("nextAttempt returned no pin — A-03 precondition gone")
	}
	if att.pin.Equal(newPub) {
		t.Log("nextAttempt honours --peer-key — A-03 appears fixed")
		return
	}
	if !att.pin.Equal(oldPub) {
		t.Fatalf("unexpected pin: neither the stored key nor --peer-key")
	}

	// 2. The operator's --peer-key, evaluated by the code that actually enforces
	//    it. It REFUSES the stored key — which is the whole point of re-pinning.
	pol := &trustPolicy{storePath: known}
	pol.pinned, err = bcrypto.DecodePubKey(cfg.PeerKey)
	if err != nil {
		t.Fatalf("decode --peer-key: %v", err)
	}
	_, derr := pol.decide("invite-tok", oldPub)
	if derr == nil {
		t.Fatal("setup broken: trustPolicy.decide accepted the old key under the new pin")
	}
	if !strings.Contains(derr.Error(), "MISMATCH") {
		t.Fatalf("setup broken: unexpected decide error %v", derr)
	}

	t.Fatalf(`A-03 CONFIRMED — --peer-key is not consulted on a reconnect.

  stored session pin : %s
  operator --peer-key: %s
  nextAttempt().pin  : %s   <- the STORED key, not the operator's

trustPolicy.decide (the only enforcer of --peer-key) refuses the stored key:
    %v

But connect.go:84-89 takes the "att.pin != nil" branch and never calls decide, so
the refusal never happens. Same if/else again at connect.go:123-130 for the
cached-peer path.

SECURITY.md §8.2 offers changing --peer-key as a revocation mechanism ("the
revoked key is then refused on the next connect"). With a session stored, it is
not: the old key keeps connecting.`,
		keyTag(oldB64), keyTag(newB64), keyTag(bcrypto.PubKeyB64(att.pin)), derr)
}

// TestAuditPeerKeyControlNoSessionStillEnforced is the POSITIVE CONTROL: with NO
// stored session, nextAttempt returns pin=nil, so connect.go falls through to
// trust.decide and --peer-key IS enforced. This isolates the defect to the
// stored-session branch rather than to --peer-key parsing or to the test setup.
func TestAuditPeerKeyControlNoSessionStillEnforced(t *testing.T) {
	newPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	dir := t.TempDir()
	known := filepath.Join(dir, "known_peers") // deliberately never written

	cfg := BuddyConfig{
		KnownPeers: known,
		PeerKey:    bcrypto.PubKeyB64(newPub),
		Token:      "invite-tok",
	}
	att, err := nextAttempt(cfg)
	if err != nil {
		t.Fatalf("nextAttempt: %v", err)
	}
	if att.pin != nil {
		t.Fatalf("control: expected pin=nil with no stored session, got %s", keyTag(bcrypto.PubKeyB64(att.pin)))
	}

	// pin==nil, so connect.go calls decide, and --peer-key does its job.
	pol := &trustPolicy{storePath: known}
	pol.pinned, err = bcrypto.DecodePubKey(cfg.PeerKey)
	if err != nil {
		t.Fatalf("decode --peer-key: %v", err)
	}
	if _, derr := pol.decide("invite-tok", otherPub); derr == nil {
		t.Fatal("control: --peer-key failed to refuse a foreign key")
	}
	if needSAS, derr := pol.decide("invite-tok", newPub); derr != nil || needSAS {
		t.Fatalf("control: --peer-key refused its own key (needSAS=%v, err=%v)", needSAS, derr)
	}
	t.Log("positive control holds: with no stored session, pin=nil and --peer-key is enforced; " +
		"the defect is specifically that a stored session pin displaces it")
}
