package role

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tzero78/buddynet/internal/atomicfile"
	bcrypto "github.com/tzero78/buddynet/internal/crypto"
)

// This node's local trust state lives in FOUR places:
//
//	known_peers            session lines (one per paired buddy)
//	known_peers            legacy trust-on-first-use lines
//	known_peers.revoked    revoked buddy keys (this file)
//	--peers-file manifest  configured buddies + bootstrap tokens
//
// They are one state, not four. A revocation that lands in three of them and not
// the fourth is finding A-01: `peers remove` dropped the manifest entry and the
// session, the still-running worker re-paired on its stale bootstrap token, and
// the SIGHUP that was supposed to APPLY the revocation restarted the buddy from
// the session it had just written back.
//
// So every writer goes through withTrustStateLock, which takes ONE designated
// lock and then calls helpers that do not lock again. That is not a style
// preference: flock is per open file description, so a nested acquireLock on the
// same path inside an already-held lock deadlocks the process.

// errPeerRevoked stops a peer worker whose buddy has been revoked. It is
// distinct from errSessionRevoked ("the session line vanished") so the
// SUPERVISOR: action=peer-stopped line names the actual reason, and so the
// crash-safe intermediate state of a revocation — tombstone written, manifest
// entry not yet removed — stops the worker instead of being retried forever.
var errPeerRevoked = errors.New("buddy revoked (listed in the revocation file) — not connecting")

// errNoTrustPath is returned when neither --known-peers nor --peers-file gives
// the lock somewhere to live. Fail closed: an unsynchronised write to the trust
// state is exactly what A-01/A-02/A-12 were.
var errNoTrustPath = errors.New("no trust-state path: set --known-peers (or --peers-file)")

// trustBase is the path the whole trust state hangs off: the lock and the
// revocation file are both derived from it. Empty when the node has neither a
// session store nor a manifest, which the write paths reject (errNoTrustPath).
func trustBase(knownPeers, peersFile string) string {
	if knownPeers != "" {
		return knownPeers
	}
	return peersFile
}

// trustLockPath picks the file the trust-state lock is derived from. Preferably
// known_peers: it is the only trust file with a default, its lock already exists
// (saveSession/removeSession take it today), and deriving from it keeps ONE lock
// for all four states. Falls back to the manifest for the unusual node that has
// a --peers-file but no --known-peers.
//
// The price of one lock rather than two is that an operator who puts manifest
// and session store in different directories gets a lock file that does not sit
// next to the manifest. That is surprising but harmless; two locks would have to
// be taken in a fixed order at every future call site, and a deadlock in a
// revocation path is worse than a lock file in an unexpected directory.
// buddyStartupTrustHint warns about exactly that layout at startup.
func trustLockPath(knownPeers, peersFile string) (string, error) {
	if base := trustBase(knownPeers, peersFile); base != "" {
		return base, nil
	}
	return "", errNoTrustPath
}

// withTrustStateLock runs fn holding the one lock that covers the whole local
// trust state: the in-process mutex (several MultiPeer workers write the session
// store concurrently) AND the advisory file lock (the CLI is a second writing
// process). fn must call only the …Locked helpers — anything that locks again
// deadlocks.
func withTrustStateLock(knownPeers, peersFile string, fn func() error) error {
	lockPath, err := trustLockPath(knownPeers, peersFile)
	if err != nil {
		return err
	}
	sessionFileMu.Lock()
	defer sessionFileMu.Unlock()
	// The lock file lives next to its subject, so the directory must exist before
	// the lock can be taken (every write below needs it anyway).
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return err
	}
	unlock, lerr := acquireLock(lockPath)
	if lerr != nil {
		return fmt.Errorf("lock trust state: %w", lerr)
	}
	defer unlock()
	return fn()
}

// revokedPath is the revocation file, next to the trust-state base path (the
// same file the lock is derived from, so the whole trust state stays together).
func revokedPath(base string) string {
	if base == "" {
		return ""
	}
	return base + ".revoked"
}

// The revocation file is a permanent list of keys, one per line, with a
// human-readable date as a trailing comment:
//
//	<pubkey_b64>  # revoked 2026-08-20
//
// THE PRESENCE OF THE KEY IS THE REVOCATION. There is no timestamp comparison,
// no generation, and deliberately no garbage collection: in distributed stores a
// tombstone expires after gc_grace and that is precisely when the zombie comes
// back. An entry disappears only when someone deliberately allows the buddy
// again (`peers allow`). At MaxBuddies = 48 the file is tiny either way.
//
// The date is a comment for the operator and carries no decision: a wall clock
// cannot order two states of the same key when it was allowed again in between.
// If an ordering is ever needed — two processes revoking and allowing
// independently — it has to be a real monotonic generation per key, not a clock.
// Today there is one writing daemon plus the CLI, and both stand under the same
// lock.

// revokedEntry is one line of the revocation file: the key, plus the trailing
// comment kept verbatim so a rewrite does not restamp older entries with today.
type revokedEntry struct {
	key  string
	note string
}

// loadRevokedLocked reads the revocation file. Caller holds the trust-state lock.
// A missing file means "nothing revoked". Unparsable lines are skipped rather
// than failing the read: the file must never be able to lock an operator out of
// their own revocation list, and a line that is not a key revokes nothing.
func loadRevokedLocked(base string) ([]revokedEntry, error) {
	path := revokedPath(base)
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path) // #nosec G304 -- the operator's own --known-peers path (same trust as every path flag)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var entries []revokedEntry
	seen := map[string]struct{}{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		field := strings.Fields(line)[0]
		pin, derr := bcrypto.DecodePubKey(field)
		if derr != nil {
			continue
		}
		keyB64 := bcrypto.PubKeyB64(pin)
		if _, dup := seen[keyB64]; dup {
			continue
		}
		seen[keyB64] = struct{}{}
		note := ""
		if i := strings.Index(line, "#"); i >= 0 {
			note = strings.TrimSpace(line[i+1:])
		}
		entries = append(entries, revokedEntry{key: keyB64, note: note})
	}
	return entries, sc.Err()
}

// writeRevokedLocked persists the list atomically (0600, 0700 dir) — the same
// treatment the session store, the allowlist and the peer cache already get.
func writeRevokedLocked(base string, entries []revokedEntry) error {
	path := revokedPath(base)
	if path == "" {
		return errNoTrustPath
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# BuddyNet revoked buddy keys — the presence of a key IS the revocation.\n")
	b.WriteString("# Lift one with:  buddynet peers allow <key>\n")
	for _, e := range entries {
		note := e.note
		if note == "" {
			note = "revoked " + time.Now().UTC().Format("2006-01-02")
		}
		fmt.Fprintf(&b, "%s  # %s\n", e.key, note)
	}
	return atomicfile.Write(path, []byte(b.String()), 0o600)
}

// addRevokedLocked appends a key to the revocation list. Caller holds the lock.
// added is false when the key was already listed (revoking twice is not an error).
func addRevokedLocked(base, keyB64 string) (added bool, err error) {
	entries, err := loadRevokedLocked(base)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.key == keyB64 {
			return false, nil // already revoked; revoking twice is not an error
		}
	}
	entry := revokedEntry{key: keyB64, note: "revoked " + time.Now().UTC().Format("2006-01-02")}
	return true, writeRevokedLocked(base, append(entries, entry))
}

// removeRevokedLocked lifts a revocation. Caller holds the lock. removed is
// false when the key was not listed.
func removeRevokedLocked(base, keyB64 string) (removed bool, err error) {
	entries, err := loadRevokedLocked(base)
	if err != nil {
		return false, err
	}
	var kept []revokedEntry
	for _, e := range entries {
		if e.key == keyB64 {
			removed = true
			continue
		}
		kept = append(kept, e)
	}
	if !removed {
		return false, nil
	}
	return true, writeRevokedLocked(base, kept)
}

// revokedSet reads the revocation list WITHOUT taking the lock, for the hot
// enforcement paths (every reconnect round, every assemblePeers). Reads are safe
// unlocked because every write is a rename of a complete file: a reader sees the
// old list or the new one, never a partial one. The write paths that must not
// race — saveSession above all — check under the lock instead.
func revokedSet(base string) (map[string]struct{}, error) {
	entries, err := loadRevokedLocked(base)
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		set[e.key] = struct{}{}
	}
	return set, nil
}

// isRevoked reports whether one key is revoked. Unlocked read — see revokedSet.
func isRevoked(base, keyB64 string) (bool, error) {
	set, err := revokedSet(base)
	if err != nil {
		return false, err
	}
	_, ok := set[keyB64]
	return ok, nil
}

// isRevokedLocked is the same check for callers that already hold the lock
// (saveSession, the transactions in peerscmd.go).
func isRevokedLocked(base, keyB64 string) (bool, error) {
	entries, err := loadRevokedLocked(base)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.key == keyB64 {
			return true, nil
		}
	}
	return false, nil
}
