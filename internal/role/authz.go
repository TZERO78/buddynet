package role

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
)

// pendingTTL bounds how long an un-approved enrollment lingers in the pending DB.
const pendingTTL = 30 * time.Minute

// These caps bound the two attacker-growable maps in approval mode. An outsider
// can mint unlimited valid-signed keys (logged) and seal unlimited valid codes
// to our public key (pend), so both must be capped and pruned — otherwise a
// flood grows them without limit (and rewrites the pending file each time),
// exhausting memory/disk on the very mode that is meant to be the hardened one.
const (
	logDedupWindow = 30 * time.Second // suppress repeat "pending" logs per key
	maxLoggedKeys  = 1024             // distinct keys tracked for log dedup
	maxPending     = 1024             // distinct enrollment codes held pending
	maxReplaySigs  = 4096             // recently-seen registration signatures kept

	// A registration signature is accepted while its timestamp is within ±regSkew
	// of now, so a captured one is replayable over a 2*regSkew span; the replay
	// cache must outlive that window to catch it.
	regReplayWindow = 2 * regSkew

	// maxAuthorizedKeys bounds how many entries the allowlist file can build into
	// an in-memory map at startup/reload, so a huge (accidental or hostile, but
	// necessarily local) file cannot exhaust memory. BuddyNet supports at most
	// MaxBuddies simultaneous peers per node; the allowlist may hold more than that
	// (rotated/revoked keys are kept for history), but a list far larger than this
	// is almost certainly a misconfiguration. Generous headroom over MaxBuddies for
	// key rotation, sized to the threat model rather than left effectively
	// unbounded.
	maxAuthorizedKeys = 1024
)

// tightenPerms enforces 0600 on a sensitive allowlist/pending file: if it is
// group/other-accessible (e.g. a config-management edit dropped the mode), warn
// and chmod it back — the same policy the identity key uses. fi is the stat of
// the OPEN file, so this also avoids a path-based re-stat race.
func tightenPerms(path string, fi os.FileInfo) {
	if fi.Mode().Perm()&0o077 != 0 {
		log.Printf("WARNING: %s had permissions %v (group/other access); tightening to 0600", path, fi.Mode().Perm())
		_ = os.Chmod(path, 0o600)
	}
}

// authorizer is the optional client allowlist (approval mode) for the handshake
// server. It holds approved client public keys, loaded from an
// SSH-authorized_keys-style file (one base64 Ed25519 key per line, optional
// label, '#' comments ignored) and hot-reloaded when the file changes.
type authorizer struct {
	path     string
	pendDB   string
	selfPriv ed25519.PrivateKey

	mu         sync.RWMutex
	keys       map[string]string
	mtime      time.Time
	logged     map[string]time.Time
	pend       map[string]pendingEntry
	recentSigs map[string]time.Time // reg signature -> first seen (replay defense)
}

type pendingEntry struct {
	Key  string
	Seen time.Time
}

func newAuthorizer(path string, selfPriv ed25519.PrivateKey) (*authorizer, error) {
	a := &authorizer{
		path:       path,
		pendDB:     path + ".pending",
		selfPriv:   selfPriv,
		keys:       map[string]string{},
		logged:     map[string]time.Time{},
		pend:       map[string]pendingEntry{},
		recentSigs: map[string]time.Time{},
	}
	if err := a.reload(); err != nil {
		return nil, err
	}
	a.pend, _ = readPending(a.pendDB)
	return a, nil
}

func (a *authorizer) reload() error {
	keys, mtime, err := readAuthorized(a.path)
	if err != nil {
		if os.IsNotExist(err) {
			a.mu.Lock()
			a.keys = map[string]string{}
			a.mu.Unlock()
			return nil
		}
		return err
	}
	a.mu.Lock()
	a.keys, a.mtime = keys, mtime
	a.mu.Unlock()
	return nil
}

func (a *authorizer) watch(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		fi, err := os.Stat(a.path)
		if err != nil {
			continue
		}
		a.mu.RLock()
		changed := !fi.ModTime().Equal(a.mtime)
		a.mu.RUnlock()
		if changed {
			if err := a.reload(); err != nil {
				log.Printf("authorized reload: %v", err)
			} else {
				log.Printf("AUTHZ: action=reload count=%d", a.count())
			}
		}
	}
}

func (a *authorizer) allowed(pubkey string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	_, ok := a.keys[pubkey]
	return ok
}

func (a *authorizer) count() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.keys)
}

func (a *authorizer) logPending(pubkey, tokenHash string) {
	a.mu.Lock()
	last, seen := a.logged[pubkey]
	if seen && time.Since(last) < logDedupWindow {
		a.mu.Unlock()
		return
	}
	// Bound the dedup map: an outsider can sign valid registrations with unlimited
	// fresh keys. Prune entries past the dedup window first; if the map is still
	// full of recent keys (an active flood), drop silently — this caps both memory
	// and the log volume the flood would otherwise produce.
	if len(a.logged) >= maxLoggedKeys {
		a.pruneLoggedLocked()
		if len(a.logged) >= maxLoggedKeys {
			a.mu.Unlock()
			return
		}
	}
	a.logged[pubkey] = time.Now()
	a.mu.Unlock()
	log.Printf("AUTHZ: action=pending key=%s token=%s — approve with: buddynet --role=handshake --authorized %s approve %s",
		keyTag(pubkey), tokenHash, a.path, pubkey)
}

// pruneLoggedLocked drops dedup entries older than the dedup window. Caller holds a.mu.
func (a *authorizer) pruneLoggedLocked() {
	for k, t := range a.logged {
		if time.Since(t) >= logDedupWindow {
			delete(a.logged, k)
		}
	}
}

// replayed reports whether this exact registration signature was seen recently,
// recording fresh ones. Callers invoke it only AFTER verifyRegistration passes,
// so the cache holds valid signatures and an attacker cannot pollute it with
// garbage. The map is bounded; when it is full we prune expired entries and, if
// still full, EVICT THE OLDEST (LRU) to make room — never failing open (which
// would let a replay through) and never refusing the new entry (which would let
// an attacker with one approved key DoS all pairings by flooding fresh sigs).
// Under a sustained flood the effective replay window narrows to the most recent
// maxReplaySigs entries, but the global rate limiter bounds how fast that can
// happen.
func (a *authorizer) replayed(sig string) bool {
	if sig == "" {
		return false
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if seen, ok := a.recentSigs[sig]; ok && now.Sub(seen) < regReplayWindow {
		return true
	}
	if len(a.recentSigs) >= maxReplaySigs {
		a.pruneSigsLocked(now)
		if len(a.recentSigs) >= maxReplaySigs {
			a.evictOldestSigLocked()
		}
	}
	a.recentSigs[sig] = now
	return false
}

// evictOldestSigLocked removes the single oldest replay-cache entry (closest to
// expiry), freeing a slot without failing open. Caller holds a.mu.
func (a *authorizer) evictOldestSigLocked() {
	var oldest string
	var oldestT time.Time
	first := true
	for s, t := range a.recentSigs {
		if first || t.Before(oldestT) {
			oldest, oldestT, first = s, t, false
		}
	}
	if !first {
		delete(a.recentSigs, oldest)
	}
}

// pruneSigsLocked drops replay-cache entries past the replay window. Caller holds a.mu.
func (a *authorizer) pruneSigsLocked(now time.Time) {
	for s, t := range a.recentSigs {
		if now.Sub(t) >= regReplayWindow {
			delete(a.recentSigs, s)
		}
	}
}

func (a *authorizer) recordPending(codeEnc, key string) {
	if codeEnc == "" {
		return
	}
	code, err := bcrypto.OpenCode(codeEnc, a.selfPriv)
	if err != nil || code == "" {
		return
	}
	h := shortHash(code)
	a.mu.Lock()
	existing, ok := a.pend[h]
	if ok && existing.Key != key {
		if _, approved := a.keys[existing.Key]; !approved {
			a.mu.Unlock()
			return
		}
	}
	isNew := !ok || existing.Key != key
	if isNew && !ok {
		// A brand-new code grows the set (and triggers a file rewrite). An outsider
		// can seal unlimited valid codes to our public key, so prune expired entries
		// before inserting and refuse once full — bounding both the map and the
		// O(n) rewrite that each new code would otherwise cost.
		if len(a.pend) >= maxPending {
			a.prunePendingLocked()
			if len(a.pend) >= maxPending {
				a.mu.Unlock()
				return
			}
		}
	}
	a.pend[h] = pendingEntry{Key: key, Seen: time.Now()}
	snapshot := clonePending(a.pend)
	a.mu.Unlock()
	if isNew {
		if err := writePending(a.pendDB, snapshot); err != nil {
			log.Printf("pending write: %v", err)
		}
		// Do NOT log the cleartext enrollment code — it is a bearer secret and the
		// log may be shipped off-box. The public key is a non-secret identifier, so
		// approve by key; the code is also persisted in the 0600 .pending file for
		// anyone who prefers code-based approval.
		log.Printf("AUTHZ: action=pending key=%s code=%s — approve with: buddynet --role=handshake --authorized %s approve %s",
			keyTag(key), shortHash(code), a.path, key)
	}
}

// prunePendingLocked drops enrollment entries past pendingTTL, so the pruned set
// is what gets persisted next. Caller holds a.mu.
func (a *authorizer) prunePendingLocked() {
	for k, e := range a.pend {
		if time.Since(e.Seen) > pendingTTL {
			delete(a.pend, k)
		}
	}
}

func clonePending(m map[string]pendingEntry) map[string]pendingEntry {
	out := make(map[string]pendingEntry, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// --- file helpers, shared by the approve/list/revoke subcommands ----------

func readAuthorized(path string) (map[string]string, time.Time, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer f.Close()
	fi, err := f.Stat() // fstat the OPEN fd: the mtime matches the bytes we read (no TOCTOU)
	if err != nil {
		return nil, time.Time{}, err
	}
	tightenPerms(path, fi)
	keys := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		key := fields[0]
		if !validPubKey(key) {
			continue
		}
		keys[key] = strings.Join(fields[1:], " ")
		if len(keys) >= maxAuthorizedKeys {
			log.Printf("WARNING: %s has more than %d keys; ignoring the rest", path, maxAuthorizedKeys)
			break
		}
	}
	return keys, fi.ModTime(), sc.Err()
}

func validPubKey(b64 string) bool {
	raw, err := base64.StdEncoding.DecodeString(b64)
	return err == nil && len(raw) == ed25519.PublicKeySize
}

// ApproveKey, ListKeys, RevokeKey and AllowClient back the handshake admin
// subcommands; they are exported so cmd/buddynet can wire them to the CLI.

func ApproveKey(path, key, label string) error {
	if !validPubKey(key) {
		return fmt.Errorf("not a valid base64 Ed25519 public key: %q", key)
	}
	defer lockAllowlist(path)() // serialise concurrent approve/revoke (lost-update guard)
	keys, _, err := readAuthorized(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if _, ok := keys[key]; ok {
		fmt.Printf("already approved: %s\n", key)
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	line := key
	if label != "" {
		line += " " + label
	}
	if _, err := fmt.Fprintln(f, line); err != nil {
		return err
	}
	fmt.Printf("approved: %s %s\n", key, label)
	return nil
}

func ListKeys(path string) error {
	keys, _, err := readAuthorized(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("(no authorized clients yet)")
			return nil
		}
		return err
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)
	for _, k := range ordered {
		fmt.Printf("%s %s\n", k, keys[k])
	}
	if len(ordered) == 0 {
		fmt.Println("(no authorized clients yet)")
	}
	return nil
}

func RevokeKey(path, key string) error {
	defer lockAllowlist(path)() // serialise concurrent approve/revoke (lost-update guard)
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	var kept []string
	removed := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) > 0 && fields[0] == key {
			removed++
			continue
		}
		kept = append(kept, line)
	}
	f.Close()
	if err := sc.Err(); err != nil {
		return err
	}
	if removed == 0 {
		fmt.Printf("not in list: %s\n", key)
		return nil
	}
	out := strings.Join(kept, "\n")
	if out != "" {
		out += "\n"
	}
	// Atomic replace (tmp + rename) so the inotify reload never observes a
	// truncated allowlist mid-rewrite: a concurrent reader sees either the old or
	// the new file, never a torn one.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(out), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	fmt.Printf("revoked %d entr(y/ies): %s\n", removed, key)
	return nil
}

// --- pending enrollments (code -> key) ------------------------------------

func readPending(path string) (map[string]pendingEntry, error) {
	out := map[string]pendingEntry{}
	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer f.Close()
	if fi, serr := f.Stat(); serr == nil {
		tightenPerms(path, fi)
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		sec, _ := strconv.ParseInt(fields[2], 10, 64)
		seen := time.Unix(sec, 0)
		if time.Since(seen) > pendingTTL {
			continue
		}
		out[fields[0]] = pendingEntry{Key: fields[1], Seen: seen}
		if len(out) >= maxPending {
			log.Printf("WARNING: %s has more than %d pending entries; ignoring the rest", path, maxPending)
			break
		}
	}
	return out, sc.Err()
}

func writePending(path string, m map[string]pendingEntry) error {
	var b strings.Builder
	for code, e := range m {
		fmt.Fprintf(&b, "%s %s %d\n", code, e.Key, e.Seen.Unix())
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func AllowClient(authorizedPath, code string) error {
	pendPath := authorizedPath + ".pending"
	pend, err := readPending(pendPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no pending enrollments yet (has the client started with --code %q?)", code)
		}
		return err
	}
	h := shortHash(code)
	e, ok := pend[h]
	if !ok {
		return fmt.Errorf("no pending client with code %q (not registered yet, or code expired)", code)
	}
	// Label the approval with a NON-reversible code tag, never the cleartext
	// enrollment code — the allowlist file may end up in config management
	// (Ansible/Chef), and the code is a bearer secret that must not persist.
	if err := ApproveKey(authorizedPath, e.Key, "code:"+shortHash(code)); err != nil {
		return err
	}
	delete(pend, h)
	return writePending(pendPath, pend)
}
