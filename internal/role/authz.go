package role

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"github.com/tzero78/buddynet/internal/atomicfile"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/ratelimit"
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
	maxReplayRegs  = 4096             // recently-seen (key,nonce) registrations of APPROVED keys
	// maxPreAuthRegs bounds the SEPARATE cache of nonces seen from keys that are not
	// (yet) approved. Separate is the whole point: entries here may only ever evict
	// each other, never an approved buddy's. It is filled behind the strict
	// enrollment limiter (rlEnroll*), so filling it outright takes longer than its
	// own TTL — a flood expires from the front rather than displacing anything.
	maxPreAuthRegs = 4096

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

	// statErrorWindow throttles the unreadable-allowlist warning. Long enough that a
	// persistent problem does not fill the log, short enough that an operator
	// watching the log sees it while they are still looking.
	statErrorWindow = 5 * time.Minute
)

// acquireLock is the indirection the state writers call, so a test can drive the
// LOCK FAILURE path deterministically — the one path that decides whether a
// failed lock turns into a refused write or a silent unsynchronised one.
// Production always uses lockFile; only tests reassign it, and they restore it
// with t.Cleanup. The package's tests run sequentially, so no reader races with
// the assignment.
var acquireLock = lockFile

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

	// enroll gates work done for keys that are NOT on the allowlist. Since an
	// unknown key may now complete the TLS handshake (that is what makes code-based
	// enrollment possible at all), the per-registration cost it can trigger — a
	// sealed-code X25519 open, a pending-map insert, a pending-file rewrite — must
	// be bounded far more tightly than the cost an approved buddy causes. Its own
	// limiter, so a stranger flood can never eat an allowlisted buddy's budget.
	enroll *ratelimit.Limiter

	// writeMu serialises PERSISTENCE. It is taken before mu and held across the
	// file write, so two writers can never rename their snapshots out of order —
	// which is how an older pending set used to overwrite a newer one. mu itself is
	// NOT held across the write: it serves allowed() and replayed() on every packet,
	// so putting disk I/O under it would trade a lost update for a stall.
	writeMu sync.Mutex

	mu         sync.RWMutex
	keys       map[string]string
	mtime      time.Time
	logged     map[string]time.Time
	pend       map[string]pendingEntry
	recentRegs map[string]time.Time // "pubkey\x00nonce" -> first seen, APPROVED keys
	// preAuthRegs is the same thing for keys that are NOT yet approved. Kept apart
	// from recentRegs so a stranger flood can never evict an approved buddy's entry
	// — the reason unapproved keys were excluded from the replay cache in the first
	// place — while still remembering what they sent, so a registration observed
	// before approval is recognised as a replay afterwards.
	preAuthRegs map[string]time.Time
	// approvedAt records WHEN a key was added to the allowlist by a running server.
	// An unapproved key never enters the replay cache (that is what stops outsiders
	// from flushing it), so without this a registration captured before approval
	// would stay replayable for the rest of its freshness window the moment the
	// operator approves. Keys present at startup carry the zero time — no approval
	// transition happened in this process, and constraining them would only punish
	// clock-skewed clients after every restart for no gain.
	approvedAt map[string]time.Time
	// missing latches "the allowlist file is not there", so the warning is logged
	// once per disappearance rather than on every poll.
	missing bool
	// lastStatWarn throttles the "cannot read the allowlist" warning, which would
	// otherwise repeat on every poll for as long as the condition lasts.
	lastStatWarn time.Time
	// lastPendWarn throttles the failed-pending-write warning the same way.
	lastPendWarn time.Time
	// pendAdded holds the entries THIS PROCESS added since its last successful
	// write. It is what gets merged into the file's own content, instead of
	// overwriting the file with our whole map — see persistPending.
	pendAdded map[string]pendingEntry
	// pendDirty means the pending FILE does not reflect the map: a write failed, or
	// a concurrent writer may have clobbered it. Without this a lost entry was
	// PERMANENT — recordPending only wrote when the entry was new, so the client
	// re-registering every second changed nothing and `allowclient <CODE>` stayed
	// broken until the TTL expired or the server restarted.
	pendDirty bool
}

// Enrollment ceilings. An enrolling client sends one REGISTER per second and only
// until the operator approves it, so a couple of attempts per second per source is
// ample; anything beyond that is a stranger probing or flooding.
const (
	rlEnrollGlobalRate = 20   // admitted unknown-key registrations/sec, all sources
	rlEnrollSrcRate    = 2    // admitted unknown-key registrations/sec per source
	rlEnrollMaxSources = 1024 // bound on the tracked-source map
)

type pendingEntry struct {
	Key  string
	Seen time.Time
}

func newAuthorizer(path string, selfPriv ed25519.PrivateKey) (*authorizer, error) {
	a := &authorizer{
		path:        path,
		pendDB:      path + ".pending",
		selfPriv:    selfPriv,
		keys:        map[string]string{},
		logged:      map[string]time.Time{},
		pend:        map[string]pendingEntry{},
		pendAdded:   map[string]pendingEntry{},
		recentRegs:  map[string]time.Time{},
		preAuthRegs: map[string]time.Time{},
		approvedAt:  map[string]time.Time{},
		enroll:      ratelimit.New(rlEnrollGlobalRate, rlEnrollSrcRate, rlEnrollMaxSources),
	}
	if err := a.load(true); err != nil {
		return nil, err
	}
	a.pend, _ = readPending(a.pendDB)
	return a, nil
}

// reload replaces the in-memory allowlist from disk. A MISSING file is not an
// error and does not fall back to anything: it loads as an EMPTY allowlist, i.e.
// zero authorized clients. Approval mode is decided by the --authorized flag
// alone, never by whether the file happens to exist.
func (a *authorizer) reload() error { return a.load(false) }

// load replaces the in-memory allowlist from disk. initial marks the load done at
// construction, where no key counts as newly approved (see approvedAt).
func (a *authorizer) load(initial bool) error {
	keys, mtime, err := readAuthorized(a.path)
	if err != nil {
		if os.IsNotExist(err) {
			a.mu.Lock()
			a.keys = map[string]string{}
			a.approvedAt = map[string]time.Time{}
			a.mtime = time.Time{}
			a.missing = true
			a.mu.Unlock()
			return nil
		}
		return err
	}
	now := time.Now()
	a.mu.Lock()
	approved := make(map[string]time.Time, len(keys))
	for k := range keys {
		switch {
		case initial:
			approved[k] = time.Time{} // unconstrained: no transition in this process
		default:
			if at, known := a.approvedAt[k]; known {
				approved[k] = at // already approved earlier; keep the original moment
			} else {
				approved[k] = now // NEW approval: this is the transition to protect
			}
		}
	}
	a.keys, a.approvedAt, a.mtime = keys, approved, mtime
	a.mu.Unlock()
	return nil
}

// freshSinceApproval reports whether a registration's timestamp is at or after
// the moment its key was approved. A registration minted BEFORE the approval —
// i.e. captured while the key was still an outsider, and therefore never recorded
// in the replay cache — is refused, closing the transition window. Keys the
// process inherited at startup are unconstrained (zero time).
//
// `ts` is unix SECONDS, so a registration minted at 16.9 s reports 16. Comparing
// it against the approval instant unmodified would reject a legitimate client for
// its first attempt after approval; one second of slack absorbs that. The cost is
// an irreducible ~1 s residual window: a registration captured in the same second
// as the approval is indistinguishable from one minted just after it. Narrowing
// that further would mean putting sub-second time on the wire, which is not worth
// a wire change for a window an operator can never hit deliberately.
func (a *authorizer) freshSinceApproval(pubkey string, ts int64) bool {
	a.mu.RLock()
	at, known := a.approvedAt[pubkey]
	a.mu.RUnlock()
	if !known || at.IsZero() {
		return true
	}
	return !time.Unix(ts, 0).Before(at.Add(-time.Second))
}

// authzPollInterval is how often the allowlist file is re-checked for changes
// (an edit, an approve/revoke, or the file disappearing entirely).
const authzPollInterval = 2 * time.Second

func (a *authorizer) watch(ctx context.Context) {
	t := time.NewTicker(authzPollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.pollOnce()
	}
}

// pollOnce is one iteration of the allowlist watch, factored out so it can be
// driven directly in tests without waiting on the ticker.
func (a *authorizer) pollOnce() {
	fi, err := os.Stat(a.path)
	if err != nil {
		if os.IsNotExist(err) {
			// The file is GONE. Approval mode stays on and the in-memory allowlist is
			// emptied: "no allowlist" must mean "nobody may pair", never "everybody
			// may". Previously this branch just skipped the tick, so a deleted
			// allowlist left the last-loaded keys authorized indefinitely — a revoke
			// by `rm` silently did nothing.
			a.noteMissing()
			return
		}
		// Any other stat error (a permission problem, transient I/O) is not evidence
		// that the operator revoked anything, so the loaded allowlist is kept — but
		// SAY SO. Silence here means an allowlist frozen at its last-loaded state
		// while the operator believes their edits (an approve, a revoke) are taking
		// effect. Throttled like every other repeating warning: the watch ticks every
		// couple of seconds.
		a.noteStatError(err)
		return
	}
	a.mu.Lock()
	changed := !fi.ModTime().Equal(a.mtime)
	restored := a.missing
	a.missing = false
	a.mu.Unlock()
	if !changed {
		return
	}
	if err := a.reload(); err != nil {
		log.Printf("authorized reload: %v", err)
		return
	}
	if restored {
		log.Printf("AUTHZ: action=restored count=%d detail=%q", a.count(), "allowlist file is back; entries reloaded")
		return
	}
	log.Printf("AUTHZ: action=reload count=%d", a.count())
}

// noteStatError reports an allowlist that cannot be stat'ed for a reason OTHER
// than "gone" (a permission change, a broken mount, transient I/O). The loaded
// allowlist stays in force — fail-static, not fail-open — but the operator has to
// learn that the file is no longer being read, or a revoke will appear to work and
// silently not.
func (a *authorizer) noteStatError(err error) {
	a.mu.Lock()
	quiet := time.Since(a.lastStatWarn) < statErrorWindow
	if !quiet {
		a.lastStatWarn = time.Now()
	}
	n := len(a.keys)
	a.mu.Unlock()
	if quiet {
		return
	}
	log.Printf("WARNING: cannot read the allowlist %s (%v) — keeping the %d key(s) loaded earlier; "+
		"approvals and revokes are NOT taking effect until this is fixed", a.path, err, n)
}

// noteMissing empties the allowlist because its file has disappeared, and says so
// ONCE per disappearance. The watch runs every couple of seconds, so logging
// unconditionally would write the same warning forever; the latch is cleared when
// the file comes back, so a later deletion is reported again.
func (a *authorizer) noteMissing() {
	a.mu.Lock()
	dropped := len(a.keys)
	already := a.missing
	a.keys = map[string]string{}
	// Zero the mtime so the file is reloaded whenever it reappears, even if it is
	// restored from a backup carrying an older timestamp than the one we last saw.
	a.mtime = time.Time{}
	a.missing = true
	a.mu.Unlock()
	if already {
		return
	}
	log.Printf("WARNING: allowlist %s no longer exists — approval mode stays ON with ZERO authorized clients "+
		"(%d dropped); no buddy can pair until the file is restored or a key is approved again", a.path, dropped)
}

func (a *authorizer) allowed(pubkey string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	_, ok := a.keys[pubkey]
	return ok
}

// allowEnroll reports whether an unknown key from src may have enrollment work
// done for it this second. A test-constructed authorizer with no limiter is
// treated as unlimited; the production constructor always installs one.
func (a *authorizer) allowEnroll(src string) bool {
	if a.enroll == nil {
		return true
	}
	return a.enroll.Allow(src)
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

// replayed reports whether this (public key, nonce) pair was seen recently,
// recording fresh ones. Callers invoke it only AFTER verifyRegistration passes,
// so the cache holds proven-valid pairs and an attacker cannot pollute it with
// garbage (nor grow the key: ValidNonce fixes the nonce length, and the pubkey is
// length-bounded by parseRegister).
//
// Keying on (key,nonce) rather than on the signature is what makes ordinary
// polling work: a buddy waiting for its partner re-registers about once a second,
// each time with a fresh nonce and therefore a fresh cache key, while a captured
// registration replayed verbatim reuses both and is caught.
//
// The map is bounded; when it is full we prune expired entries and, if still
// full, EVICT THE OLDEST (LRU) to make room — never failing open (which would let
// a replay through) and never refusing the new entry (which would let an attacker
// with one approved key DoS all pairings by flooding fresh nonces). Under a
// sustained flood the effective replay window narrows to the most recent
// maxReplayRegs entries, but the global rate limiter bounds how fast that can
// happen.
func (a *authorizer) replayed(pubkey, nonce string) bool {
	if pubkey == "" || nonce == "" {
		return false
	}
	k := regKey(pubkey, nonce)
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if seen, ok := a.recentRegs[k]; ok && now.Sub(seen) < regReplayWindow {
		return true
	}
	// BOTH caches are consulted. A nonce first seen while the key was still
	// unapproved lives in preAuthRegs; without this lookup, approving the key would
	// make that captured registration replayable — and no timestamp check can close
	// that, because the timestamp is the attacker's to choose (it may legitimately
	// sit up to regSkew in the FUTURE, i.e. after the approval that follows).
	if seen, ok := a.preAuthRegs[k]; ok && now.Sub(seen) < regReplayWindow {
		return true
	}
	if len(a.recentRegs) >= maxReplayRegs {
		a.pruneRegsLocked(now)
		if len(a.recentRegs) >= maxReplayRegs {
			a.evictOldestRegLocked()
		}
	}
	a.recentRegs[k] = now
	return false
}

// recordPreAuth remembers a nonce presented by a key that is not approved, in the
// cache reserved for exactly that. Callers invoke it only AFTER verifyRegistration
// passes and behind the enrollment limiter, so entries are proven-valid and
// rate-bounded. Eviction here touches preAuthRegs only.
func (a *authorizer) recordPreAuth(pubkey, nonce string) {
	if pubkey == "" || nonce == "" {
		return
	}
	k := regKey(pubkey, nonce)
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.preAuthRegs[k]; ok {
		return // already known; keep the FIRST sighting as the entry's age
	}
	if len(a.preAuthRegs) >= maxPreAuthRegs {
		for s, t := range a.preAuthRegs {
			if now.Sub(t) >= regReplayWindow {
				delete(a.preAuthRegs, s)
			}
		}
		if len(a.preAuthRegs) >= maxPreAuthRegs {
			var oldest string
			var oldestT time.Time
			first := true
			for s, t := range a.preAuthRegs {
				if first || t.Before(oldestT) {
					oldest, oldestT, first = s, t, false
				}
			}
			if !first {
				delete(a.preAuthRegs, oldest) // only ever a pre-auth entry
			}
		}
	}
	a.preAuthRegs[k] = now
}

// regKey is the replay-cache key. NUL-separated: neither field can contain it
// (both are base64), so no pair of distinct (key,nonce) inputs can collide.
func regKey(pubkey, nonce string) string { return pubkey + "\x00" + nonce }

// evictOldestRegLocked removes the single oldest replay-cache entry (closest to
// expiry), freeing a slot without failing open. Caller holds a.mu.
func (a *authorizer) evictOldestRegLocked() {
	var oldest string
	var oldestT time.Time
	first := true
	for s, t := range a.recentRegs {
		if first || t.Before(oldestT) {
			oldest, oldestT, first = s, t, false
		}
	}
	if !first {
		delete(a.recentRegs, oldest)
	}
}

// pruneRegsLocked drops expired entries from BOTH replay caches. Caller holds a.mu.
func (a *authorizer) pruneRegsLocked(now time.Time) {
	for s, t := range a.recentRegs {
		if now.Sub(t) >= regReplayWindow {
			delete(a.recentRegs, s)
		}
	}
	for s, t := range a.preAuthRegs {
		if now.Sub(t) >= regReplayWindow {
			delete(a.preAuthRegs, s)
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
	entry := pendingEntry{Key: key, Seen: time.Now()}
	a.pend[h] = entry
	if isNew || a.pendDirty {
		a.pendAdded[h] = entry // ours to contribute at the next write
	}
	dirty := a.pendDirty
	a.mu.Unlock()
	// Persist when the entry is new OR when the file is known to be out of sync.
	// The dirty case is what makes a lost entry recoverable: the enrolling client
	// re-registers about once a second, and each of those attempts now repairs the
	// file instead of finding "already in the map" and doing nothing.
	if isNew || dirty {
		a.persistPending()
	}
	if isNew {
		// Do NOT log the cleartext enrollment code — it is a bearer secret and the
		// log may be shipped off-box. The public key is a non-secret identifier, so
		// approve by key; the code is also persisted in the 0600 .pending file for
		// anyone who prefers code-based approval.
		log.Printf("AUTHZ: action=pending key=%s code=%s — approve with: buddynet --role=handshake --authorized %s approve %s",
			keyTag(key), shortHash(code), a.path, key)
	}
}

// persistPending writes the pending set to disk with the snapshot taken INSIDE
// writeMu, so a slower writer can never rename an older set over a newer one. A
// failure marks the file dirty, so the next registration retries rather than
// leaving the operator with a code that `allowclient` cannot find.
func (a *authorizer) persistPending() {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	// The ADVISORY FILE lock as well, not just the in-process one: `allowclient`
	// runs in a separate process and does its own read-modify-write of this file.
	// writeMu orders our own writers against each other and says nothing about that
	// one, so without this an operator approving a code could still drop an entry
	// the server wrote in between (or have its own write dropped).
	//
	// A lock we cannot take means we must NOT write: another process is mid-update,
	// which is precisely the case this exists for. The state stays dirty, so the
	// next registration retries — an enrolling client sends one about once a second.
	unlock, lerr := acquireLock(a.pendDB)
	if lerr != nil {
		a.mu.Lock()
		a.pendDirty = true
		a.mu.Unlock()
		a.notePendWriteError(lerr)
		return
	}
	defer unlock()

	// READ-MODIFY-WRITE, not overwrite. Holding the lock only orders the writes;
	// it does not make our in-memory map the truth. `allowclient` removes an entry
	// under the same lock, and a server that then wrote its own snapshot would
	// RESURRECT the approved code — the operator's change lost despite the lock
	// working exactly as intended.
	//
	// So the FILE is authoritative for what other processes did, and we contribute
	// only what we added ourselves since the last successful write.
	onDisk, rerr := readPending(a.pendDB)
	if rerr != nil && !os.IsNotExist(rerr) {
		a.mu.Lock()
		a.pendDirty = true
		a.mu.Unlock()
		a.notePendWriteError(rerr)
		return
	}

	a.mu.RLock()
	merged := clonePending(onDisk)
	contributed := make([]string, 0, len(a.pendAdded))
	for h, e := range a.pendAdded {
		merged[h] = e
		contributed = append(contributed, h)
	}
	a.mu.RUnlock()

	err := writePending(a.pendDB, merged)
	a.mu.Lock()
	if err == nil {
		// Retire exactly what THIS write carried. Clearing the whole map would drop a
		// contribution that recordPending added while we were writing — it does not
		// hold writeMu, only a.mu, and briefly.
		for _, h := range contributed {
			delete(a.pendAdded, h)
		}
		// Realign the in-memory view with the file, so an entry `allowclient` removed
		// does not linger and reappear at the next write. Entries still queued in
		// pendAdded stay: they are ours and not on disk yet.
		for h := range a.pend {
			_, onDiskNow := merged[h]
			_, stillQueued := a.pendAdded[h]
			if !onDiskNow && !stillQueued {
				delete(a.pend, h)
			}
		}
		for h, e := range merged {
			if _, known := a.pend[h]; !known {
				a.pend[h] = e
			}
		}
	}
	a.pendDirty = err != nil
	a.mu.Unlock()
	if err != nil {
		a.notePendWriteError(err)
	}
}

// notePendWriteError reports a failed pending write, throttled: the write is
// retried on every subsequent registration, and an enrolling client sends one
// about once a second, so an unthrottled line would fill the log for as long as
// the condition lasts.
func (a *authorizer) notePendWriteError(err error) {
	a.mu.Lock()
	quiet := time.Since(a.lastPendWarn) < statErrorWindow
	if !quiet {
		a.lastPendWarn = time.Now()
	}
	a.mu.Unlock()
	if quiet {
		return
	}
	log.Printf("WARNING: could not persist pending enrollments to %s (%v) — "+
		"`allowclient <CODE>` may not find a waiting client until this succeeds; "+
		"retrying on the next registration", a.pendDB, err)
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
	unlock, lerr := acquireLock(path) // serialise concurrent approve/revoke (lost-update guard)
	if lerr != nil {
		return fmt.Errorf("cannot lock the allowlist for update: %w", lerr)
	}
	defer unlock()
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
	unlock, lerr := acquireLock(path) // serialise concurrent approve/revoke (lost-update guard)
	if lerr != nil {
		return fmt.Errorf("cannot lock the allowlist for update: %w", lerr)
	}
	defer unlock()
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
	// Atomic replace so the reload never observes a truncated allowlist mid-rewrite:
	// a concurrent reader sees either the old or the new file, never a torn one —
	// and a crash cannot leave an allowlist that authorises nobody.
	if err := atomicfile.Write(path, []byte(out), 0o600); err != nil {
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
	return atomicfile.Write(path, []byte(b.String()), 0o600)
}

func AllowClient(authorizedPath, code string) error {
	pendPath := authorizedPath + ".pending"
	// Read-modify-write of the pending file under the SAME advisory lock the
	// approve/revoke commands take, so a concurrent operator invocation cannot lose
	// this update. (The server's own writes go through persistPending; the lock is
	// what keeps the two processes from interleaving.)
	unlock, lerr := acquireLock(pendPath)
	if lerr != nil {
		return fmt.Errorf("cannot lock the pending file for update: %w", lerr)
	}
	defer unlock()
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
