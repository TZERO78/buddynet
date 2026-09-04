package role

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/tzero78/buddynet/internal/atomicfile"
	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/nft"
	"github.com/tzero78/buddynet/internal/peer"
)

// This file holds the `peers` subcommands a node uses to curate its OWN list of
// buddies (list/add/remove/migrate). There is no admin authority here: BuddyNet
// is decentralised and self-sovereign, so each node manages only its own
// manifest — distrusting a buddy is a local decision that never affects the
// other peers. Removal is the security-relevant one: it drops both the manifest
// entry AND the stored session secret, so a dropped buddy is fully revoked
// locally and not silently reconnected (see removeSession).

// PeersList prints every configured buddy and whether it is already paired (has a
// stored session). Buddies with a stored session but no manifest entry — e.g.
// peers paired before the manifest existed — are listed too, marked accordingly,
// since the supervisor maintains them as well.
func PeersList(peersFile, knownPeers, peersPath string) error {
	specs, err := loadPeersFile(peersFile)
	if err != nil {
		return err
	}
	sessions, err := loadSessions(knownPeers)
	if err != nil {
		return err
	}
	paired := map[string]bool{}
	for _, s := range sessions {
		paired[bcrypto.PubKeyB64(s.pin)] = true
	}
	revoked, err := revokedSet(trustBase(knownPeers, peersFile))
	if err != nil {
		return err
	}
	names := loadPeerNames(peersPath) // best-effort; empty until a buddy is seen

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	rows := 0
	emit := func(pin ed25519.PublicKey, name, status, tok, expose, source string) {
		keyB64 := bcrypto.PubKeyB64(pin)
		if name == "" {
			name = names[keyB64]
		}
		if name == "" {
			name = "—"
		}
		if rows == 0 {
			fmt.Fprintln(w, "VIP\tNAME\tSTATUS\tKEY\tTOKEN\tEXPOSE\tSOURCE")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			bcrypto.VirtualIPString(pin), name, status, shortKeyTag(keyB64), tok, expose, source)
		rows++
	}

	inManifest := map[string]bool{}
	for _, s := range specs {
		keyB64 := bcrypto.PubKeyB64(s.pin)
		inManifest[keyB64] = true
		status := "unpaired"
		if paired[keyB64] {
			status = "paired"
		}
		if _, gone := revoked[keyB64]; gone {
			status = "REVOKED"
		}
		tok := "no-token"
		if s.token != "" {
			tok = "token-set"
		}
		expose := "(inherit)" // no per-buddy scope: --expose flag, else fail-closed
		if s.expose != nil {
			expose = s.expose.String()
		}
		emit(s.pin, s.name, status, tok, expose, "manifest")
	}
	listed := func(k string) bool { return inManifest[k] }
	for _, s := range sessions {
		keyB64 := bcrypto.PubKeyB64(s.pin)
		if listed(keyB64) {
			continue
		}
		status := "paired"
		if _, gone := revoked[keyB64]; gone {
			status = "REVOKED"
		}
		emit(s.pin, "", status, "—", "(inherit)", "session-only")
		inManifest[keyB64] = true // already shown
	}
	// A revoked buddy usually has neither a manifest entry nor a session left, so
	// it would vanish from this list entirely — and the operator would have no way
	// to see WHY it never comes back, or which key to pass to `peers allow`.
	var revokedKeys []string
	for k := range revoked {
		if !listed(k) {
			revokedKeys = append(revokedKeys, k)
		}
	}
	sort.Strings(revokedKeys)
	for _, k := range revokedKeys {
		pin, derr := bcrypto.DecodePubKey(k)
		if derr != nil {
			continue
		}
		emit(pin, "", "REVOKED", "—", "—", "revoked")
	}
	if rows > 0 && len(revokedKeys) > 0 {
		defer fmt.Println("\nREVOKED buddies cannot pair again until you run: peers allow <key>")
	}
	if rows == 0 {
		fmt.Println("(no buddies configured yet)")
		return nil
	}
	return w.Flush()
}

// shortKeyTag is the 6-char form of a base64 pubkey shown in `peers list`. It is
// a human-friendly handle, not a unique identifier — `peers remove` resolves it
// back to a full key (and rejects an ambiguous prefix).
func shortKeyTag(keyB64 string) string {
	if len(keyB64) < 6 {
		return keyB64
	}
	return keyB64[:6]
}

// loadPeerNames best-effort resolves pubkey -> self-asserted name from the
// offline peer cache (peers.json). Manifest names take precedence in PeersList;
// this covers buddies without one, learned via the server's PEER_LIST. A
// missing/unreadable cache is not an error — the name column just shows "—".
func loadPeerNames(peersPath string) map[string]string {
	names := map[string]string{}
	reg, err := peer.Open(peersPath)
	if err != nil {
		return names
	}
	for _, p := range reg.List() {
		if p.Name != "" {
			names[p.PubKey] = p.Name
		}
	}
	return names
}

// errLegacyManifest tells the operator to convert before writing: add/remove
// write only the YAML format, so they must not silently rewrite a legacy file.
func errLegacyManifest(peersFile string) error {
	return fmt.Errorf("%s is in the deprecated line format — run `buddynet --peers-file %s peers migrate` first", peersFile, peersFile)
}

// PeersAdd appends a buddy to the manifest: a pinned key, an optional one-time
// bootstrap token, and optionally a name and a per-buddy exposure scope for the
// WireGuard data plane. The key is validated and de-duplicated (a buddy already
// listed is reported, not duplicated). The file is created 0600 in a 0700
// directory, same trust domain as known_peers.
func PeersAdd(peersFile, knownPeers, key, token, name, expose string) error {
	if peersFile == "" {
		return fmt.Errorf("--peers-file <path> is required for peers add")
	}
	pin, err := bcrypto.DecodePubKey(key)
	if err != nil {
		return fmt.Errorf("bad peer key: %w", err)
	}
	keyB64 := bcrypto.PubKeyB64(pin)
	if strings.ContainsAny(token, " \t") {
		return fmt.Errorf("bootstrap token must not contain whitespace")
	}
	if err := validateBuddyName(name); err != nil {
		return err
	}
	var scope *nft.Scope
	if expose != "" {
		s, perr := nft.ParseScope(expose)
		if perr != nil {
			return perr
		}
		scope = &s
	}
	if legacy, lerr := manifestNeedsMigration(peersFile); lerr != nil {
		return lerr
	} else if legacy {
		return errLegacyManifest(peersFile)
	}

	// One transaction: listed-ness, the revocation list and the manifest write all
	// under the SAME lock, so `peers add` cannot race the running daemon or a
	// second CLI. The re-allow ordering is the mirror of the revoke ordering (see
	// PeersRemove): manifest entry FIRST, tombstone last, so a crash in between
	// leaves "configured but still revoked" — refused, and the operator repeats —
	// never "allowed but not configured".
	return withTrustStateLock(knownPeers, peersFile, func() error {
		existing, err := loadPeersFile(peersFile)
		if err != nil {
			return err
		}
		lockBase := trustBase(knownPeers, peersFile)
		revoked, err := isRevokedLocked(lockBase, keyB64)
		if err != nil {
			return err
		}
		listed := false
		for _, s := range existing {
			if bcrypto.PubKeyB64(s.pin) == keyB64 {
				listed = true
				break
			}
		}
		// "Listed but revoked" is NOT "already listed" — it is the normal shape of a
		// re-allow, because a revoke deliberately leaves the manifest entry standing
		// if it crashes after the tombstone. Reporting "already listed" here is what
		// left a buddy silently revoked with no way back through this command.
		if listed && !revoked {
			fmt.Printf("already listed: %s\n", keyTag(keyB64))
			return nil
		}
		if !listed {
			// Refuse to grow past the design limit (a new key would make len+1).
			if len(existing) >= MaxBuddies {
				return errTooManyBuddies(len(existing) + 1)
			}
			existing = append(existing, peerSpec{pin: pin, token: token, name: name, expose: scope})
			if err := saveManifestLocked(peersFile, existing); err != nil {
				return err
			}
		}
		if revoked {
			if _, rerr := removeRevokedLocked(lockBase, keyB64); rerr != nil {
				return rerr
			}
			fmt.Printf("allowed buddy %s again (revocation lifted)%s%s\n", keyTag(keyB64), tokenNote(token), exposeNote(scope))
			fmt.Println("note: the old session was destroyed by the revoke — pair again with a NEW invite.")
			fmt.Println("      a running buddy picks this up on SIGHUP (kill -HUP <pid>) or restart.")
			return nil
		}
		fmt.Printf("added buddy %s%s%s\n", keyTag(keyB64), tokenNote(token), exposeNote(scope))
		fmt.Println("note: a running buddy picks this up on SIGHUP (kill -HUP <pid>) or restart.")
		return nil
	})
}

// PeersAllow lifts a revocation WITHOUT touching the manifest, for the node that
// has no --peers-file (the single-buddy setup the Unraid plugin runs). It is
// deliberately a separate, explicit act: the plugin performs it only after a new
// invite has been minted, so the window between "allowed again" and "pinned
// again" never stands open.
func PeersAllow(peersFile, knownPeers, key string) error {
	keyB64, err := resolveKeyRef(peersFile, knownPeers, key)
	if err != nil {
		return err
	}
	return withTrustStateLock(knownPeers, peersFile, func() error {
		lifted, rerr := removeRevokedLocked(trustBase(knownPeers, peersFile), keyB64)
		if rerr != nil {
			return rerr
		}
		if !lifted {
			fmt.Printf("not revoked: %s (nothing to lift)\n", keyTag(keyB64))
			return nil
		}
		fmt.Printf("allowed buddy %s again (revocation lifted)\n", keyTag(keyB64))
		fmt.Println("note: the revoke destroyed the stored session — pair again with a NEW invite.")
		fmt.Println("      with a manifest, add the buddy back too: peers add <key> <token>")
		return nil
	})
}

// PeersRemove revokes a buddy: it drops its manifest entry AND its stored
// session secret. Both are needed — removing only the manifest entry would
// leave the supervisor reconnecting via the stored session. Other buddies are
// untouched (the design is decentralised: distrusting one peer never affects
// the rest).
func PeersRemove(peersFile, knownPeers, key string) error {
	keyB64, err := resolveKeyRef(peersFile, knownPeers, key)
	if err != nil {
		return err
	}

	var manifestRemoved, sessionRemoved int
	var alreadyRevoked bool
	// ONE transaction, and the write order is load-bearing (A-01):
	//
	//   1. tombstone   — the revocation must be durable FIRST
	//   2. session     — the credential that lets the buddy reconnect
	//   3. manifest    — the bootstrap token it could re-pair with
	//
	// A crash between any two steps then leaves the SAFE state: revoked, possibly
	// still configured. The buddy is refused (the tombstone is checked at every
	// attempt), and the operator repeats the command. The reverse order would
	// leave "no longer configured but not revoked", which is precisely the state a
	// still-running worker resurrected itself from.
	// inEffect turns true the moment the tombstone is durable. From then on the
	// buddy is refused whatever else fails, and the operator has to be told so.
	var inEffect bool
	err = withTrustStateLock(knownPeers, peersFile, func() error {
		added, aerr := addRevokedLocked(trustBase(knownPeers, peersFile), keyB64)
		if aerr != nil {
			return aerr
		}
		alreadyRevoked = !added
		inEffect = true
		var serr error
		if sessionRemoved, serr = removeSessionLocked(knownPeers, keyB64); serr != nil {
			return serr
		}
		manifestRemoved, err = removeManifestEntryLocked(peersFile, keyB64)
		return err
	})
	if err != nil {
		if inEffect {
			// Reporting this as a plain failure would be a lie in the dangerous
			// direction: the operator reads "error", concludes the buddy still has
			// access, and goes looking for another way to cut it off. The
			// revocation is already durable — only the cleanup did not finish.
			return fmt.Errorf("the revocation of %s IS ALREADY IN EFFECT — the key is on the "+
				"revocation list and is refused at every reconnect attempt. What did NOT finish "+
				"is the cleanup: %w\n"+
				"  Run the same command again, or remove the buddy's entry from %s by hand. "+
				"The buddy stays revoked either way until you run: peers allow <key>",
				keyTag(keyB64), err, peersFile)
		}
		return err
	}
	if manifestRemoved == 0 && sessionRemoved == 0 && alreadyRevoked {
		fmt.Printf("already revoked: %s\n", keyTag(keyB64))
		return nil
	}
	fmt.Printf("revoked buddy %s (manifest=%d session=%d)\n", keyTag(keyB64), manifestRemoved, sessionRemoved)
	fmt.Println("note: the key is now on the revocation list, so a still-running buddy cannot")
	fmt.Println("      re-pair itself back in; it stops on its next round. A running daemon also")
	fmt.Println("      applies this on SIGHUP (kill -HUP <pid>) or restart, and an already-")
	fmt.Println("      established direct tunnel persists until it drops (see --reauth-interval).")
	fmt.Println("      To allow this buddy again later: peers allow <key>, then a NEW invite.")
	return nil
}

// PeersMigrate converts a legacy line-format manifest to the YAML schema in
// place, keeping the original as <path>.bak. Already-YAML files are a no-op.
func PeersMigrate(peersFile, knownPeers string) error {
	if peersFile == "" {
		return fmt.Errorf("--peers-file <path> is required for peers migrate")
	}
	legacy, err := manifestNeedsMigration(peersFile)
	if err != nil {
		return err
	}
	if !legacy {
		fmt.Printf("%s is already in the YAML format (or absent) — nothing to do\n", peersFile)
		return nil
	}
	specs, err := loadPeersFile(peersFile)
	if err != nil {
		return err
	}
	backup := peersFile + ".bak"
	data, err := os.ReadFile(peersFile)
	if err != nil {
		return err
	}
	// atomicfile, like every other state write: the backup carries the bootstrap
	// tokens of the legacy manifest, and os.WriteFile would have followed a
	// pre-planted symlink at <file>.bak and left an existing file's mode alone —
	// so a world-readable .bak stayed world-readable. Write-to-temp-then-rename
	// neither follows nor inherits.
	if err := atomicfile.Write(backup, data, 0o600); err != nil {
		return fmt.Errorf("write backup %s: %w", backup, err)
	}
	if err := saveManifest(knownPeers, peersFile, specs); err != nil {
		return err
	}
	fmt.Printf("migrated %s to YAML (%d buddies); the old file is kept at %s\n", peersFile, len(specs), backup)
	return nil
}

// resolveKeyRef turns a user-supplied key reference into a full base64 pubkey.
// A complete, valid key is used as-is (so removing an unknown full key stays a
// no-op, not an error). Otherwise the reference is treated as a prefix of the
// base64 key — e.g. the 6-char form shown by `peers list` — and matched against
// this node's known buddies (manifest + sessions). An unknown or ambiguous
// prefix is an error so a typo never silently removes the wrong buddy.
func resolveKeyRef(peersFile, knownPeers, ref string) (string, error) {
	if pin, err := bcrypto.DecodePubKey(ref); err == nil {
		return bcrypto.PubKeyB64(pin), nil
	}
	known := map[string]struct{}{}
	specs, err := loadPeersFile(peersFile)
	if err != nil {
		return "", err
	}
	for _, s := range specs {
		known[bcrypto.PubKeyB64(s.pin)] = struct{}{}
	}
	sessions, err := loadSessions(knownPeers)
	if err != nil {
		return "", err
	}
	for _, s := range sessions {
		known[bcrypto.PubKeyB64(s.pin)] = struct{}{}
	}
	// Revoked keys are resolvable too: after a revoke the key is in neither the
	// manifest nor the sessions, and `peers allow <prefix>` still has to find it.
	rev, err := revokedSet(trustBase(knownPeers, peersFile))
	if err != nil {
		return "", err
	}
	for k := range rev {
		known[k] = struct{}{}
	}

	var matches []string
	for k := range known {
		if strings.HasPrefix(k, ref) {
			matches = append(matches, k)
		}
	}
	sort.Strings(matches)
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", fmt.Errorf("no buddy matches %q — use the KEY shown by `peers list`, or the full key", ref)
	default:
		return "", fmt.Errorf("key %q is ambiguous (matches %d buddies) — use more characters or the full key", ref, len(matches))
	}
}

// removeManifestEntry drops every manifest entry whose pinned key matches
// keyB64, preserving the other buddies. Returns how many were removed. A legacy
// file must be migrated first (remove writes only YAML).
func removeManifestEntryLocked(peersFile, keyB64 string) (int, error) {
	if peersFile == "" {
		return 0, nil
	}
	if legacy, err := manifestNeedsMigration(peersFile); err != nil {
		return 0, err
	} else if legacy {
		return 0, errLegacyManifest(peersFile)
	}
	specs, err := loadPeersFile(peersFile)
	if err != nil {
		return 0, err
	}
	var kept []peerSpec
	removed := 0
	for _, s := range specs {
		if bcrypto.PubKeyB64(s.pin) == keyB64 {
			removed++
			continue
		}
		kept = append(kept, s)
	}
	if removed == 0 {
		return 0, nil
	}
	return removed, saveManifestLocked(peersFile, kept)
}

func tokenNote(token string) string {
	if token == "" {
		return " (no bootstrap token — must already be paired, or add one to bootstrap)"
	}
	return " (with bootstrap token)"
}

func exposeNote(scope *nft.Scope) string {
	if scope == nil {
		return ""
	}
	return fmt.Sprintf(" (WireGuard expose: %s)", scope)
}
