package role

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
)

// This file holds the `peers` subcommands a node uses to curate its OWN list of
// buddies (list/add/remove). There is no admin authority here: BuddyNet is
// decentralised and self-sovereign, so each node manages only its own manifest —
// distrusting a buddy is a local decision that never affects the other peers.
// Removal is the security-relevant one: it drops both the manifest line AND the
// stored session secret, so a dropped buddy is fully revoked locally and not
// silently reconnected (see removeSession).

// PeersList prints every configured buddy and whether it is already paired (has a
// stored session). Buddies with a stored session but no manifest line — e.g.
// peers paired before the manifest existed — are listed too, marked accordingly,
// since the supervisor maintains them as well.
func PeersList(peersFile, knownPeers string) error {
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

	inManifest := map[string]bool{}
	count := 0
	for _, s := range specs {
		keyB64 := bcrypto.PubKeyB64(s.pin)
		inManifest[keyB64] = true
		status := "unpaired"
		if paired[keyB64] {
			status = "paired"
		}
		tok := "no-token"
		if s.token != "" {
			tok = "token-set"
		}
		fmt.Printf("%s  %-8s  %-9s  %s\n", keyB64, status, tok, "(manifest)")
		count++
	}
	for _, s := range sessions {
		keyB64 := bcrypto.PubKeyB64(s.pin)
		if inManifest[keyB64] {
			continue
		}
		fmt.Printf("%s  %-8s  %-9s  %s\n", keyB64, "paired", "no-token", "(session only)")
		count++
	}
	if count == 0 {
		fmt.Println("(no buddies configured yet)")
	}
	return nil
}

// PeersAdd appends a buddy to the manifest: a pinned key and an optional one-time
// bootstrap token. The key is validated and de-duplicated (a buddy already listed
// is reported, not duplicated). The file is created 0600 in a 0700 directory,
// same trust domain as known_peers.
func PeersAdd(peersFile, key, token string) error {
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

	existing, err := loadPeersFile(peersFile)
	if err != nil {
		return err
	}
	for _, s := range existing {
		if bcrypto.PubKeyB64(s.pin) == keyB64 {
			fmt.Printf("already listed: %s\n", keyTag(keyB64))
			return nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(peersFile), 0o700); err != nil {
		return err
	}
	line := keyB64
	if token != "" {
		line += " " + token
	}
	f, err := os.OpenFile(peersFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := fmt.Fprintln(f, line); err != nil {
		return err
	}
	fmt.Printf("added buddy %s%s\n", keyTag(keyB64), tokenNote(token))
	fmt.Println("note: a running buddy picks this up on SIGHUP (kill -HUP <pid>) or restart.")
	return nil
}

// PeersRemove revokes a buddy: it drops its manifest line AND its stored session
// secret. Both are needed — removing only the manifest line would leave the
// supervisor reconnecting via the stored session. Other buddies are untouched
// (the design is decentralised: distrusting one peer never affects the rest).
func PeersRemove(peersFile, knownPeers, key string) error {
	pin, err := bcrypto.DecodePubKey(key)
	if err != nil {
		return fmt.Errorf("bad peer key: %w", err)
	}
	keyB64 := bcrypto.PubKeyB64(pin)

	manifestRemoved, err := removeManifestLine(peersFile, keyB64)
	if err != nil {
		return err
	}
	sessionRemoved, err := removeSession(knownPeers, keyB64)
	if err != nil {
		return err
	}
	if manifestRemoved == 0 && sessionRemoved == 0 {
		fmt.Printf("not a known buddy: %s\n", keyTag(keyB64))
		return nil
	}
	fmt.Printf("revoked buddy %s (manifest=%d session=%d)\n", keyTag(keyB64), manifestRemoved, sessionRemoved)
	fmt.Println("note: a running buddy applies this on SIGHUP (kill -HUP <pid>) or restart;")
	fmt.Println("      an already-established direct tunnel persists until it drops (see --reauth-interval).")
	return nil
}

// removeManifestLine drops every manifest line whose pinned key matches keyB64,
// preserving comments, blank lines, and other peers. Returns how many were removed.
func removeManifestLine(peersFile, keyB64 string) (int, error) {
	if peersFile == "" {
		return 0, nil
	}
	data, err := os.ReadFile(peersFile)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var kept []string
	removed := 0
	for _, line := range strings.Split(string(data), "\n") {
		text := strings.TrimSpace(line)
		if text != "" && !strings.HasPrefix(text, "#") {
			if fields := strings.Fields(text); len(fields) > 0 {
				if pin, derr := bcrypto.DecodePubKey(fields[0]); derr == nil && bcrypto.PubKeyB64(pin) == keyB64 {
					removed++
					continue
				}
			}
		}
		kept = append(kept, line)
	}
	if removed == 0 {
		return 0, nil
	}
	out := strings.TrimRight(strings.Join(kept, "\n"), "\n")
	if out != "" {
		out += "\n"
	}
	return removed, os.WriteFile(peersFile, []byte(out), 0o600)
}

func tokenNote(token string) string {
	if token == "" {
		return " (no bootstrap token — must already be paired, or add one to bootstrap)"
	}
	return " (with bootstrap token)"
}
