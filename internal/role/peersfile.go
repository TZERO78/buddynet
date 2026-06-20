package role

import (
	"bufio"
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
)

// peerSpec is one buddy the supervisor maintains: its pinned identity key and an
// optional one-time bootstrap token. token is needed only until a session secret
// has been derived and stored for pin; afterwards reconnects use that session and
// the token is ignored. token == "" means "reconnect only" (a stored session must
// already exist, e.g. a previously paired peer not listed in the manifest).
type peerSpec struct {
	pin   ed25519.PublicKey
	token string
}

// loadPeersFile parses a peers manifest: one buddy per line,
//
//	<peer-pubkey-b64> [bootstrap-token]
//
// Blank lines and #-comments are ignored. The pinned key is mandatory (Model A:
// every tunnel is pinned, no trust-on-first-use), the token optional. Duplicate
// keys are rejected so a typo can't silently shadow a peer. The file is the same
// trust domain as known_peers (keep it 0600); an empty path yields no specs.
func loadPeersFile(path string) ([]peerSpec, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // absent manifest = no peers (consistent with loadSessions)
		}
		return nil, fmt.Errorf("peers-file %s: %w", path, err)
	}
	defer f.Close()

	var specs []peerSpec
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) > 2 {
			return nil, fmt.Errorf("peers-file %s line %d: expected '<peer-key> [token]', got %d fields", path, line, len(fields))
		}
		pin, err := bcrypto.DecodePubKey(fields[0])
		if err != nil {
			return nil, fmt.Errorf("peers-file %s line %d: bad peer key: %w", path, line, err)
		}
		keyB64 := bcrypto.PubKeyB64(pin)
		if seen[keyB64] {
			return nil, fmt.Errorf("peers-file %s line %d: duplicate peer key %s", path, line, keyTag(keyB64))
		}
		seen[keyB64] = true
		spec := peerSpec{pin: pin}
		if len(fields) == 2 {
			spec.token = fields[1]
		}
		specs = append(specs, spec)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("peers-file %s: %w", path, err)
	}
	return specs, nil
}

// assemblePeers builds the supervisor's worker set as the union of the peers
// manifest and the stored sessions, keyed by pinned identity. A manifest entry
// contributes its bootstrap token; a stored session for a key already in the
// manifest just confirms it (the session, once present, takes over from the
// token). Stored sessions for keys NOT in the manifest are still maintained as
// reconnect-only peers, so previously paired buddies are not dropped.
func assemblePeers(cfg BuddyConfig) ([]peerSpec, error) {
	manifest, err := loadPeersFile(cfg.PeersFile)
	if err != nil {
		return nil, err
	}
	byKey := map[string]int{} // pubkey b64 → index into specs
	var specs []peerSpec
	for _, s := range manifest {
		byKey[bcrypto.PubKeyB64(s.pin)] = len(specs)
		specs = append(specs, s)
	}

	sessions, err := loadSessions(cfg.KnownPeers)
	if err != nil {
		return nil, err
	}
	for _, s := range sessions {
		if _, ok := byKey[bcrypto.PubKeyB64(s.pin)]; ok {
			continue // already covered by the manifest (session resolved at runtime)
		}
		specs = append(specs, peerSpec{pin: s.pin}) // reconnect-only
	}
	return specs, nil
}
