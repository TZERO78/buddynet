package role

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/tzero78/buddynet/internal/atomicfile"
)

// trustPolicy decides whether to trust the partner identity the handshake server
// vouched for, applying a hierarchy of decreasing strength:
//
//  1. pinned (--peer-key): the partner key MUST equal it, else refuse. Strongest.
//  2. insecure (--lab): accept anything, no verification. Loud, opt-in only.
//  3. otherwise TOFU: record the key on first connect for a token and trust it;
//     on later connects require it to match (a change is refused, SSH-style).
type trustPolicy struct {
	pinned    ed25519.PublicKey
	insecure  bool
	storePath string
}

// decide evaluates whether to trust the partner identity, WITHOUT learning a new
// one. needSAS is true only in the trust-on-first-use case where the key is not
// yet known: the caller must then bring up the tunnel, have the human verify the
// SAS, and call confirm to persist it. For a pinned key, --lab, or an
// already-known matching key it returns needSAS=false. A known key that CHANGED
// is refused with an error (possible MITM).
func (t *trustPolicy) decide(token string, partnerPub ed25519.PublicKey) (needSAS bool, err error) {
	partnerB64 := base64.StdEncoding.EncodeToString(partnerPub)
	// A revoked buddy is refused before any of the three sources gets a say —
	// including --lab and including a legacy trust-on-first-use line that still
	// matches. Revocation is this node's own decision about this key, so nothing
	// weaker than it may override it.
	if t.storePath != "" {
		revoked, rerr := isRevoked(t.storePath, partnerB64)
		if rerr != nil {
			return false, rerr
		}
		if revoked {
			log.Printf("SECURITY: event=revoked-peer token=%s key=%s detail=%q",
				tokenTag(token), keyTag(partnerB64), "this buddy was revoked here — refusing")
			return false, fmt.Errorf("buddy %s: %w (lift it with: peers allow %s)", keyTag(partnerB64), errPeerRevoked, partnerB64)
		}
	}
	switch {
	case t.pinned != nil:
		if !partnerPub.Equal(t.pinned) {
			// Log the security event HERE, at the detection point with full context,
			// rather than letting it surface three call-frames up as a generic
			// "tunnel error".
			log.Printf("SECURITY: event=pin-mismatch token=%s key=%s detail=%q",
				tokenTag(token), keyTag(partnerB64), "partner key is not the pinned --peer-key (possible hijack/MITM)")
			return false, errors.New("partner identity MISMATCH: not the pinned --peer-key — refusing (possible hijack/MITM)")
		}
		log.Printf("TRUST: action=pinned-ok key=%s token=%s", keyTag(partnerB64), tokenTag(token))
		return false, nil
	case t.insecure:
		log.Printf("TRUST: action=insecure key=%s token=%s detail=%q", keyTag(partnerB64), tokenTag(token), "identity NOT verified (--lab)")
		return false, nil
	default:
		known, err := loadKnownPeer(t.storePath, token)
		if err != nil {
			return false, fmt.Errorf("trust store %s: %w", t.storePath, err)
		}
		if known == "" {
			return true, nil // first contact: verify via SAS, then confirm (logged as tofu-new)
		}
		if known != partnerB64 {
			log.Printf("SECURITY: event=key-changed token=%s key=%s detail=%q",
				tokenTag(token), keyTag(partnerB64),
				fmt.Sprintf("buddy key changed (known %s) — refusing (possible MITM)", keyTag(known)))
			return false, fmt.Errorf("buddy key CHANGED for this token (known %s, got %s) — refusing (possible MITM). If legitimate, remove the entry from %s", known, partnerB64, t.storePath)
		}
		log.Printf("TRUST: action=tofu-match key=%s token=%s", keyTag(partnerB64), tokenTag(token))
		return false, nil
	}
}

// enforcePins checks the partner key the server (or the offline cache) vouched
// for against EVERY pin this node holds locally: the stored session pin, and —
// when --peer-key is set — the operator's configured pin. BOTH must match.
//
// This is the second half of the A-03 fix. nextAttempt already refuses to even
// register when the two local pins contradict each other; that covers "my own
// configuration is inconsistent". This one covers "the server named a partner
// neither pin allows" — a different attacker, so a separate check. Without it,
// a stored session would keep displacing --peer-key exactly as it did before,
// because trustPolicy.decide is never reached once att.pin is set.
func enforcePins(att attempt, partnerPub ed25519.PublicKey, source string) error {
	partnerB64 := base64.StdEncoding.EncodeToString(partnerPub)
	if att.pin != nil && !partnerPub.Equal(att.pin) {
		log.Printf("SECURITY: event=pin-mismatch token=%s key=%s detail=%q",
			tokenTag(att.rendezvous), keyTag(partnerB64), "partner key is not the stored session pin")
		return fmt.Errorf("%s does not match the stored session pin — refusing (someone else answered on the session secret?)", source)
	}
	if att.cfgPin != nil && !partnerPub.Equal(att.cfgPin) {
		log.Printf("SECURITY: event=pin-mismatch token=%s key=%s detail=%q",
			tokenTag(att.rendezvous), keyTag(partnerB64), "partner key is not the pinned --peer-key (possible hijack/MITM)")
		return fmt.Errorf("%s is not the pinned --peer-key — refusing (possible hijack/MITM)", source)
	}
	return nil
}

// confirm persists a partner key to the trust store after the SAS has been
// verified, so subsequent connects match it silently. It is a no-op for a pinned
// or insecure policy (nothing to learn).
func (t *trustPolicy) confirm(token string, partnerPub ed25519.PublicKey) error {
	if t.pinned != nil || t.insecure || t.storePath == "" {
		return nil
	}
	partnerB64 := base64.StdEncoding.EncodeToString(partnerPub)
	if err := learnPeer(t.storePath, token, partnerB64); err != nil {
		return fmt.Errorf("trust store %s: %w", t.storePath, err)
	}
	log.Printf("TRUST: action=tofu-new key=%s token=%s store=%s detail=%q",
		keyTag(partnerB64), tokenTag(token), t.storePath, "recorded on first contact; pin with --peer-key to skip the SAS next time")
	return nil
}

// tokenKey hashes the token for use as the trust-store lookup key, so the store
// never holds the token in clear.
func tokenKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func loadKnownPeer(path, token string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()
	key := tokenKey(token)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == key {
			return fields[1], nil
		}
	}
	return "", sc.Err()
}

// learnPeer records a trust-on-first-use line. A-02: it used to be a bare
// O_APPEND while every other writer of this file does a LOCKED read-modify-write
// — so a TOFU line appended inside another writer's window was dropped when that
// writer renamed its snapshot into place. It now takes the same trust-state lock
// and writes the same atomic way as its neighbours.
func learnPeer(path, token, pubB64 string) error {
	if path == "" {
		return fmt.Errorf("no known-peers path to record the buddy key")
	}
	return withTrustStateLock(path, "", func() error {
		return learnPeerLocked(path, token, pubB64)
	})
}

// learnPeerLocked is learnPeer's body; the caller holds the trust-state lock.
func learnPeerLocked(path, token, pubB64 string) error {
	// A revoked buddy must not come back through the TOFU door either. decide()
	// would only reach confirm() after a human verified the SAS, but "the human
	// confirmed" is not the question here — the operator already said no.
	if revoked, rerr := isRevokedLocked(path, pubB64); rerr != nil {
		return rerr
	} else if revoked {
		return fmt.Errorf("refusing to record revoked buddy %s: %w", keyTag(pubB64), errPeerRevoked)
	}
	existing, err := os.ReadFile(path) // #nosec G304 -- the operator's own --known-peers path
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(existing) > 0 && !bytes.HasSuffix(existing, []byte("\n")) {
		existing = append(existing, '\n')
	}
	line := fmt.Sprintf("%s %s\n", tokenKey(token), pubB64)
	return atomicfile.Write(path, append(existing, line...), 0o600)
}

// DefaultKnownPeersPath is ${XDG_CONFIG_HOME:-~/.config}/buddynet/known_peers,
// or "" if no config dir is available.
func DefaultKnownPeersPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "buddynet", "known_peers")
}

// DefaultPeersPath is ${XDG_CONFIG_HOME:-~/.config}/buddynet/peers.json, the
// offline peer cache, or "" if no config dir is available.
func DefaultPeersPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "buddynet", "peers.json")
}
