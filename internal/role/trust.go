package role

import (
	"bufio"
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
)

// trustPolicy decides whether to trust the partner identity the handshake server
// vouched for, applying a hierarchy of decreasing strength:
//
//  1. pinned (--peer-key): the partner key MUST equal it, else refuse. Strongest.
//  2. insecure (--insecure): accept anything, no verification. Loud, opt-in only.
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
// SAS, and call confirm to persist it. For a pinned key, --insecure, or an
// already-known matching key it returns needSAS=false. A known key that CHANGED
// is refused with an error (possible MITM).
func (t *trustPolicy) decide(token string, partnerPub ed25519.PublicKey) (needSAS bool, err error) {
	partnerB64 := base64.StdEncoding.EncodeToString(partnerPub)
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
		log.Printf("TRUST: action=insecure key=%s token=%s detail=%q", keyTag(partnerB64), tokenTag(token), "identity NOT verified (--insecure)")
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

func learnPeer(path, token, pubB64 string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s %s\n", tokenKey(token), pubB64)
	return err
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
