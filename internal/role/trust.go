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

func (t *trustPolicy) check(token string, partnerPub ed25519.PublicKey) error {
	partnerB64 := base64.StdEncoding.EncodeToString(partnerPub)
	switch {
	case t.pinned != nil:
		if !partnerPub.Equal(t.pinned) {
			return errors.New("partner identity MISMATCH: not the pinned --peer-key — refusing (possible hijack/MITM)")
		}
		return nil
	case t.insecure:
		return nil
	default:
		known, err := loadKnownPeer(t.storePath, token)
		if err != nil {
			return fmt.Errorf("trust store %s: %w", t.storePath, err)
		}
		if known == "" {
			if err := learnPeer(t.storePath, token, partnerB64); err != nil {
				return fmt.Errorf("trust store %s: %w", t.storePath, err)
			}
			log.Printf("trust-on-first-use: recorded buddy identity %s for this token in %s — pin it with --peer-key to be safe", partnerB64, t.storePath)
			return nil
		}
		if known != partnerB64 {
			return fmt.Errorf("buddy key CHANGED for this token (known %s, got %s) — refusing (possible MITM). If legitimate, remove the entry from %s", known, partnerB64, t.storePath)
		}
		return nil
	}
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
