package role

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tzero78/buddynet/internal/tunnel"
)

// sessionSecretLabel binds the derived rendezvous secret to this TLS session.
const sessionSecretLabel = "buddynet-session-rendezvous-v1"

// deriveSessionSecret derives the long-lived rendezvous secret for a pair from
// the live TLS session's exported keying material (RFC 5705) plus both
// identities. Both ends compute the identical value WITHOUT transmitting it; a
// man in the middle — a different TLS session per side — derives a different one
// (and would already have been caught by the SAS). The result is a URL-safe
// base64 string used as the rendezvous token on later reconnects, so the
// short-lived invite token never has to travel or be reused.
func deriveSessionSecret(sess tunnel.Session, myPub, peerPub ed25519.PublicKey) (string, error) {
	a, b := []byte(myPub), []byte(peerPub)
	if bytes.Compare(a, b) > 0 {
		a, b = b, a
	}
	ctx := append(append([]byte{}, a...), b...)
	ekm, err := sess.ExportKeyingMaterial(sessionSecretLabel, ctx, 32)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ekm), nil
}

// A session is persisted in the known_peers store as a third field on the line,
// alongside the invite-token hash and the pinned partner key:
//
//	<tokenhash> <partner_pubkey_b64> <session_secret_b64>
//
// Legacy trust-on-first-use lines have only the first two fields and are left
// untouched. BuddyPeer keeps a single session, so reconnect simply loads the one
// line that carries a session secret.

// saveSession upserts the (single, BuddyPeer) session line: it drops any
// existing session line, preserves legacy 2-field lines, and appends the new
// one. The store stays 0600 in a 0700 directory (same trust domain as id.key).
func saveSession(path, inviteToken, partnerB64, secret string) error {
	if path == "" {
		return fmt.Errorf("no known-peers path to persist the session")
	}
	var kept []string
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				continue // drop the previous session line (BuddyPeer: one only)
			}
			if strings.TrimSpace(line) != "" {
				kept = append(kept, line)
			}
		}
		f.Close()
	} else if !os.IsNotExist(err) {
		return err
	}
	kept = append(kept, fmt.Sprintf("%s %s %s", tokenKey(inviteToken), partnerB64, secret))

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o600)
}

// loadSession returns the single stored session: the pinned partner key and the
// rendezvous secret. ok is false if there is no session line yet.
func loadSession(path string) (partnerPub ed25519.PublicKey, secret string, ok bool, err error) {
	if path == "" {
		return nil, "", false, nil
	}
	f, oerr := os.Open(path)
	if oerr != nil {
		if os.IsNotExist(oerr) {
			return nil, "", false, nil
		}
		return nil, "", false, oerr
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		pub, derr := base64.StdEncoding.DecodeString(fields[1])
		if derr != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		return ed25519.PublicKey(pub), fields[2], true, nil
	}
	return nil, "", false, sc.Err()
}
