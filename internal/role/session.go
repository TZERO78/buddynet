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
// untouched. The store keeps ONE session line PER partner key (multi-peer): each
// pinned buddy has its own derived rendezvous secret, so reconnect loads every
// session line and the supervisor runs one peerSession per stored partner.

// storedSession is one persisted per-partner session: the pinned partner key and
// the derived rendezvous secret used to re-pair with that one buddy.
type storedSession struct {
	pin    ed25519.PublicKey
	secret string
}

// saveSession upserts the session line FOR THIS PARTNER: it drops only the
// previous session line whose partner key matches partnerB64 (re-pairing the same
// buddy), preserves session lines for OTHER partners (multi-peer) and legacy
// 2-field TOFU lines, then appends the new one. The store stays 0600 in a 0700
// directory (same trust domain as id.key).
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
			// A session line for THIS partner is the one we replace; session lines
			// for other partners and legacy 2-field lines are preserved.
			if len(fields) >= 3 && fields[1] == partnerB64 {
				continue
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

// loadSessions returns every stored session (one per pinned partner). The
// multi-peer supervisor starts one peerSession per returned entry. A store with
// no session line yet returns an empty slice and no error.
func loadSessions(path string) ([]storedSession, error) {
	if path == "" {
		return nil, nil
	}
	f, oerr := os.Open(path)
	if oerr != nil {
		if os.IsNotExist(oerr) {
			return nil, nil
		}
		return nil, oerr
	}
	defer f.Close()
	var out []storedSession
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
		out = append(out, storedSession{pin: ed25519.PublicKey(pub), secret: fields[2]})
	}
	return out, sc.Err()
}

// loadSessionFor returns the stored rendezvous secret for one specific pinned
// partner. The multi-peer supervisor reloads it each reconnect round so a re-pair
// is picked up and a session removed from the store (revocation) ends that one
// peer's worker. ok is false when no session line pins this key.
func loadSessionFor(path string, pin ed25519.PublicKey) (secret string, ok bool, err error) {
	sessions, err := loadSessions(path)
	if err != nil {
		return "", false, err
	}
	for _, s := range sessions {
		if s.pin.Equal(pin) {
			return s.secret, true, nil
		}
	}
	return "", false, nil
}

// loadSession returns the FIRST stored session (back-compat for the single-peer
// reconnect path). Multi-peer callers use loadSessions. ok is false if there is
// no session line yet.
func loadSession(path string) (partnerPub ed25519.PublicKey, secret string, ok bool, err error) {
	sessions, err := loadSessions(path)
	if err != nil || len(sessions) == 0 {
		return nil, "", false, err
	}
	return sessions[0].pin, sessions[0].secret, true, nil
}
