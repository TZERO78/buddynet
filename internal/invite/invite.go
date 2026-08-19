// Package invite encodes and decodes the invite blob a buddy hands to its
// partner out of band (phone, Signal).
//
// The blob carries two things in one string: the one-time rendezvous token
// (which says WHERE to meet) and the inviter's full Ed25519 public key (which
// says WHO will be there). Binding the key to the invite is what turns the
// trusted channel the invite already travels over into a trust anchor: the
// joining side pins that key before it ever talks to the handshake server, so a
// malicious or compromised server cannot substitute an identity — the joiner
// refuses anything that is not the key from the blob. Without it the invite is a
// bare bearer secret that says nothing about identity, and the entire
// impersonation defence rests on a human comparing a short code.
//
// Everything here is CLIENT-SIDE. The blob never goes on the wire: the server
// only ever sees the opaque rendezvous token, so no protocol version is
// involved and an old peer that is handed a bare token keeps working.
package invite

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// prefix versions the blob format. A future format ("bnet2.") can be told apart
// from this one, and anything without a known prefix is treated as a bare
// legacy token rather than being rejected.
const prefix = "bnet1."

// ErrBadBlob is returned for a string that announces itself as an invite blob
// (it carries the prefix) but does not parse. It is deliberately distinct from
// "this is a bare token": a mistyped or truncated blob must fail loudly instead
// of silently degrading to the weaker unpinned path.
var ErrBadBlob = errors.New("malformed invite")

// Mint returns the invite blob for a rendezvous token and this node's public
// key: "bnet1.<token>.<pubkey>", both parts base64url without padding, so the
// whole thing stays one shell- and URL-safe word that survives a copy-paste
// through a messenger.
func Mint(token string, pub ed25519.PublicKey) string {
	return prefix + token + "." + base64.RawURLEncoding.EncodeToString(pub)
}

// Parse splits an invite the user passed to --join. A blob yields the token and
// the inviter's key, which the caller pins. Anything WITHOUT the prefix is
// returned as-is with a nil key — that is a bare token from an older inviter,
// which still pairs, just by the weaker trust-on-first-use path. A string that
// carries the prefix but does not parse returns ErrBadBlob, never a fallback.
func Parse(s string) (token string, pub ed25519.PublicKey, err error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, prefix) {
		return s, nil, nil
	}
	rest := strings.TrimPrefix(s, prefix)
	tok, keyPart, ok := strings.Cut(rest, ".")
	if !ok || tok == "" || keyPart == "" {
		return "", nil, fmt.Errorf("%w: expected %s<token>.<key>", ErrBadBlob, prefix)
	}
	raw, derr := base64.RawURLEncoding.DecodeString(keyPart)
	if derr != nil {
		return "", nil, fmt.Errorf("%w: key is not base64url: %v", ErrBadBlob, derr)
	}
	if len(raw) != ed25519.PublicKeySize {
		return "", nil, fmt.Errorf("%w: expected a %d-byte key, got %d", ErrBadBlob, ed25519.PublicKeySize, len(raw))
	}
	return tok, ed25519.PublicKey(raw), nil
}

// IsBlob reports whether s announces itself as an invite blob, so a caller can
// tell "the user pasted an invite" from "the user pasted a bare token" even
// when the blob turns out to be malformed.
func IsBlob(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), prefix)
}
