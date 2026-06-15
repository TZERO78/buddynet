package role

import (
	"crypto/sha256"
	"encoding/hex"
)

// This file holds the small, shared helpers behind BuddyNet's structured log
// schema. Three levels are kept deliberately distinct so an operator (or a log
// pipeline) can filter them apart:
//
//   - SECURITY: event=<type> ...   security events; always logged, never silent.
//   - <STATE>:  key=value ...      state transitions (CONNECTED/DISCONNECTED/
//                                  PAIRED/TRUST/AUTHZ), key=value for grep/parse.
//   - stats (last Xs): role=... [ALERT: ...]   per-minute aggregate counters.
//
// Peer identity in logs uses the STABLE key tag (keyTag), not the ephemeral
// per-run id, so an audit trail survives reconnects. Tokens are anonymized:
// logTag (server-keyed HMAC) on the handshake/authz side so the same token maps
// to the same tag across those logs without being a public guessing oracle, and
// tokenTag (plain hash) on the client side where the server key is unavailable.

// keyTag is a short, stable tag for a base64 Ed25519 public key. The first 8
// characters identify a key in practice while keeping log lines readable; the
// full key still appears where an operator needs to act on it (e.g. approve).
func keyTag(pubB64 string) string {
	if len(pubB64) < 8 {
		return pubB64
	}
	return pubB64[:8]
}

// tokenTag is a stable, non-reversible 10-hex tag for a pairing token, used in
// CLIENT-side logs where the server-keyed logTag is not available. It lets two
// client log lines for the same token be correlated; it intentionally differs
// from the server's keyed tag (the client is not a public oracle, so a plain
// truncated hash is sufficient here).
func tokenTag(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:5])
}
