package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// PairSecret derives a stable shared secret for a pair of identities from the
// STATIC X25519 Diffie-Hellman of their Ed25519-derived keys. Both ends compute
// the identical value without transmitting it, and only the two private-key
// holders can — the handshake server and a network observer cannot (they would
// need a private key).
//
// It is the EKM-free replacement for the QUIC/TLS-derived rendezvous secret
// (see internal/role.deriveSessionSecret): on a WireGuard data plane there is no
// RFC 5705 exported keying material to bind to. Properties:
//   - Deterministic across runs → both ends ALWAYS agree, which avoids the
//     rendezvous desync a per-session secret can hit (the #56 class).
//   - No forward secrecy — intentionally fine: this is a matchmaking/rendezvous
//     token, not a content key. Content is encrypted end-to-end with forward
//     secrecy by the data plane itself.
//
// The two identities are mixed in (canonical order) and domain-separated by a
// label so this secret cannot be confused with any other use of the same keys
// (e.g. the WireGuard handshake).
func PairSecret(myPriv ed25519.PrivateKey, peerPub ed25519.PublicKey) ([]byte, error) {
	myScalar := X25519FromEd25519Private(myPriv)
	peerX, err := X25519FromEd25519Public(peerPub)
	if err != nil {
		return nil, err
	}
	shared, err := curve25519.X25519(myScalar[:], peerX[:])
	if err != nil {
		return nil, err
	}

	myPub := myPriv.Public().(ed25519.PublicKey)
	lo, hi := []byte(myPub), []byte(peerPub)
	if bytes.Compare(lo, hi) > 0 {
		lo, hi = hi, lo
	}
	info := append([]byte("buddynet-pair-secret-v1\x00"), lo...)
	info = append(info, hi...)

	out := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, nil, info), out); err != nil {
		return nil, err
	}
	return out, nil
}
