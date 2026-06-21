package crypto

import (
	"crypto/ed25519"
	"crypto/sha512"

	"filippo.io/edwards25519"
)

// X25519 (Curve25519) keys derived deterministically from a node's long-term
// Ed25519 identity. The mapping lets any consumer that already holds an Ed25519
// key — or a pinned Ed25519 public key — obtain the matching X25519 key without
// distributing a second key or running a second derivation.
//
// Used by two callers that must agree on the SAME X25519 key for the same
// identity:
//   - sealedcode.go: NaCl sealed boxes to the server's derived recipient key.
//   - the WireGuard data plane (Phase 3): a buddy derives its partner's WG
//     public key from the partner's already-pinned Ed25519 public key, so no WG
//     key is exchanged over the tunnel and pinning keeps carrying trust.
//
// Keep a single derivation here; a second, divergent mapping elsewhere would mean
// two "truths" for the same identity. See docs/plans/wireguard.md §3.

// X25519FromEd25519Public maps an Ed25519 public key to the equivalent X25519
// (Montgomery) public key.
func X25519FromEd25519Public(pub ed25519.PublicKey) ([32]byte, error) {
	var out [32]byte
	p, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return out, err
	}
	copy(out[:], p.BytesMontgomery())
	return out, nil
}

// X25519FromEd25519Private maps an Ed25519 private key to the matching X25519
// private scalar (clamped SHA-512 of the seed, per the Ed25519 construction).
func X25519FromEd25519Private(priv ed25519.PrivateKey) [32]byte {
	h := sha512.Sum512(priv.Seed())
	var s [32]byte
	copy(s[:], h[:32])
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
	return s
}
