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
//
// Key reuse across protocols — reviewed and ACCEPTED, not accidental.
// This one identity-derived X25519 keypair is the long-term key for more than one
// protocol: the NaCl sealed box (sealedcode.go), the static-static DH behind the
// rendezvous secret (pairsecret.go), and — on the Phase 3 branch — the WireGuard
// static key. The textbook reflex is "one key, one purpose": derive a separate
// X25519 key per protocol via HKDF(seed, label).
//
// We deliberately do NOT, because that is impossible WITHOUT breaking the design's
// load-bearing invariant. HKDF(seed, …) needs the private seed, so a peer holding
// only a pinned Ed25519 PUBLIC key could no longer recompute the per-purpose
// public key non-interactively — which is the entire point of the map above (a
// buddy derives a partner's WG / sealed-box key straight from the pinned identity,
// nothing is exchanged over the tunnel). A key you must derive from the public
// half cannot be domain-separated. Giving each protocol its own exchanged/pinned
// public key would trade a theoretical concern for a REAL one: a second key to
// distribute and pin, i.e. a fresh MITM surface the "one pinned key" model exists
// to remove.
//
// The reuse is safe here because separation happens at each CONSUMER's KDF, not at
// the key: Ed25519-sign + X25519-DH from one seed is the blessed libsodium/Signal
// construction; pairsecret.go runs the DH output through a LABELLED HKDF
// ("buddynet-pair-secret-v1" ‖ both pubkeys); the sealed box is domain-fixed by
// its own HSalsa20 construction and is the sole NaCl-box user; WireGuard/Noise IK
// binds the static key into its transcript hash. The invariant to preserve when
// touching this: any NEW consumer of this keypair MUST post-process the raw DH
// through a labelled KDF and MUST NOT introduce a second public-key derivation.
// This reuse is now LIVE across three consumers (sealed box, rendezvous secret,
// and the shipped --wireguard data plane) and is the designated item for an
// external crypto review. See SECURITY.md "One key, many roles".

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
	wipe(h[:]) // the SHA-512 block holds the raw scalar material; drop it once copied
	return s
}
