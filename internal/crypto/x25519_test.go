package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"math/big"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// The load-bearing property: the X25519 public key derived from an Ed25519
// public key must equal the curve base point times the X25519 private scalar
// derived from the matching private key. If this holds, a buddy can derive its
// partner's WireGuard public key from the partner's pinned Ed25519 public key
// (no key exchange over the tunnel) and the two ends still agree. See
// docs/plans/wireguard.md §3.
func TestX25519FromEd25519KeyPairAgrees(t *testing.T) {
	for i := 0; i < 16; i++ {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		gotPub, err := X25519FromEd25519Public(pub)
		if err != nil {
			t.Fatalf("public mapping failed: %v", err)
		}
		scalar := X25519FromEd25519Private(priv)
		wantPub, err := curve25519.X25519(scalar[:], curve25519.Basepoint)
		if err != nil {
			t.Fatalf("scalar base mult failed: %v", err)
		}
		if !bytes.Equal(gotPub[:], wantPub) {
			t.Fatalf("derived X25519 public != base point * private scalar\n got=%x\nwant=%x", gotPub, wantPub)
		}
	}
}

// Two parties must reach the same shared secret (ECDH) using only the local
// private scalar and the peer's derived public key — the symmetry WireGuard
// relies on.
func TestX25519FromEd25519SharedSecretSymmetric(t *testing.T) {
	aPub, aPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	bPub, bPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	aScalar := X25519FromEd25519Private(aPriv)
	bScalar := X25519FromEd25519Private(bPriv)
	aPeer, err := X25519FromEd25519Public(bPub)
	if err != nil {
		t.Fatal(err)
	}
	bPeer, err := X25519FromEd25519Public(aPub)
	if err != nil {
		t.Fatal(err)
	}
	ab, err := curve25519.X25519(aScalar[:], aPeer[:])
	if err != nil {
		t.Fatal(err)
	}
	ba, err := curve25519.X25519(bScalar[:], bPeer[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ab, ba) {
		t.Fatalf("shared secrets differ:\n a->b=%x\n b->a=%x", ab, ba)
	}
}

// Deterministic: the same identity always derives the same X25519 keys (a buddy
// re-deriving a partner's WG key across restarts must get an identical result).
func TestX25519FromEd25519Deterministic(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p1, _ := X25519FromEd25519Public(pub)
	p2, _ := X25519FromEd25519Public(pub)
	if p1 != p2 {
		t.Fatalf("public derivation not deterministic")
	}
	if X25519FromEd25519Private(priv) != X25519FromEd25519Private(priv) {
		t.Fatalf("private derivation not deterministic")
	}
}

// montgomeryUFromEdPub is an INDEPENDENT implementation of the Ed25519->X25519
// public-key map, straight from the RFC 7748 birational formula
//
//	u = (1 + y) / (1 - y)  (mod 2^255 - 19)
//
// computed with math/big and NOTHING from filippo.io/edwards25519. It exists only
// so the test below can cross-check X25519FromEd25519Public against a second, from
// scratch computation — the standard defence against a self-consistent-but-wrong
// derivation. The Edwards point encoding is little-endian y with the sign bit of x
// in the top bit of the last byte; u depends only on y, so we clear that bit.
func montgomeryUFromEdPub(pub ed25519.PublicKey) [32]byte {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	le := make([]byte, 32)
	copy(le, pub)
	le[31] &= 0x7f // drop x's sign bit, leaving the pure y-coordinate
	be := make([]byte, 32)
	for i := range be {
		be[i] = le[31-i] // little-endian -> big-endian for big.Int
	}
	y := new(big.Int).SetBytes(be)
	one := big.NewInt(1)
	num := new(big.Int).Add(one, y)
	den := new(big.Int).Mod(new(big.Int).Sub(one, y), p)
	u := new(big.Int).Mod(new(big.Int).Mul(num, new(big.Int).ModInverse(den, p)), p)
	ub := u.Bytes() // big-endian, may be short
	var out [32]byte
	for i := 0; i < len(ub); i++ {
		out[i] = ub[len(ub)-1-i] // back to little-endian
	}
	return out
}

// TestX25519PublicMatchesRFC7748BirationalMap is a known-answer / differential
// test: for many identities, X25519FromEd25519Public (which uses
// edwards25519.Point.BytesMontgomery) must produce exactly the same bytes as the
// independent RFC 7748 formula above. This locks the mapping to the STANDARD one
// libsodium's crypto_sign_ed25519_pk_to_curve25519 and the WireGuard tooling use,
// so a partner deriving a buddy's WG key with any conformant implementation lands
// on the identical key. A regression in the production derivation fails here.
func TestX25519PublicMatchesRFC7748BirationalMap(t *testing.T) {
	for i := 0; i < 64; i++ {
		pub, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := X25519FromEd25519Public(pub)
		if err != nil {
			t.Fatalf("public mapping failed: %v", err)
		}
		want := montgomeryUFromEdPub(pub)
		if !bytes.Equal(got[:], want[:]) {
			t.Fatalf("derivation diverges from the RFC 7748 birational map\n edpub=%x\n   got=%x\n  want=%x", pub, got, want)
		}
	}
}

// TestX25519DerivationGoldenVectors freezes the whole identity derivation against
// a FIXED seed. If any of these bytes ever change, the node's WireGuard key, its
// sealed-box recipient key, or its virtual IP moved — a silent break of on-the-wire
// compatibility with already-deployed and already-pinned peers. The values were
// generated from this same code and cross-checked by the birational test above.
func TestX25519DerivationGoldenVectors(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 1) // 01 02 03 ... 20
	}
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)

	const (
		wantEdPub = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
		wantXPub  = "4a3807d064d077181cc070989e76891d20dca5559548dc2c77c1a50273882b38"
		wantXPriv = "70788f1a0cea001a2631dae5d05dbd062008d5b30f50b9e29beb2a7822289044"
		wantVIP   = "10.66.101.182"
	)

	if got := hex.EncodeToString(pub); got != wantEdPub {
		t.Fatalf("ed25519 public changed for the fixed seed:\n got=%s\nwant=%s", got, wantEdPub)
	}
	xpub, err := X25519FromEd25519Public(pub)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(xpub[:]); got != wantXPub {
		t.Fatalf("X25519 public derivation changed:\n got=%s\nwant=%s", got, wantXPub)
	}
	xpriv := X25519FromEd25519Private(priv)
	if got := hex.EncodeToString(xpriv[:]); got != wantXPriv {
		t.Fatalf("X25519 private derivation changed:\n got=%s\nwant=%s", got, wantXPriv)
	}
	if got := VirtualIPString(pub); got != wantVIP {
		t.Fatalf("virtual IP derivation changed:\n got=%s\nwant=%s", got, wantVIP)
	}

	// The clamping bits must hold regardless of the golden bytes: a valid X25519
	// scalar has the low 3 bits clear and the top two bits fixed (bit 254 set,
	// bit 255 clear). Guards the mapping even if the vectors are ever regenerated.
	if xpriv[0]&0b111 != 0 || xpriv[31]&0b1000_0000 != 0 || xpriv[31]&0b0100_0000 == 0 {
		t.Fatalf("X25519 private scalar is not correctly clamped: %x", xpriv)
	}
}
