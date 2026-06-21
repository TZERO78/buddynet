package crypto

import (
	"bytes"
	"crypto/ed25519"
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
