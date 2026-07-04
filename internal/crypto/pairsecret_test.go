package crypto

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestPairSecretSymmetricAndStable(t *testing.T) {
	aPub, aPriv, _ := ed25519.GenerateKey(nil)
	bPub, bPriv, _ := ed25519.GenerateKey(nil)

	ab, err := PairSecret(aPriv, bPub)
	if err != nil {
		t.Fatal(err)
	}
	ba, err := PairSecret(bPriv, aPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ab, ba) {
		t.Fatalf("not symmetric:\n a->b=%x\n b->a=%x", ab, ba)
	}
	if len(ab) != 32 {
		t.Fatalf("want 32 bytes, got %d", len(ab))
	}
	// Deterministic across calls (stable rendezvous token).
	again, _ := PairSecret(aPriv, bPub)
	if !bytes.Equal(ab, again) {
		t.Fatal("not deterministic across calls")
	}
}

// TestPairSecretNeverExposesRawDH is the domain-separation guard for the reviewed
// key-reuse (see x25519.go "Key reuse across protocols" and SECURITY.md "One key,
// many roles"). The single identity-derived X25519 key is shared across protocols;
// the safety argument depends on every consumer post-processing the raw DH through
// a LABELLED KDF instead of using it directly. This test fails if PairSecret ever
// regresses to returning (a prefix of) the bare curve25519 shared secret — the
// exact change that would weaken the domain separation the reuse relies on.
func TestPairSecretNeverExposesRawDH(t *testing.T) {
	aPub, aPriv, _ := ed25519.GenerateKey(nil)
	bPub, bPriv, _ := ed25519.GenerateKey(nil)

	secret, err := PairSecret(aPriv, bPub)
	if err != nil {
		t.Fatal(err)
	}

	// The raw static-static DH the labelled HKDF is fed with, computed directly.
	aScalar := X25519FromEd25519Private(aPriv)
	bX, err := X25519FromEd25519Public(bPub)
	if err != nil {
		t.Fatal(err)
	}
	rawDH, err := curve25519.X25519(aScalar[:], bX[:])
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(secret, rawDH) {
		t.Fatal("PairSecret returned the bare DH secret — the labelled KDF was bypassed")
	}
	if bytes.HasPrefix(rawDH, secret) || bytes.HasPrefix(secret, rawDH) {
		t.Fatal("PairSecret output overlaps the raw DH — domain separation is not intact")
	}

	// Sanity: the same DH under the other party's view still yields the SAME
	// labelled secret (symmetry), so the guard above is not just catching asymmetry.
	if again, _ := PairSecret(bPriv, aPub); !bytes.Equal(secret, again) {
		t.Fatal("labelled secret is not symmetric")
	}
}

func TestPairSecretDistinctPerPair(t *testing.T) {
	_, aPriv, _ := ed25519.GenerateKey(nil)
	bPub, _, _ := ed25519.GenerateKey(nil)
	cPub, _, _ := ed25519.GenerateKey(nil)

	ab, _ := PairSecret(aPriv, bPub)
	ac, _ := PairSecret(aPriv, cPub)
	if bytes.Equal(ab, ac) {
		t.Fatal("secret must differ for different partners")
	}
}
