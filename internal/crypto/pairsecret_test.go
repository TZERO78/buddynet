package crypto

import (
	"bytes"
	"crypto/ed25519"
	"testing"
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
