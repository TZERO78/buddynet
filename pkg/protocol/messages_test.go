package protocol

import (
	"crypto/ed25519"
	"testing"
)

// TestPeerListPayloadStable guards the property the whole MITM defense rests on:
// signer and verifier must produce byte-identical payloads for the same logical
// roster, and any change to the roster must change the bytes.
func TestPeerListPayloadStable(t *testing.T) {
	peers := []Peer{{ID: "a", PubKey: "k", VirtualIP: "10.66.0.5"}}
	p1 := PeerListPayload("tok", 1234, peers)
	p2 := PeerListPayload("tok", 1234, peers)
	if string(p1) != string(p2) {
		t.Fatal("payload not reproducible")
	}
	if string(PeerListPayload("other", 1234, peers)) == string(p1) {
		t.Fatal("token must affect the signed bytes")
	}
	if string(PeerListPayload("tok", 9999, peers)) == string(p1) {
		t.Fatal("timestamp must affect the signed bytes")
	}
}

func TestPeerListSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	peers := []Peer{{ID: "a", PubKey: "k"}}
	payload := PeerListPayload("tok", 42, peers)
	sig := ed25519.Sign(priv, payload)
	if !ed25519.Verify(pub, payload, sig) {
		t.Fatal("valid signature did not verify")
	}
	// A tampered roster must fail verification.
	tampered := PeerListPayload("tok", 42, []Peer{{ID: "a", PubKey: "evil"}})
	if ed25519.Verify(pub, tampered, sig) {
		t.Fatal("tampered roster verified — MITM defense broken")
	}
}

func TestRegistrationPayloadStable(t *testing.T) {
	a := RegistrationPayload("t", "id", "pk", 7)
	b := RegistrationPayload("t", "id", "pk", 7)
	if string(a) != string(b) {
		t.Fatal("registration payload not reproducible")
	}
	if string(RegistrationPayload("t", "id2", "pk", 7)) == string(a) {
		t.Fatal("id must affect the signed bytes")
	}
}
