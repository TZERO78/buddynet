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
	base := Message{Ver: Version, Role: RoleBuddy, Token: "t", ID: "id", PubKey: "pk",
		VirtualIP: "10.66.1.2", Name: "alice", Ts: 7, Nonce: "nnnn", CodeEnc: "ce"}
	a := RegistrationPayload(base)
	if string(a) != string(RegistrationPayload(base)) {
		t.Fatal("registration payload not reproducible")
	}
	// Every field the server acts on must change the signed bytes, so none of them
	// can be altered in flight under a captured signature.
	for name, mutate := range map[string]func(m *Message){
		"ver":        func(m *Message) { m.Ver++ },
		"role":       func(m *Message) { m.Role = RoleRelay },
		"token":      func(m *Message) { m.Token = "t2" },
		"id":         func(m *Message) { m.ID = "id2" },
		"pubkey":     func(m *Message) { m.PubKey = "pk2" },
		"virtual ip": func(m *Message) { m.VirtualIP = "10.66.3.4" },
		"name":       func(m *Message) { m.Name = "mallory" },
		"ts":         func(m *Message) { m.Ts++ },
		"nonce":      func(m *Message) { m.Nonce = "mmmm" },
		"code_enc":   func(m *Message) { m.CodeEnc = "ce2" },
	} {
		t.Run(name, func(t *testing.T) {
			m := base
			mutate(&m)
			if string(RegistrationPayload(m)) == string(a) {
				t.Fatalf("%s must affect the signed bytes", name)
			}
		})
	}
}

func TestNonceRoundTripAndValidation(t *testing.T) {
	n, err := NewNonce()
	if err != nil {
		t.Fatalf("NewNonce: %v", err)
	}
	if !ValidNonce(n) {
		t.Fatalf("a freshly minted nonce must validate: %q", n)
	}
	other, _ := NewNonce()
	if other == n {
		t.Fatal("two nonces collided — not random")
	}
	for name, bad := range map[string]string{
		"empty":          "",
		"too short":      n[:len(n)-1],
		"too long":       n + "A",
		"bad alphabet":   "!!!!!!!!!!!!!!!!!!!!!!",
		"std base64 pad": "AAAAAAAAAAAAAAAAAAAAA=",
	} {
		t.Run(name, func(t *testing.T) {
			if ValidNonce(bad) {
				t.Fatalf("malformed nonce %q accepted", bad)
			}
		})
	}
}
