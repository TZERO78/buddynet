package role

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/tzero78/buddynet/pkg/protocol"
)

// These are the adversarial counterparts to the happy-path signature tests: the
// key-ownership proof on the control plane (approval mode) is the load-bearing
// trust decision, so every way an attacker can hand it a tampered or malformed
// REGISTER must be REJECTED. A regression that made verifyRegistration accept any
// of these would let a non-owner register someone else's identity.

// signedRegister builds a Message whose RegSig is a valid key-ownership proof, so
// each test below can then tamper with exactly one field and confirm rejection.
func signedRegister(t *testing.T) (protocol.Message, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := signReg(t, priv, protocol.Message{
		Type:      protocol.TypeRegister,
		Role:      protocol.RoleBuddy,
		Token:     "rendezvous-token",
		ID:        "buddy-a",
		PubKey:    base64.StdEncoding.EncodeToString(pub),
		VirtualIP: "10.66.7.8",
		Name:      "buddy-a-name",
		Ts:        time.Now().Unix(),
	})
	return m, priv
}

func TestVerifyRegistrationAcceptsValidProof(t *testing.T) {
	m, _ := signedRegister(t)
	if !verifyRegistration(m, time.Minute) {
		t.Fatal("a correctly signed REGISTER was rejected")
	}
}

func TestVerifyRegistrationRejectsTampering(t *testing.T) {
	// Each case takes a freshly signed, valid REGISTER and mutates it so the
	// reconstructed payload or the signature no longer matches. All must fail.
	cases := map[string]func(m *protocol.Message){
		"flipped signature byte": func(m *protocol.Message) {
			sig, _ := base64.StdEncoding.DecodeString(m.RegSig)
			sig[0] ^= 0x01
			m.RegSig = base64.StdEncoding.EncodeToString(sig)
		},
		"flipped signature last byte": func(m *protocol.Message) {
			sig, _ := base64.StdEncoding.DecodeString(m.RegSig)
			sig[len(sig)-1] ^= 0x80
			m.RegSig = base64.StdEncoding.EncodeToString(sig)
		},
		"truncated signature": func(m *protocol.Message) {
			sig, _ := base64.StdEncoding.DecodeString(m.RegSig)
			m.RegSig = base64.StdEncoding.EncodeToString(sig[:len(sig)-1])
		},
		"empty signature":      func(m *protocol.Message) { m.RegSig = "" },
		"signature not base64": func(m *protocol.Message) { m.RegSig = "!!!not-base64!!!" },
		"tampered ID":          func(m *protocol.Message) { m.ID = "buddy-evil" },
		"tampered token":       func(m *protocol.Message) { m.Token = "other-token" },
		"tampered timestamp":   func(m *protocol.Message) { m.Ts++ },
		"tampered version":     func(m *protocol.Message) { m.Ver++ },
		"tampered role":        func(m *protocol.Message) { m.Role = protocol.RoleRelay },
		"tampered virtual ip":  func(m *protocol.Message) { m.VirtualIP = "10.66.9.9" },
		"tampered name":        func(m *protocol.Message) { m.Name = "impostor" },
		"injected code":        func(m *protocol.Message) { m.CodeEnc = "grafted-enrollment-code" },
		"swapped nonce": func(m *protocol.Message) {
			n, _ := protocol.NewNonce()
			m.Nonce = n
		},
		"dropped nonce":     func(m *protocol.Message) { m.Nonce = "" },
		"pubkey not base64": func(m *protocol.Message) { m.PubKey = "@@@" },
		"pubkey wrong length": func(m *protocol.Message) {
			m.PubKey = base64.StdEncoding.EncodeToString([]byte("too-short"))
		},
		"substituted attacker key": func(m *protocol.Message) {
			// The classic attack: keep a valid self-signature but swap in a DIFFERENT
			// identity's public key. The proof must bind to the claimed key, so the
			// signature (made by the original key) must no longer verify.
			otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
			m.PubKey = base64.StdEncoding.EncodeToString(otherPub)
			// re-sign with a key that is NOT otherPub's private key -> still invalid
			_ = otherPriv
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m, _ := signedRegister(t)
			mutate(&m)
			if verifyRegistration(m, time.Minute) {
				t.Fatalf("tampered REGISTER (%s) was accepted", name)
			}
		})
	}
}

func TestVerifyRegistrationRejectsStaleAndFuture(t *testing.T) {
	// A signature over a stale (or far-future) timestamp is cryptographically
	// valid but must still be refused: the freshness window is what stops an old,
	// captured REGISTER from being replayed.
	skew := time.Minute
	for name, delta := range map[string]time.Duration{
		"too old":    -2 * time.Minute,
		"too future": 2 * time.Minute,
	} {
		t.Run(name, func(t *testing.T) {
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			m := signReg(t, priv, protocol.Message{
				Type:   protocol.TypeRegister,
				Token:  "rendezvous-token",
				ID:     "buddy-a",
				PubKey: base64.StdEncoding.EncodeToString(pub),
				Ts:     time.Now().Add(delta).Unix(),
			})
			if verifyRegistration(m, skew) {
				t.Fatalf("%s REGISTER (still validly signed) was accepted", name)
			}
		})
	}
}
