package role

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/pkg/protocol"
)

func TestAuthorizerApproveListRevoke(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key := base64.StdEncoding.EncodeToString(pub)

	// Missing file = empty allowlist, not an error.
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	a, err := newAuthorizer(path, srvPriv)
	if err != nil {
		t.Fatalf("newAuthorizer: %v", err)
	}
	if a.allowed(key) {
		t.Fatal("key allowed before approval")
	}

	if err := ApproveKey(path, key, "laptop"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := a.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !a.allowed(key) {
		t.Fatal("key not allowed after approval")
	}

	if err := RevokeKey(path, key); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := a.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if a.allowed(key) {
		t.Fatal("key still allowed after revoke")
	}
}

func TestEnrollByCodeFlow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized")
	srvPub, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientPub, _, _ := ed25519.GenerateKey(rand.Reader)
	clientKey := base64.StdEncoding.EncodeToString(clientPub)

	a, err := newAuthorizer(path, srvPriv)
	if err != nil {
		t.Fatalf("newAuthorizer: %v", err)
	}

	// Client seals its enrollment code to the server identity; server records it.
	enc, err := bcrypto.SealCode("ab56fe2", srvPub)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	a.recordPending(enc, clientKey)
	// The pending DB must store a HASH of the code, never the plaintext.
	if data, _ := os.ReadFile(path + ".pending"); strings.Contains(string(data), "ab56fe2") {
		t.Fatal("pending DB leaks the plaintext enrollment code")
	} else if !strings.Contains(string(data), shortHash("ab56fe2")) {
		t.Fatal("pending DB does not contain the code hash")
	}
	// First-come-wins: a different key with the same code is ignored.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	a.recordPending(enc, base64.StdEncoding.EncodeToString(otherPub))

	if a.allowed(clientKey) {
		t.Fatal("client allowed before approval")
	}
	// Operator approves by the short code.
	if err := AllowClient(path, "ab56fe2"); err != nil {
		t.Fatalf("allowClient: %v", err)
	}
	if err := a.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !a.allowed(clientKey) {
		t.Fatal("client not allowed after allowClient")
	}
	// Wrong code approves nobody.
	if err := AllowClient(path, "nope12"); err == nil {
		t.Fatal("allowClient with unknown code should error")
	}
}

func TestApproveRejectsBadKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized")
	if err := ApproveKey(path, "not-a-valid-key", ""); err == nil {
		t.Fatal("approve should reject a malformed key")
	}
}

func TestVerifyRegistration(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	signed := func(token, id string, ts int64, signer ed25519.PrivateKey) protocol.Message {
		sig := ed25519.Sign(signer, protocol.RegistrationPayload(token, id, pubB64, ts))
		return protocol.Message{Type: protocol.TypeRegister, Token: token, ID: id, PubKey: pubB64, Ts: ts, RegSig: base64.StdEncoding.EncodeToString(sig)}
	}

	if !verifyRegistration(signed("tok", "A", time.Now().Unix(), priv), time.Minute) {
		t.Fatal("valid registration rejected")
	}
	// Tampered token invalidates the signature.
	bad := signed("tok", "A", time.Now().Unix(), priv)
	bad.Token = "other"
	if verifyRegistration(bad, time.Minute) {
		t.Fatal("tampered token accepted")
	}
	// Stale timestamp rejected.
	if verifyRegistration(signed("tok", "A", time.Now().Add(-5*time.Minute).Unix(), priv), time.Minute) {
		t.Fatal("stale registration accepted")
	}
	// Signature by a different key (claiming pubB64 without owning it) rejected.
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	if verifyRegistration(signed("tok", "A", time.Now().Unix(), attacker), time.Minute) {
		t.Fatal("forged signature accepted")
	}
}
