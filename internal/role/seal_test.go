package role

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/pkg/protocol"
)

// A sealed pairing token must round-trip through the server unsealer to the same
// value, and the cleartext token must never appear in the REGISTER bytes.
func TestSealedTokenRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	const token = "super-secret-rendezvous"
	enc, err := bcrypto.SealCode(token, pub)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	raw, _ := json.Marshal(protocol.Message{
		Type: protocol.TypeRegister, Ver: protocol.Version,
		TokenEnc: enc, ID: "id1", PubKey: "k",
	})
	if bytes.Contains(raw, []byte(token)) {
		t.Fatal("cleartext token leaked into the REGISTER bytes")
	}

	m, ok := parseRegister(raw)
	if !ok {
		t.Fatal("parseRegister rejected a valid sealed register")
	}
	if m.Token != "" {
		t.Fatal("sealed register must carry no cleartext Token before unseal")
	}
	if !resolveToken(&m, priv) {
		t.Fatal("resolveToken failed on a valid sealed token")
	}
	if m.Token != token {
		t.Fatalf("unsealed token = %q, want %q", m.Token, token)
	}
	if m.TokenEnc != "" {
		t.Fatal("TokenEnc must be cleared after unseal")
	}
}

func TestSealedTokenRejectsGarbage(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw, _ := json.Marshal(protocol.Message{
		Type: protocol.TypeRegister, Ver: protocol.Version,
		TokenEnc: "not-a-sealed-blob", ID: "id1",
	})
	m, ok := parseRegister(raw)
	if !ok {
		t.Fatal("parseRegister should accept the structural form")
	}
	if resolveToken(&m, priv) {
		t.Fatal("resolveToken must reject an undecryptable sealed token")
	}
}

// A plaintext token (legacy buddy) still works (server backward-compat), and a
// register carrying BOTH forms is rejected.
func TestTokenFormsValidation(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	plain, _ := json.Marshal(protocol.Message{
		Type: protocol.TypeRegister, Ver: protocol.Version, Token: "plain-tok", ID: "id1",
	})
	m, ok := parseRegister(plain)
	if !ok || !resolveToken(&m, priv) || m.Token != "plain-tok" {
		t.Fatal("plaintext token (legacy) must still pass")
	}

	both, _ := json.Marshal(protocol.Message{
		Type: protocol.TypeRegister, Ver: protocol.Version, Token: "p", TokenEnc: "e", ID: "id1",
	})
	if _, ok := parseRegister(both); ok {
		t.Fatal("a register with BOTH Token and TokenEnc must be rejected")
	}
}
