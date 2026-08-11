package role

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
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

// Sealing the pairing token or the enrollment code must FAIL CLOSED. Both used to
// degrade silently: setToken fell back to the cleartext field — putting the token
// on the wire unencrypted exactly when something was already wrong — and a
// code that would not seal was simply dropped, leaving the operator waiting for a
// `pending` line that could never appear.
//
// A truncated server key cannot be decoded as an Ed25519 point, so SealCode
// fails — the one reliable way to reach the error path. (An all-zero or all-0xFF
// key does NOT fail: both decode to a point. That is why this test carries a hard
// assertion instead of a t.Skip — a skip would silently stop testing anything the
// day the failure mode changes.)
func TestSealingFailuresFailClosed(t *testing.T) {
	nd, _ := testNode(t)
	nd.serverPub = make(ed25519.PublicKey, 16) // too short to be a point
	if _, err := bcrypto.SealCode("x", nd.serverPub); err == nil {
		t.Fatal("test setup is broken: SealCode must fail for this key, or the test proves nothing")
	}

	raw, err := buildRegister(BuddyConfig{}, nd, "rendezvous", "")
	if err == nil {
		var m protocol.Message
		_ = json.Unmarshal(raw, &m)
		t.Fatalf("a registration was built despite an unsealable token (Token=%q TokenEnc=%q) — "+
			"the cleartext fallback is back", m.Token, m.TokenEnc)
	}

	// The code is sealed BEFORE the token, so with --code the failure must name the
	// CODE. Asserting only "some error" would be satisfied by the token failure that
	// follows anyway, and a silently dropped code would slip through.
	_, cerr := buildRegister(BuddyConfig{Code: "ENROLL-ME"}, nd, "rendezvous", "")
	if cerr == nil {
		t.Fatal("a registration was built despite an unsealable enrollment code")
	}
	if !strings.Contains(cerr.Error(), "enrollment code") {
		t.Fatalf("the enrollment code was dropped silently and the registration failed for another "+
			"reason instead (%v) — the operator would wait for a `pending` line that never comes", cerr)
	}
}
