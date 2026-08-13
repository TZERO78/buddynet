package role

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/pkg/protocol"
)

// testNode builds a buddy identity for the registration tests, pinned to a
// server key the tests also hold (so sealed tokens/codes can be opened).
func testNode(t *testing.T) (*node, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, srvPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	return &node{
		id:        randomID(),
		pub:       bcrypto.PubKeyB64(pub),
		vip:       bcrypto.VirtualIPString(pub),
		priv:      priv,
		serverPub: srvPriv.Public().(ed25519.PublicKey),
	}, srvPriv
}

// unmarshalRegister decodes a built registration and resolves its sealed token
// exactly as the server does, yielding the message the server actually verifies.
func unmarshalRegister(t *testing.T, raw []byte, srvPriv ed25519.PrivateKey) protocol.Message {
	t.Helper()
	m, ok := parseRegister(raw)
	if !ok {
		t.Fatalf("server rejected a self-built registration: %s", raw)
	}
	if !resolveToken(&m, srvPriv) {
		t.Fatal("server could not unseal the token of a self-built registration")
	}
	return m
}

// The core Phase 1 property: two ordinary polling attempts must differ in nonce,
// timestamp coverage and signature. Reusing one signed blob is exactly what made
// the server treat a buddy's own second poll as a replay.
func TestBuildRegisterIsFreshPerAttempt(t *testing.T) {
	nd, srvPriv := testNode(t)
	cfg := BuddyConfig{Name: "alice"}

	first, err := buildRegister(cfg, nd, "rendezvous", "")
	if err != nil {
		t.Fatalf("buildRegister: %v", err)
	}
	second, err := buildRegister(cfg, nd, "rendezvous", "")
	if err != nil {
		t.Fatalf("buildRegister: %v", err)
	}

	a := unmarshalRegister(t, first, srvPriv)
	b := unmarshalRegister(t, second, srvPriv)

	if a.Nonce == b.Nonce {
		t.Fatal("two registration attempts reused the same nonce")
	}
	if a.RegSig == b.RegSig {
		t.Fatal("two registration attempts reused the same signature")
	}
	if !protocol.ValidNonce(a.Nonce) || !protocol.ValidNonce(b.Nonce) {
		t.Fatalf("malformed nonces: %q %q", a.Nonce, b.Nonce)
	}
	for i, m := range []protocol.Message{a, b} {
		if !verifyRegistration(m, regSkew) {
			t.Fatalf("attempt %d did not verify server-side", i)
		}
	}
}

// A built registration must carry the sealed token on the wire (never the
// cleartext one) while signing the PLAINTEXT the server recovers, and must claim
// the virtual IP its own key derives.
func TestBuildRegisterSealsTokenAndBindsIdentity(t *testing.T) {
	nd, srvPriv := testNode(t)

	raw, err := buildRegister(BuddyConfig{Name: "alice"}, nd, "secret-rendezvous", "")
	if err != nil {
		t.Fatalf("buildRegister: %v", err)
	}
	var onWire protocol.Message
	if err := json.Unmarshal(raw, &onWire); err != nil {
		t.Fatal(err)
	}
	if onWire.Token != "" {
		t.Fatalf("cleartext token leaked onto the wire: %q", onWire.Token)
	}
	if onWire.TokenEnc == "" {
		t.Fatal("token was not sealed to the server key")
	}

	m := unmarshalRegister(t, raw, srvPriv)
	if m.Token != "secret-rendezvous" {
		t.Fatalf("unsealed token = %q, want the plaintext rendezvous", m.Token)
	}
	if m.VirtualIP != nd.vip {
		t.Fatalf("virtual ip = %q, want the key-derived %q", m.VirtualIP, nd.vip)
	}
	if !verifyRegistration(m, regSkew) {
		t.Fatal("signature does not cover the unsealed token")
	}
}

// The sealed enrollment code is covered by the signature, so a captured code
// cannot be lifted onto another key's registration.
func TestEnrollmentCodeIsBoundToTheSigningKey(t *testing.T) {
	victim, srvPriv := testNode(t)
	raw, err := buildRegister(BuddyConfig{Code: "ENROLL-ME"}, victim, "tok", "")
	if err != nil {
		t.Fatalf("buildRegister: %v", err)
	}
	captured := unmarshalRegister(t, raw, srvPriv)
	if captured.CodeEnc == "" {
		t.Fatal("no enrollment code was sealed")
	}

	// An attacker registers under ITS OWN key and grafts on the captured code.
	attacker, _ := testNode(t)
	attacker.serverPub = victim.serverPub
	rawAtk, err := buildRegister(BuddyConfig{}, attacker, "tok", "")
	if err != nil {
		t.Fatalf("buildRegister: %v", err)
	}
	graft := unmarshalRegister(t, rawAtk, srvPriv)
	graft.CodeEnc = captured.CodeEnc
	if verifyRegistration(graft, regSkew) {
		t.Fatal("an enrollment code grafted onto another key's registration was accepted")
	}
}

func mustBuild(t *testing.T, nd *node) []byte {
	t.Helper()
	raw, err := buildRegister(BuddyConfig{}, nd, "tok", "")
	if err != nil {
		t.Fatalf("buildRegister: %v", err)
	}
	return raw
}

// Approval mode end to end: the same key polling repeatedly is accepted every
// time (fresh nonce), while a verbatim replay of any one attempt is rejected.
func TestApprovalModePollingIsNotAReplay(t *testing.T) {
	nd, srvPriv := testNode(t)
	authz := newTestAuthorizer(t, srvPriv, nd.pub)
	reg := newHSRegistry(time.Minute)

	var last protocol.Message
	for i := 0; i < 5; i++ {
		m := unmarshalRegister(t, mustBuild(t, nd), srvPriv)
		if _, ok := pairRegister(reg, authz, "", v4(1000), m); !ok {
			t.Fatalf("poll %d of an allowlisted buddy was rejected — polling must not look like a replay", i)
		}
		last = m
	}
	if _, ok := pairRegister(reg, authz, "", v4(1000), last); ok {
		t.Fatal("a verbatim replay of a previous attempt must be rejected")
	}
}

// The two stacks of a dual-stacked server must not block each other: each
// datagram carries its own nonce, so the v6 copy of a tick is not the v4 copy's
// replay and BOTH source candidates get observed.
func TestDualStackAttemptsDoNotCollide(t *testing.T) {
	nd, srvPriv := testNode(t)
	authz := newTestAuthorizer(t, srvPriv, nd.pub)
	reg := newHSRegistry(time.Minute)

	over4 := unmarshalRegister(t, mustBuild(t, nd), srvPriv)
	over6 := unmarshalRegister(t, mustBuild(t, nd), srvPriv)
	if over4.Nonce == over6.Nonce {
		t.Fatal("the v4 and v6 datagrams of one tick shared a nonce")
	}
	if _, ok := pairRegister(reg, authz, "", v4(1000), over4); !ok {
		t.Fatal("the IPv4 registration was rejected")
	}
	if _, ok := pairRegister(reg, authz, "", v6(1000), over6); !ok {
		t.Fatal("the IPv6 registration was rejected — the two stacks blocked each other")
	}
	self, _, ok := reg.upsert(over4, v4(1000))
	if !ok || len(self.cands) < 2 {
		t.Fatalf("server learned %d candidates, want both stacks", len(self.cands))
	}
}

// The server derives the virtual IP from the public key and refuses a
// registration that claims a different one (identity IS address).
func TestServerRejectsInconsistentVirtualIP(t *testing.T) {
	nd, srvPriv := testNode(t)
	authz := newTestAuthorizer(t, srvPriv, nd.pub)

	m := unmarshalRegister(t, mustBuild(t, nd), srvPriv)
	m.VirtualIP = "10.66.200.201"
	// Re-sign so the ONLY thing wrong is the claim itself, not the signature.
	m.RegSig = base64.StdEncoding.EncodeToString(ed25519.Sign(nd.priv, protocol.RegistrationPayload(m)))
	if !verifyRegistration(m, regSkew) {
		t.Fatal("test setup: the re-signed message should verify")
	}
	if _, ok := pairRegister(newHSRegistry(time.Minute), authz, "", v4(1000), m); ok {
		t.Fatal("a registration claiming a virtual IP its key does not derive was accepted")
	}
}

// An old client must be told it is incompatible rather than dropped in silence —
// and must NOT be served under the pre-v7 signature rules.
func TestIncompatibleClientGetsAClearAnswer(t *testing.T) {
	nd, srvPriv := testNode(t)
	raw := mustBuild(t, nd)

	var m protocol.Message
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m.Ver = protocol.Version - 1
	old, _ := json.Marshal(m)

	parsed, ok := parseRegister(old)
	if !ok {
		t.Fatal("structural parsing must still succeed so the version can be reported")
	}
	if parsed.Ver == protocol.Version {
		t.Fatal("test setup: the message should carry the old version")
	}
	// The reply the server sends carries OUR version, which is what the buddy
	// compares before it looks at the roster or its signature.
	reply := replyIncompatible()
	if reply.Ver != protocol.Version || reply.Type != protocol.TypePeerList {
		t.Fatalf("incompatibility reply = %+v, want an empty v%d PEER_LIST", reply, protocol.Version)
	}
	if len(reply.Peers) != 0 || reply.Sig != "" {
		t.Fatal("the incompatibility reply must leak no roster and no signature")
	}
	// Nothing about the old message may be honoured: its signature does not cover
	// the v7 payload, so it cannot verify.
	if resolveToken(&parsed, srvPriv) && verifyRegistration(parsed, regSkew) {
		t.Fatal("a pre-v7 registration signature must not verify under v7 rules")
	}
}

func newTestAuthorizer(t *testing.T, srvPriv ed25519.PrivateKey, keys ...string) *authorizer {
	t.Helper()
	path := t.TempDir() + "/authorized"
	var body string
	for _, k := range keys {
		body += k + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := newAuthorizer(path, srvPriv)
	if err != nil {
		t.Fatalf("newAuthorizer: %v", err)
	}
	return a
}
