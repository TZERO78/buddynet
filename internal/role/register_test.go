package role

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
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

// The cookie is attached but NOT signed: it is verified against the server's own
// HMAC key and the source IP, so it must not disturb the signature — and the
// post-challenge retry must still be a fresh, independently valid registration.
func TestCookieRetryIsAFreshSignedRegistration(t *testing.T) {
	nd, srvPriv := testNode(t)
	cookieKey = deriveSubkey(srvPriv.Seed(), "buddynet-cookie-v1")
	ip := net.IPv4(198, 51, 100, 7)

	challenged := unmarshalRegister(t, mustBuild(t, nd, ""), srvPriv)
	if challenged.Cookie != "" {
		t.Fatal("the first attempt should carry no cookie")
	}

	retry := unmarshalRegister(t, mustBuild(t, nd, freshCookie(ip)), srvPriv)
	if !validCookie(retry.Cookie, ip) {
		t.Fatal("the retry did not carry a valid address-validation cookie")
	}
	if retry.Nonce == challenged.Nonce {
		t.Fatal("the post-challenge retry reused the challenged attempt's nonce")
	}
	if !verifyRegistration(retry, regSkew) {
		t.Fatal("the post-challenge retry is not validly signed")
	}
	// Swapping the cookie must NOT break the signature (it is deliberately outside
	// the signed payload) — the server checks it against its own key instead.
	retry.Cookie = freshCookie(net.IPv4(203, 0, 113, 9))
	if !verifyRegistration(retry, regSkew) {
		t.Fatal("the cookie must not be part of the signed payload")
	}
}

func mustBuild(t *testing.T, nd *node, cookie string) []byte {
	t.Helper()
	raw, err := buildRegister(BuddyConfig{}, nd, "tok", cookie)
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
		m := unmarshalRegister(t, mustBuild(t, nd, ""), srvPriv)
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

	over4 := unmarshalRegister(t, mustBuild(t, nd, ""), srvPriv)
	over6 := unmarshalRegister(t, mustBuild(t, nd, ""), srvPriv)
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

	m := unmarshalRegister(t, mustBuild(t, nd, ""), srvPriv)
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
	raw := mustBuild(t, nd, "")

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

// A REGISTER from an unvalidated source must be answered with a cookie challenge
// BEFORE the server spends an X25519 unseal on its sealed token. If the order
// were reversed, a flood of garbage TokenEnc blobs from spoofed sources would buy
// an attacker one asymmetric operation per packet — so a packet whose TokenEnc is
// deliberately undecryptable must still get a challenge, not be dropped.
func TestCookieIsCheckedBeforeTokenDecryption(t *testing.T) {
	srvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srvConn.Close()
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	cookieKey = deriveSubkey(srvPriv.Seed(), "buddynet-cookie-v1")
	tokenLogKey = deriveSubkey(srvPriv.Seed(), "buddynet-logtag-v1")

	reg := newHSRegistry(time.Minute)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, rerr := srvConn.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			raw := append([]byte(nil), buf[:n]...)
			handleRegister(srvConn, reg, srvPriv, nil, "", src, raw)
		}
	}()

	cli, err := net.DialUDP("udp", nil, srvConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	// A structurally valid REGISTER whose sealed token is pure garbage.
	nd, _ := testNode(t)
	m := protocol.Message{
		Type:     protocol.TypeRegister,
		Ver:      protocol.Version,
		Role:     protocol.RoleBuddy,
		ID:       nd.id,
		PubKey:   nd.pub,
		TokenEnc: base64.StdEncoding.EncodeToString([]byte("this will never decrypt")),
		Ts:       time.Now().Unix(),
	}
	raw, _ := json.Marshal(m)
	if _, err := cli.Write(raw); err != nil {
		t.Fatal(err)
	}

	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, err := cli.Read(buf)
	if err != nil {
		t.Fatal("no cookie challenge: the server decrypted (and dropped on) the token before validating the source")
	}
	var reply protocol.Message
	if err := json.Unmarshal(buf[:n], &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Type != protocol.TypeCookie || reply.Cookie == "" {
		t.Fatalf("got %+v, want a COOKIE challenge", reply)
	}
	if n >= len(raw) {
		t.Fatalf("the challenge (%d B) must be smaller than the request (%d B) — never an amplifier", n, len(raw))
	}
}

// Nothing behind the cookie may run for an unvalidated source — including the
// approval-mode work: no signature verify, and above all no X25519 open of the
// sealed ENROLLMENT CODE, which would otherwise let a spoofed source both spend
// asymmetric crypto and grow the pending database.
func TestUnvalidatedSourceReachesNoApprovalModeWork(t *testing.T) {
	srvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srvConn.Close()

	nd, srvPriv := testNode(t)
	authz := newTestAuthorizer(t, srvPriv) // empty allowlist: nd would enroll
	cookieKey = deriveSubkey(srvPriv.Seed(), "buddynet-cookie-v1")
	tokenLogKey = deriveSubkey(srvPriv.Seed(), "buddynet-logtag-v1")

	reg := newHSRegistry(time.Minute)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, rerr := srvConn.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			handleRegister(srvConn, reg, srvPriv, authz, "", src, append([]byte(nil), buf[:n]...))
		}
	}()

	cli, err := net.DialUDP("udp", nil, srvConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	// A fully valid registration with a real enrollment code — but NO cookie.
	const code = "WOULD-BE-PENDING"
	raw, err := buildRegister(BuddyConfig{Code: code}, nd, "tok", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Write(raw); err != nil {
		t.Fatal(err)
	}

	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, err := cli.Read(buf)
	if err != nil {
		t.Fatalf("expected a cookie challenge: %v", err)
	}
	var reply protocol.Message
	if err := json.Unmarshal(buf[:n], &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Type != protocol.TypeCookie {
		t.Fatalf("got %s, want a COOKIE challenge", reply.Type)
	}
	authz.mu.RLock()
	pending := len(authz.pend)
	authz.mu.RUnlock()
	if pending != 0 {
		t.Fatal("an unvalidated source got its enrollment code decrypted and pended")
	}

	// With the cookie echoed, the very same client DOES reach the enrollment path —
	// so the check above failed on validation, not on something incidental.
	withCookie, err := buildRegister(BuddyConfig{Code: code}, nd, "tok", reply.Cookie)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Write(withCookie); err != nil {
		t.Fatal(err)
	}
	if !waitFor(t, 3*time.Second, func() bool {
		authz.mu.RLock()
		defer authz.mu.RUnlock()
		_, ok := authz.pend[shortHash(code)]
		return ok
	}) {
		t.Fatal("positive control failed: a cookie-validated enrollment never reached the app layer")
	}
}

// newTestAuthorizer builds an approval-mode authorizer allowing exactly keys.
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
