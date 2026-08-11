package role

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tzero78/buddynet/pkg/protocol"
)

// T-3: freshSinceApproval is the SECOND line of defence at the approval
// transition, behind the pre-auth nonce cache. Because the cache catches both
// scenarios the end-to-end tests drive, removing this check entirely left every
// test green — so it was shipped untested. Drive it directly.
func TestFreshSinceApprovalRejectsPreApprovalTimestamps(t *testing.T) {
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "authorized")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := newAuthorizer(path, srvPriv)
	if err != nil {
		t.Fatal(err)
	}

	const key = "some-key"
	// A fixed instant with a sub-second component, because that is exactly what the
	// one-second slack exists for: REGISTER timestamps are unix SECONDS.
	approvedAt := time.Unix(1_700_000_000, 500_000_000)
	a.mu.Lock()
	a.keys[key] = ""
	a.approvedAt[key] = approvedAt
	a.mu.Unlock()

	// A registration minted well before the approval: refused.
	if a.freshSinceApproval(key, approvedAt.Add(-30*time.Second).Unix()) {
		t.Error("a registration timestamped 30s before the approval was accepted")
	}
	// One minted after it: accepted.
	if !a.freshSinceApproval(key, approvedAt.Add(5*time.Second).Unix()) {
		t.Error("a registration timestamped after the approval was refused")
	}
	// Unix SECONDS on the wire: a client that mints its registration in the SAME
	// second as the approval reports a timestamp that truncates to just before it.
	// The one-second slack absorbs that rather than refusing an honest client's
	// first attempt after being approved.
	if !a.freshSinceApproval(key, approvedAt.Truncate(time.Second).Unix()) {
		t.Error("a registration minted in the same second as the approval was refused — " +
			"the one-second slack for second-resolution timestamps is gone")
	}
	// But the slack is ONE second, not a free window: the previous second is out.
	if a.freshSinceApproval(key, approvedAt.Truncate(time.Second).Add(-2*time.Second).Unix()) {
		t.Error("a registration two seconds before the approval was accepted — the slack is too wide")
	}

	// A key the process INHERITED at startup carries no approval moment: no
	// transition happened here, and constraining it would only punish clock-skewed
	// clients after every restart.
	const inherited = "startup-key"
	a.mu.Lock()
	a.keys[inherited] = ""
	a.approvedAt[inherited] = time.Time{}
	a.mu.Unlock()
	if !a.freshSinceApproval(inherited, time.Now().Add(-time.Hour).Unix()) {
		t.Error("a key inherited at startup must be unconstrained")
	}
}

// T-5: the nonce must be strictly well-formed before it becomes a replay-cache
// key. verifyRegistration enforces it, but nothing asserted that — removing the
// check left every test green.
func TestVerifyRegistrationRequiresAWellFormedNonce(t *testing.T) {
	nd, _ := testNode(t)
	base := signReg(t, nd.priv, protocol.Message{
		Type: protocol.TypeRegister, Token: "tok", ID: nd.id, PubKey: nd.pub,
	})
	if !verifyRegistration(base, regSkew) {
		t.Fatal("setup: the baseline registration must verify")
	}

	for name, nonce := range map[string]string{
		"empty":          "",
		"too short":      "AAAA",
		"too long":       base.Nonce + "AA",
		"not base64url":  "!!!!!!!!!!!!!!!!!!!!!!",
		"padded base64":  "AAAAAAAAAAAAAAAAAAAAA=",
		"right length,+": "AAAAAAAAAAAAAAAAAAAA+A",
	} {
		m := base
		m.Nonce = nonce
		// Re-sign, so the ONLY thing wrong is the nonce itself: a test that let the
		// signature break would pass for the wrong reason.
		m = signRegKeepingNonce(t, nd.priv, m)
		if verifyRegistration(m, regSkew) {
			t.Errorf("%s nonce (%q) was accepted", name, nonce)
		}
	}
}

// signRegKeepingNonce signs m WITHOUT replacing its nonce, so a test can present
// a malformed nonce under a valid signature.
func signRegKeepingNonce(t *testing.T, priv ed25519.PrivateKey, m protocol.Message) protocol.Message {
	t.Helper()
	if m.Ts == 0 {
		m.Ts = time.Now().Unix()
	}
	m.RegSig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, protocol.RegistrationPayload(m)))
	return m
}
