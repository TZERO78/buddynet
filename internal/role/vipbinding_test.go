package role

import (
	"bytes"
	"crypto/ed25519"
	"log"
	"strings"
	"testing"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/pkg/protocol"
)

// The buddy-side VIP↔key check had no test of its own: the live lab
// (lab/test-wg-vip.sh) cannot reach it, because the handshake server derives the
// virtual IP itself and drops a registration that claims a different one — a
// hostile PEER can never get a forged VIP into the roster. The check exists for
// the hostile-or-buggy SERVER, and that is what these tests stand in for.

func mustKey(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, bcrypto.PubKeyB64(pub)
}

func TestCheckPartnerVIPRejectsForgedVIP(t *testing.T) {
	pub, b64 := mustKey(t)
	derived := bcrypto.VirtualIPString(pub)

	var logs bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(old)

	err := checkPartnerVIP(protocol.Peer{PubKey: b64, VirtualIP: "10.66.0.1"}, pub)
	if err == nil {
		t.Fatal("a roster claiming a VIP the key does not derive was accepted")
	}
	if !strings.Contains(err.Error(), "does not match its key") {
		t.Fatalf("error should name the mismatch, got: %v", err)
	}
	if !strings.Contains(err.Error(), derived) {
		t.Fatalf("error should name the VIP the key derives (%s), got: %v", derived, err)
	}
	// The operator-visible signal is a SECURITY event at the detection point.
	if got := logs.String(); !strings.Contains(got, "SECURITY: event=vip-mismatch") {
		t.Fatalf("no vip-mismatch SECURITY event logged, got: %q", got)
	}
}

func TestCheckPartnerVIPAcceptsDerivedVIP(t *testing.T) {
	pub, b64 := mustKey(t)
	p := protocol.Peer{PubKey: b64, VirtualIP: bcrypto.VirtualIPString(pub)}
	if err := checkPartnerVIP(p, pub); err != nil {
		t.Fatalf("the key's own derived VIP was rejected: %v", err)
	}
}

// An absent VirtualIP carries no claim, so it is not a mismatch — everything
// load-bearing (the WG peer address, the route) is derived from the key anyway.
// Pinned deliberately: a future change that starts treating "" as a claim would
// break rosters from a server that omits the field.
func TestCheckPartnerVIPAllowsAbsentVIP(t *testing.T) {
	pub, b64 := mustKey(t)
	if err := checkPartnerVIP(protocol.Peer{PubKey: b64}, pub); err != nil {
		t.Fatalf("absent VirtualIP treated as a mismatch: %v", err)
	}
}

// A forged VIP that happens to be the VIP of ANOTHER key is the interesting
// variant: it is well-formed and belongs to a real identity, so only the
// comparison against THIS partner's key catches it.
func TestCheckPartnerVIPRejectsAnotherKeysVIP(t *testing.T) {
	pub, b64 := mustKey(t)
	otherPub, _ := mustKey(t)
	other := bcrypto.VirtualIPString(otherPub)
	if other == bcrypto.VirtualIPString(pub) {
		t.Skip("the two random keys collided on one VIP (1 in 65024)")
	}
	if err := checkPartnerVIP(protocol.Peer{PubKey: b64, VirtualIP: other}, pub); err == nil {
		t.Fatalf("accepted another key's valid VIP (%s) for this partner", other)
	}
}
