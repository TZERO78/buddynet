package role

// AUDIT 2026-08-20, finding A-05 (LOW / hardening): protocol.Message.Role is the
// one REGISTER field the handshake server neither validates nor bounds, and it
// is retained in long-lived server state.
//
// Every neighbouring field is gated:
//
//	ID       -> validField   (non-empty, <= MaxFieldLen, base64url alphabet)
//	PubKey   -> length-bounded in parseRegister, then decoded to exactly 32 bytes
//	Nonce    -> protocol.ValidNonce (exact length + alphabet)
//	CodeEnc  -> <= maxCodeEncLen
//	TokenEnc -> <= maxCodeEncLen
//	Name     -> protocol.ValidName (DNS label rules, MaxNameLen)
//	Token    -> validField after unsealing
//	VirtualIP-> must equal the value the key derives, else the register is dropped
//
// Role is stored raw: `if m.Role != "" { self.role = m.Role }`. It is covered by
// RegistrationPayload, so it is signed — by the ATTACKER'S OWN key, which costs
// them nothing — and the only ceiling left is maxControlReq (8192 bytes), the
// size of the whole control request.
//
// Two things follow, and the second is the reason to fix it rather than shrug:
//
//  1. Memory. hsPeer.role is retained for up to maxTokens*maxIDsPerToken peers,
//     so the registry's stated bound ("hard caps bound server memory regardless
//     of spoofed source addresses") is off by the size of this one field. A
//     hsPeer with validated fields is a few hundred bytes; with a padded Role it
//     is ~8 KB.
//
//  2. hsPeer.role is DEAD STATE. Nothing in the tree ever reads it — handshake.go
//     line 274 is the only reference, and asProtocolPeer does not emit it. So
//     this is attacker-controlled, unvalidated, unbounded data retained for no
//     purpose at all, which is the cheapest possible thing to close.
//
// This is rated hardening, not a vulnerability: the total stays bounded (the
// registry caps still hold), and nothing reads the value back out, so there is
// no injection sink today. What it breaks is the memory bound the file claims.

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tzero78/buddynet/pkg/protocol"
)

// TestAuditRoleFieldIsNotRetained is the A-05 regression. The finding was that
// REGISTER.Role — the one field with neither a validator nor a length bound —
// was stored verbatim in the registry although nothing ever read it. The fix
// removed the field, so this test can no longer inspect it; instead it asserts
// the property that matters: none of the hostile bytes survive anywhere in the
// stored peer.
func TestAuditRoleFieldIsNotRetained(t *testing.T) {
	reg := newHSRegistry(time.Minute)

	// Everything a real REGISTER carries, plus a Role padded to what one control
	// request still has room for, containing bytes every other field's validator
	// refuses (a newline and a NUL).
	const pad = 7000
	needle := "\n\x00SECURITY: event=forged"
	hostile := protocol.Role(strings.Repeat("A", pad) + needle)

	m := auditRegMsg(t, "audit-role-token", "audit-role-id")
	m.Role = hostile

	self, _, ok := reg.upsert(m, auditSrc(1))
	if !ok {
		t.Fatal("setup: the registry refused the registration outright")
	}

	// Whatever the peer holds, it must not contain the attacker's bytes. %+v
	// renders every field, so a future field that starts storing Role again is
	// caught here and not just the one that was removed.
	stored := fmt.Sprintf("%+v", *self)
	if strings.Contains(stored, needle) || strings.Contains(stored, strings.Repeat("A", 64)) {
		t.Fatalf("A-05 is back: REGISTER.Role bytes are retained in the registry peer:\n%.400s", stored)
	}

	// Positive control: the registration itself still worked — the peer is real
	// and carries the fields it is supposed to carry. Without this, "the bytes
	// are gone" would also be true of a registry that dropped everything.
	if self.id != "audit-role-id" {
		t.Fatalf("control: the peer did not keep its id (got %q)", self.id)
	}
	if self.pubkey != m.PubKey {
		t.Fatalf("control: the peer did not keep its pubkey")
	}

	// And the neighbouring validated field still behaves: the same hostile string
	// offered as Name is dropped, which is what made Role stand out originally.
	m2 := auditRegMsg(t, "audit-name-token", "audit-name-id")
	m2.Name = string(hostile)
	self2, _, ok := reg.upsert(m2, auditSrc(2))
	if !ok {
		t.Fatal("setup: the registry refused the name registration outright")
	}
	if self2.name != "" {
		t.Fatalf("control FAILED: the hostile string was accepted as Name (%d bytes)", len(self2.name))
	}
}

// TestAuditRoleFieldControlValidFieldRefuses is the POSITIVE CONTROL for the
// validator itself: validField — the gate Role does not pass through — does
// refuse exactly these bytes. Without this, the test above would only be showing
// that nothing rejected the string, not that the project's own rule would have.
func TestAuditRoleFieldControlValidFieldRefuses(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"oversized", strings.Repeat("A", protocol.MaxFieldLen+1)},
		{"newline", "buddy\nforged"},
		{"nul", "buddy\x00forged"},
	}
	for _, c := range cases {
		if validField(c.in) {
			t.Fatalf("positive control FAILED: validField accepted %s input", c.name)
		}
	}
	if !validField("buddy") {
		t.Fatal("positive control FAILED: validField refused an ordinary role string")
	}
	t.Log(fmt.Sprintf("positive control holds: validField refuses oversized/newline/NUL input and accepts %q — "+
		"Role is simply never passed through it", "buddy"))
}
