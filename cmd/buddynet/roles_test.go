package main

import (
	"testing"

	"github.com/tzero78/buddynet/pkg/protocol"
)

// TestAllInOneCoordinatorRoles guards the role combination that docs/SETUP.md
// step 0 ("Do you need a VPS at all?") tells people to run: one of the two
// buddies is also the coordinator, so a pair needs no rented machine at all.
//
// That advice rests entirely on parseRoles placing no restriction on combining
// buddy with the server roles. lab/test-coordinator.sh proves the whole setup
// end to end behind two simulated NAT routers — but it needs Docker and does not
// run in CI, so a future "buddy and handshake are mutually exclusive" guard would
// land unnoticed and silently invalidate a documented setup. This is the cheap
// half of that proof, in the place CI actually looks.
func TestAllInOneCoordinatorRoles(t *testing.T) {
	got, err := parseRoles("buddy,handshake,relay")
	if err != nil {
		t.Fatalf("the all-in-one coordinator documented in docs/SETUP.md step 0 no longer parses: %v", err)
	}
	want := []protocol.Role{protocol.RoleBuddy, protocol.RoleHandshake, protocol.RoleRelay}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v (order is preserved as written)", got, want)
		}
	}
}

// TestParseRolesRejectsAndDeduplicates covers the neighbouring behaviour, so the
// test above cannot pass by accident on a parseRoles that accepts anything.
func TestParseRolesRejectsAndDeduplicates(t *testing.T) {
	for _, bad := range []string{"", "   ", "buddy,coordinator", "vps", ","} {
		if got, err := parseRoles(bad); err == nil {
			t.Fatalf("parseRoles(%q) = %v, want an error", bad, got)
		}
	}
	got, err := parseRoles("relay, buddy ,relay")
	if err != nil {
		t.Fatalf("parseRoles with spaces and a repeat: %v", err)
	}
	if len(got) != 2 || got[0] != protocol.RoleRelay || got[1] != protocol.RoleBuddy {
		t.Fatalf("got %v, want [relay buddy] (deduplicated, order preserved)", got)
	}
}
