package dns

import (
	"net/netip"
	"testing"

	"github.com/tzero78/buddynet/pkg/protocol"
)

func TestResolveKnownName(t *testing.T) {
	table := map[string]netip.Addr{
		"alice": netip.MustParseAddr("10.66.0.1"),
		"bob":   netip.MustParseAddr("10.66.0.2"),
	}
	for _, tc := range []struct{ q, want string }{
		{"alice.buddy.", "10.66.0.1"},
		{"bob.buddy.", "10.66.0.2"},
		{"Alice.buddy.", "10.66.0.1"}, // case-insensitive
		{"BOB.BUDDY.", "10.66.0.2"},   // fully uppercased
	} {
		addr, ok := Resolve(table, tc.q)
		if !ok {
			t.Errorf("Resolve(%q): got not-found, want %s", tc.q, tc.want)
			continue
		}
		if addr.String() != tc.want {
			t.Errorf("Resolve(%q): got %s, want %s", tc.q, addr, tc.want)
		}
	}
}

func TestResolveUnknown(t *testing.T) {
	table := map[string]netip.Addr{"alice": netip.MustParseAddr("10.66.0.1")}
	if _, ok := Resolve(table, "nichtda.buddy."); ok {
		t.Fatal("expected not-found for unknown name")
	}
	if _, ok := Resolve(table, "alice.example.com."); ok {
		t.Fatal("expected not-found for non-.buddy query")
	}
	if _, ok := Resolve(table, "sub.alice.buddy."); ok {
		t.Fatal("expected not-found for multi-label .buddy query")
	}
}

func TestBuildTableNameAndFingerprint(t *testing.T) {
	peers := []protocol.Peer{
		{PubKey: "AAAA", VirtualIP: "10.66.0.1", Name: "alice"},
		{PubKey: "BBBB", VirtualIP: "10.66.0.2"}, // no name → fingerprint only
	}
	table := BuildTable(peers, "self", netip.MustParseAddr("10.66.0.99"))

	// Named peer reachable by name.
	if addr, ok := table["alice"]; !ok || addr.String() != "10.66.0.1" {
		t.Errorf("alice entry: got %v %v", addr, ok)
	}
	// Every peer has a fingerprint entry.
	fpA := fingerprint("AAAA")
	if _, ok := table[fpA]; !ok {
		t.Errorf("fingerprint entry missing for AAAA (fp=%s)", fpA)
	}
	fpB := fingerprint("BBBB")
	if _, ok := table[fpB]; !ok {
		t.Errorf("fingerprint entry missing for BBBB (fp=%s)", fpB)
	}
	// Self entry.
	if addr, ok := table["self"]; !ok || addr.String() != "10.66.0.99" {
		t.Errorf("self entry: got %v %v", addr, ok)
	}
}

func TestBuildTableSelfEmptyName(t *testing.T) {
	table := BuildTable(nil, "", netip.MustParseAddr("10.66.0.1"))
	if len(table) != 0 {
		t.Errorf("expected empty table for no peers and no self-name, got %d entries", len(table))
	}
}

func TestValidName(t *testing.T) {
	for _, tc := range []struct {
		s    string
		want bool
	}{
		{"alice", true},
		{"bob-server", true},
		{"node1", true},
		{"a", true},
		{"", false},
		{"-start", false},
		{"end-", false},
		{"Alice", false}, // uppercase rejected
		{"has space", false},
		{"has.dot", false},
		{"has_under", false},
	} {
		if got := protocol.ValidName(tc.s); got != tc.want {
			t.Errorf("ValidName(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}
