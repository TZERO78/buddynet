package tunnel

import (
	"net"
	"testing"

	"github.com/tzero78/buddynet/internal/netkey"
)

// TestControlPlaneUsesTheSharedAccountingKey is the ANTI-DRIFT invariant made
// executable, and the direct regression guard for finding H-01.
//
// H-01 was not "the relay had a bug". It was that two places implemented the same
// per-source accounting rule and one of them drifted: this control plane
// aggregated IPv6 to /64 while the relay keyed per exact address, so a single /64
// bypassed every relay cap. The fix is that both call internal/netkey. This test
// fails the moment anyone reintroduces a local copy of the rule here.
//
// The relay side of the same invariant is asserted in
// internal/relay/ipv6_accounting_test.go, which drives Server.bind end to end.
func TestControlPlaneUsesTheSharedAccountingKey(t *testing.T) {
	addrs := []string{
		"192.0.2.7",
		"::ffff:192.0.2.7",
		"2001:db8:1234:5678::1",
		"2001:db8:1234:5678::2",
		"2001:db8:1234:5679::1",
		"::1",
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			t.Fatalf("bad test address %q", a)
		}
		ua := &net.UDPAddr{IP: ip, Port: 51820}
		got := ipKey(ua)
		want := netkey.FromAddr(ua)
		if got != want {
			t.Fatalf("the control plane derives a DIFFERENT accounting key than the shared rule for %s: ipKey=%q netkey=%q\n\n"+
				"That divergence is exactly finding H-01: whichever budget is looser becomes the bypass. "+
				"Both sides must call internal/netkey.", a, got, want)
		}
	}
}

// TestControlPlaneAggregatesIPv6AndUnmaps states the outcome the connection cap
// depends on, independently of which function computes it.
func TestControlPlaneAggregatesIPv6AndUnmaps(t *testing.T) {
	key := func(s string) string {
		return ipKey(&net.UDPAddr{IP: net.ParseIP(s), Port: 1})
	}
	if a, b := key("2001:db8:1:2::1"), key("2001:db8:1:2::2"); a != b {
		t.Fatalf("two addresses of one /64 got separate connection budgets: %q vs %q", a, b)
	}
	if a, b := key("2001:db8:1:2::1"), key("2001:db8:1:3::1"); a == b {
		t.Fatalf("two different /64s collapsed into one budget: %q", a)
	}
	if a, b := key("192.0.2.7"), key("::ffff:192.0.2.7"); a != b {
		t.Fatalf("the IPv4-mapped form got its own budget: %q vs %q", a, b)
	}
}
