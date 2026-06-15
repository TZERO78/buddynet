package role

import (
	"net"
	"net/netip"
	"testing"
)

func TestCIDRAllowed(t *testing.T) {
	// No allowlist: every source is served (default open).
	if !cidrAllowed(nil, net.ParseIP("8.8.8.8")) {
		t.Fatal("an empty allowlist must allow every source")
	}

	allow := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true}, // inside 10/8
		{"10.255.255.255", true},
		{"8.8.8.8", false}, // outside
		{"192.168.1.1", false},
		{"::1", true}, // inside ::1/128
	}
	for _, c := range cases {
		if got := cidrAllowed(allow, net.ParseIP(c.ip)); got != c.want {
			t.Errorf("cidrAllowed(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}
