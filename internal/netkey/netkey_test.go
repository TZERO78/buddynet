package netkey

import (
	"net"
	"testing"
)

// TestAccountingRule pins the rule itself: IPv4 per exact address, IPv6 per /64,
// IPv4-mapped IPv6 folded onto the IPv4 key, port always dropped.
func TestAccountingRule(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		want string
	}{
		{"ipv4 exact", "192.0.2.7", "192.0.2.7"},
		{"ipv4 neighbour is a different key", "192.0.2.8", "192.0.2.8"},
		{"ipv4-mapped folds onto ipv4", "::ffff:192.0.2.7", "192.0.2.7"},
		{"ipv6 aggregates to /64", "2001:db8:1234:5678::1", "2001:db8:1234:5678::/64"},
		{"ipv6 sibling shares the key", "2001:db8:1234:5678::dead:beef", "2001:db8:1234:5678::/64"},
		{"ipv6 neighbouring /64 differs", "2001:db8:1234:5679::1", "2001:db8:1234:5679::/64"},
		{"ipv6 loopback", "::1", "::/64"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ip := net.ParseIP(c.ip)
			if ip == nil {
				t.Fatalf("bad test address %q", c.ip)
			}
			if got := FromIP(ip); got != c.want {
				t.Fatalf("FromIP(%s) = %q, want %q", c.ip, got, c.want)
			}
		})
	}
}

// TestPortIsDropped: these are per-host budgets, not per-socket. Two sockets of
// one host must never get two budgets.
func TestPortIsDropped(t *testing.T) {
	ip := net.ParseIP("2001:db8:1234:5678::1")
	a := FromAddr(&net.UDPAddr{IP: ip, Port: 1000})
	b := FromAddr(&net.UDPAddr{IP: ip, Port: 2000})
	if a != b {
		t.Fatalf("port changed the accounting key: %q vs %q", a, b)
	}
	if tcp := FromAddr(&net.TCPAddr{IP: ip, Port: 3000}); tcp != a {
		t.Fatalf("TCP and UDP disagree for the same host: %q vs %q", tcp, a)
	}
}

// TestOneSlash64CannotMintBudgets is the property finding H-01 turned on: every
// address inside a /64 is free to create, so they must all collapse to one key.
func TestOneSlash64CannotMintBudgets(t *testing.T) {
	seen := map[string]bool{}
	addrs := []string{
		"2001:db8:aaaa:1::1", "2001:db8:aaaa:1::2", "2001:db8:aaaa:1::ffff",
		"2001:db8:aaaa:1:dead:beef:cafe:1", "2001:db8:aaaa:1::",
	}
	for _, a := range addrs {
		seen[FromIP(net.ParseIP(a))] = true
	}
	if len(seen) != 1 {
		t.Fatalf("%d addresses of one /64 produced %d distinct budgets: %v", len(addrs), len(seen), seen)
	}
}

// TestUnknownAddrTypesDoNotShareOneKey guards the fallback: an address type we do
// not understand must not silently collapse onto the empty key shared by every
// other unknown, which would be one budget for all of them.
func TestUnknownAddrTypesDoNotShareOneKey(t *testing.T) {
	a := FromAddr(&net.IPAddr{IP: net.ParseIP("192.0.2.1")})
	b := FromAddr(&net.IPAddr{IP: net.ParseIP("192.0.2.2")})
	if a == b {
		t.Fatalf("two distinct unknown-type addresses share the key %q", a)
	}
	if got := FromAddr(nil); got != "" {
		t.Fatalf("FromAddr(nil) = %q, want empty", got)
	}
}
