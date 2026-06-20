package relay

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func mustPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("bad test CIDR %q: %v", c, err)
		}
		out = append(out, p)
	}
	return out
}

// With an allowlist that excludes the source, a bind is refused (no ack), so the
// source cannot use the relay at all. With one that includes it, the bind acks.
func TestRelayCIDRGate(t *testing.T) {
	// Denied: loopback is not in 10.0.0.0/8.
	denyConn := mustListen(t)
	defer denyConn.Close()
	go NewServer(2*time.Second, mustPrefixes(t, "10.0.0.0/8"), 0, 0).Run(denyConn)
	denyDial := &net.UDPAddr{IP: net.IPv6loopback, Port: denyConn.LocalAddr().(*net.UDPAddr).Port}

	c := mustListen(t)
	defer c.Close()
	if err := BindLeg(c, denyDial, "tok", 500*time.Millisecond); err == nil {
		t.Fatal("bind from a source outside --allow-cidr must be refused")
	}

	// Allowed: loopback is explicitly listed.
	allowConn := mustListen(t)
	defer allowConn.Close()
	go NewServer(2*time.Second, mustPrefixes(t, "::1/128", "127.0.0.1/32"), 0, 0).Run(allowConn)
	allowDial := &net.UDPAddr{IP: net.IPv6loopback, Port: allowConn.LocalAddr().(*net.UDPAddr).Port}

	c2 := mustListen(t)
	defer c2.Close()
	if err := BindLeg(c2, allowDial, "tok", 2*time.Second); err != nil {
		t.Fatalf("bind from an allowed source must succeed: %v", err)
	}
}

// An empty allowlist keeps the relay open to all (default behaviour).
func TestRelayOpenByDefault(t *testing.T) {
	s := NewServer(2*time.Second, nil, 0, 0)
	if !s.cidrAllowed(net.IPv6loopback) || !s.cidrAllowed(net.ParseIP("8.8.8.8")) {
		t.Fatal("with no allowlist every source must be allowed")
	}
}
