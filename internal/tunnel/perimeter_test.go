package tunnel

// Tests for the two perimeter properties of the public control port, both of
// which used to sit one layer too far inside:
//
//   - QUIC Retry: an unvalidated source must not get a connection (and with it a
//     full TLS + Ed25519 handshake) before it has proven it can receive packets.
//     Without it the per-source connection caps never see the traffic at all,
//     because they only apply once quic-go has already built the connection.
//   - The source allowlist: a disallowed source must not occupy one of the
//     connection slots. It used to be checked in the REGISTER handler — after TLS
//     and after the slot was taken — while the flag help promised "before any
//     crypto".

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"
)

func mustPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("bad test CIDR %q: %v", c, err)
		}
		out = append(out, p)
	}
	return out
}

func listenLoopback(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// TestListenControlRequiresSourceValidation pins that Retry is switched on. A
// unit test cannot spoof a source address, so it asserts the callback is
// installed and demands validation — the property the DoS finding turned on.
func TestListenControlRequiresSourceValidation(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := ListenControl(listenLoopback(t), priv, time.Second, nil)
	if err != nil {
		t.Fatalf("ListenControl: %v", err)
	}
	defer cs.Close()

	if cs.tr.VerifySourceAddress == nil {
		t.Fatal(`the QUIC transport has no VerifySourceAddress callback.

Without it quic-go creates a connection — and runs the whole TLS/Ed25519
handshake — for any well-formed Initial, including a spoofed one, before any of
BuddyNet's per-source caps can see it.`)
	}
	// Every address must be told to validate: no threshold to tune wrong.
	for _, addr := range []net.Addr{
		&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1},
		&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1},
	} {
		if !cs.tr.VerifySourceAddress(addr) {
			t.Fatalf("VerifySourceAddress(%v) = false: this source would skip Retry", addr)
		}
	}
}

// TestSourceAllowedGatesBeforeTheSlot covers the decision itself. acceptConns
// calls this before admit, so a "false" here is a source that never reaches the
// connection table.
func TestSourceAllowedGatesBeforeTheSlot(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	cs, err := ListenControl(listenLoopback(t), priv, time.Second,
		mustPrefixes(t, "192.0.2.0/24", "2001:db8:1::/48"))
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	cases := []struct {
		addr string
		want bool
	}{
		{"192.0.2.7", true},
		{"192.0.2.255", true},
		{"198.51.100.7", false},
		{"2001:db8:1::5", true},
		{"2001:db8:2::5", false},
		{"::ffff:192.0.2.7", true}, // IPv4-mapped must match the IPv4 prefix
		{"::ffff:198.51.100.7", false},
	}
	for _, c := range cases {
		got := cs.sourceAllowed(&net.UDPAddr{IP: net.ParseIP(c.addr), Port: 51820})
		if got != c.want {
			t.Errorf("sourceAllowed(%s) = %v, want %v", c.addr, got, c.want)
		}
	}
}

// TestEmptyAllowlistStaysOpen: the default must not become fail-closed by
// accident — an empty --allow-cidr means "no restriction", not "refuse everyone".
func TestEmptyAllowlistStaysOpen(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	cs, err := ListenControl(listenLoopback(t), priv, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	if !cs.sourceAllowed(&net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 1}) {
		t.Fatal("an empty allowlist refused a source; the default must stay open")
	}
}

// slotsAfterDial dials the server from loopback and reports how many connection
// slots are held once the server has had a chance to accept. Used for both the
// positive control (an allowed source DOES take a slot — so the assertion below
// can see anything at all) and the actual check.
func slotsAfterDial(t *testing.T, allowed []netip.Prefix) int {
	t.Helper()
	srvPub, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	conn := listenLoopback(t)
	cs, err := ListenControl(conn, srvPriv, 5*time.Second, allowed)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	_, cliPriv, _ := ed25519.GenerateKey(rand.Reader)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cc, derr := DialControl(ctx, listenLoopback(t), conn.LocalAddr().(*net.UDPAddr), srvPub, cliPriv, 5*time.Second)
	if derr == nil {
		defer cc.Close()
	}

	// Give acceptConns time to run. Without this the count can be read before the
	// server accepted anything, which reads as "no slot held" no matter what the
	// gate does — the first version of this test was green with the gate REMOVED
	// for exactly that reason.
	deadline := time.Now().Add(2 * time.Second)
	best := 0
	for time.Now().Before(deadline) {
		cs.connMu.Lock()
		n := cs.conns
		cs.connMu.Unlock()
		if n > best {
			best = n
		}
		if best > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return best
}

// TestAllowedSourceDoesTakeASlot is the POSITIVE CONTROL for the test below: with
// loopback allowed, a dial must actually occupy a slot. If this ever fails, a
// "no slot held" result next door proves nothing.
func TestAllowedSourceDoesTakeASlot(t *testing.T) {
	if n := slotsAfterDial(t, mustPrefixes(t, "127.0.0.0/8")); n == 0 {
		t.Fatal("an allowed source took no connection slot — the observation itself is broken, so the refusal test below would be vacuous")
	}
}

// TestDisallowedSourceNeverTakesASlot is the actual statement: a client from
// outside the allowlist may complete QUIC/TLS (unavoidable with this library) but
// must never occupy one of the connection slots.
func TestDisallowedSourceNeverTakesASlot(t *testing.T) {
	// 203.0.113.0/24 does not contain 127.0.0.1.
	if n := slotsAfterDial(t, mustPrefixes(t, "203.0.113.0/24")); n != 0 {
		t.Fatalf(`a source outside --allow-cidr held %d connection slot(s).

The allowlist must be enforced before the slot is handed out; checking it in the
REGISTER handler let a refused source occupy capacity until the idle timeout.`, n)
	}
}
