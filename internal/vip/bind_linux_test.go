//go:build linux

package vip

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
)

// loHasAddr reports whether the loopback interface currently carries ip.
func loHasAddr(t *testing.T, ip netip.Addr) bool {
	t.Helper()
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("lookup lo: %v", err)
	}
	addrs, err := lo.Addrs()
	if err != nil {
		t.Fatalf("lo addrs: %v", err)
	}
	for _, a := range addrs {
		if pfx, ok := a.(*net.IPNet); ok {
			if got, ok := netip.AddrFromSlice(pfx.IP.To4()); ok && got == ip {
				return true
			}
		}
	}
	return false
}

// TestAssignReleaseRoundTrip adds a VIP to lo, confirms it appears, then releases
// it and confirms it is gone. It needs NET_ADMIN; without it (CI, unprivileged
// dev), the test skips rather than fails.
func TestAssignReleaseRoundTrip(t *testing.T) {
	ip := netip.MustParseAddr("10.66.211.177") // overlay range, test-only

	if loHasAddr(t, ip) {
		t.Skipf("%s already on lo; skipping to avoid clobbering host state", ip)
	}

	release, err := Assign(ip)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("no NET_ADMIN to assign loopback VIP: %v", err)
		}
		t.Fatalf("Assign: %v", err)
	}
	if !loHasAddr(t, ip) {
		release()
		t.Fatalf("%s was not added to lo", ip)
	}

	// Idempotent re-assign must not error while the address is present.
	if r2, err := Assign(ip); err != nil {
		release()
		t.Fatalf("re-Assign (idempotent) failed: %v", err)
	} else {
		_ = r2 // r2 would remove it too; we rely on the first release below
	}

	if err := release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if loHasAddr(t, ip) {
		t.Fatalf("%s still on lo after release", ip)
	}

	// Releasing again is a no-op (idempotent), not an error.
	if err := release(); err != nil {
		t.Fatalf("double release should be a no-op: %v", err)
	}
}

// ReconcileStale must remove a leaked overlay VIP that is NOT in the keep set
// while leaving a kept one (and any non-overlay loopback address) alone.
func TestReconcileStale(t *testing.T) {
	stale := netip.MustParseAddr("10.66.222.111") // simulated leak from a SIGKILLed run
	keep := netip.MustParseAddr("10.66.222.112")  // a VIP this run still manages

	for _, ip := range []netip.Addr{stale, keep} {
		if loHasAddr(t, ip) {
			t.Skipf("%s already on lo; skipping", ip)
		}
	}
	r1, err := Assign(stale)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("no NET_ADMIN: %v", err)
		}
		t.Fatalf("assign stale: %v", err)
	}
	r2, err := Assign(keep)
	if err != nil {
		r1()
		t.Fatalf("assign keep: %v", err)
	}
	// Belt-and-braces cleanup in case the assertions fail mid-way.
	defer func() { r1(); r2() }()

	removed, err := ReconcileStale([]netip.Addr{keep})
	if err != nil {
		t.Fatalf("ReconcileStale: %v", err)
	}
	if removed < 1 {
		t.Fatalf("expected the stale VIP to be removed, removed=%d", removed)
	}
	if loHasAddr(t, stale) {
		t.Fatalf("stale VIP %s was not removed", stale)
	}
	if !loHasAddr(t, keep) {
		t.Fatalf("kept VIP %s was wrongly removed", keep)
	}
}

func TestAssignRejectsIPv6(t *testing.T) {
	if _, err := Assign(netip.MustParseAddr("fd00::1")); err == nil {
		t.Fatal("Assign must reject a non-IPv4 VIP")
	}
}
