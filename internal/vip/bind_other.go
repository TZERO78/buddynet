//go:build !linux

package vip

import (
	"fmt"
	"net/netip"
	"runtime"
)

// Assign is unsupported off Linux: per-buddy loopback VIP binding uses the Linux
// NETLINK_ROUTE interface. Callers degrade gracefully (the tunnel still works;
// VIP routing is simply unavailable), so this returns an error they can detect.
func Assign(ip netip.Addr) (release func() error, err error) {
	return nil, fmt.Errorf("vip: loopback VIP binding is not supported on %s", runtime.GOOS)
}
