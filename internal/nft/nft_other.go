//go:build !linux

package nft

import "errors"

// ErrUnsupported mirrors wg.ErrUnsupported: scoped exposure needs the Linux
// kernel's nftables subsystem, which only the WireGuard data plane (Linux-only
// anyway) uses.
var ErrUnsupported = errors.New("nft: scoped exposure is only supported on Linux")

// Apply is unsupported off Linux; callers fail closed.
func Apply(ifName string, s Scope) error { return ErrUnsupported }

// Remove is a no-op off Linux (nothing was ever applied).
func Remove(ifName string) error { return nil }
