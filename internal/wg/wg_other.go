//go:build !linux

package wg

import "net/netip"

// Up is unavailable off Linux: there is no kernel WireGuard netlink interface.
// Callers degrade gracefully (errors.Is(err, ErrUnsupported)). A future Windows
// port would live in wg_windows.go (userspace wireguard-go + Wintun).
func Up(cfg Config) (down func() error, err error) {
	return nil, ErrUnsupported
}

// AddPeer is unavailable off Linux (see Up).
func AddPeer(ifName string, p Peer) error { return ErrUnsupported }

// RemovePeer is unavailable off Linux (see Up).
func RemovePeer(ifName string, pub [32]byte) error { return ErrUnsupported }

// Available reports false off Linux: no kernel WireGuard.
func Available() bool { return false }

// PeerEndpoint is unavailable off Linux (see Up).
func PeerEndpoint(ifName string, peerPub [32]byte) (netip.AddrPort, bool, error) {
	return netip.AddrPort{}, false, ErrUnsupported
}
