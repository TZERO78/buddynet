// Package wg brings up a kernel WireGuard data-plane interface and configures a
// single peer, talking to the kernel directly over raw netlink sockets — no
// `wg`/`ip` subprocess, no iproute2/wireguard-tools dependency, no external Go
// module. This mirrors internal/vip's raw-NETLINK_ROUTE approach and keeps the
// project's zero-dependency, security-first posture (Phase 3 — see
// docs/plans/wireguard.md §4).
//
// Interface creation and link/address changes go over NETLINK_ROUTE
// (RTM_NEWLINK with kind "wireguard", RTM_NEWADDR, RTM_DELLINK); the crypto
// config (private key + peer public key/endpoint/allowed-ips) goes over
// NETLINK_GENERIC to the kernel's "wireguard" generic-netlink family
// (WG_CMD_SET_DEVICE).
//
// Bringing an interface up needs root/NET_ADMIN and the wireguard kernel module;
// Up wraps syscall.EPERM/ENODEV so callers can degrade gracefully (errors.Is).
// A userspace fallback (wireguard-go) is intentionally NOT in the default build
// (it is a heavy dependency) — see docs/plans/wireguard.md §4.
//
// This package is the isolated P3.1 spike: it can stand up a tun + one peer
// against a statically configured counterpart in the lab, before any
// control-plane integration. The data path is opaque to the rest of BuddyNet;
// identity still flows through the pinned Ed25519 key (the peer's X25519 public
// key is derived from it, see internal/crypto.X25519FromEd25519Public).
package wg

import (
	"errors"
	"net/netip"
)

// ErrUnsupported is returned by Up on platforms without kernel WireGuard support
// (anything other than Linux in this build).
var ErrUnsupported = errors.New("wg: kernel WireGuard is only supported on Linux")

// Peer is the single remote endpoint configured on the interface.
type Peer struct {
	// PublicKey is the peer's WireGuard (X25519) public key, derived
	// deterministically from its pinned Ed25519 identity
	// (crypto.X25519FromEd25519Public). No key is exchanged over the tunnel.
	PublicKey [32]byte
	// Endpoint is the peer's UDP address (the hole-punched remote address at
	// integration time; a static address in the spike). The zero value leaves
	// the endpoint unset (roaming — the kernel learns it from inbound traffic).
	Endpoint netip.AddrPort
	// AllowedIPs are the prefixes routed to this peer — typically the partner's
	// virtual IP as a /32.
	AllowedIPs []netip.Prefix
	// Keepalive is the persistent-keepalive interval in seconds (0 = off). Useful
	// across NAT to keep the punched mapping alive.
	Keepalive uint16
}

// Config describes the interface to bring up.
type Config struct {
	// IfName is the interface name (max 15 bytes), e.g. "bnet0" — the BuddyNet
	// adapter. One device carries all buddies; add a peer per buddy with AddPeer.
	IfName string
	// PrivateKey is this node's WireGuard (X25519) private key
	// (crypto.X25519FromEd25519Private).
	PrivateKey [32]byte
	// ListenPort is the UDP port the kernel WireGuard socket binds (0 = kernel
	// chooses). The spike sets distinct ports so two ends can run on one host.
	ListenPort int
	// Address is assigned to the interface. Using the overlay prefix (e.g. the
	// node's VIP as 10.66.X.Y/16) gives a connected route over the interface so
	// peers in the overlay are reachable without an explicit route.
	Address netip.Prefix
	// Peer is the single remote peer (the spike configures exactly one).
	Peer Peer
}

func (c Config) validate() error {
	if c.IfName == "" || len(c.IfName) > 15 {
		return errors.New("wg: IfName must be 1..15 bytes")
	}
	if c.PrivateKey == ([32]byte{}) {
		return errors.New("wg: PrivateKey is zero")
	}
	if c.Peer.PublicKey == ([32]byte{}) {
		return errors.New("wg: Peer.PublicKey is zero")
	}
	for _, p := range c.Peer.AllowedIPs {
		if !p.IsValid() {
			return errors.New("wg: invalid AllowedIP prefix")
		}
	}
	if c.Address.IsValid() && !c.Address.Addr().Is4() {
		return errors.New("wg: only IPv4 interface addresses are supported")
	}
	return nil
}
