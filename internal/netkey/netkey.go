// Package netkey derives the ACCOUNTING KEY a source address is charged under.
//
// Every public-facing budget in BuddyNet — the control plane's per-source
// connection cap, the handshake server's rate limiters, the relay's bind limiter
// and its per-source leg cap — must charge the same address the same way. When
// two of them normalize differently, the stricter one is silently bypassed by
// whichever address form the looser one accounts separately. That is not
// hypothetical: the control plane aggregated IPv6 to a /64 while the relay keyed
// per exact address, so one /64 minted an unlimited supply of "distinct sources"
// and could fill the relay's global session table (finding H-01).
//
// This package exists so there is exactly ONE implementation of that rule. It
// deliberately depends on nothing inside BuddyNet, so both the transport and the
// server roles can use it without either importing the other.
//
// The rule:
//
//   - IPv4 is accounted PER EXACT ADDRESS. Addresses are scarce enough there that
//     rotation is not a cheap lever, while aggregating (say to a /24) would fold
//     unrelated customers of one provider into a single budget.
//   - IPv6 is accounted PER /64. A /64 is what a single LAN normally gets, and
//     every address inside it is free to mint — so counting per address counts
//     nothing. Aggregating to /64 charges exactly the addresses an attacker gets
//     for nothing.
//   - IPv4-mapped IPv6 (::ffff:a.b.c.d) is unmapped FIRST, so it lands on the same
//     key as the plain IPv4 address. Otherwise a peer doubles its allowance just
//     by reaching the same service over the mapped form.
//
// What /64 aggregation does NOT do: it does not bound an attacker to one budget.
// A site may be delegated a /56 or /60, and a botnet spans many prefixes. It
// removes FREE rotation within one /64; it is a ceiling on cheap abuse, not
// access control.
//
// The port is always dropped: these are per-host budgets, not per-socket.
package netkey

import (
	"net"
	"net/netip"
)

// V6Bits is the prefix length an IPv6 source is accounted on. See the package
// doc for why /64 and not per address.
const V6Bits = 64

// FromAddr returns the accounting key for a net.Addr. A *net.UDPAddr or
// *net.TCPAddr is reduced to its IP; anything else falls back to its String()
// form, which keeps an unknown address type accounted as *something* rather than
// silently sharing the empty key with every other unknown.
func FromAddr(a net.Addr) string {
	switch v := a.(type) {
	case *net.UDPAddr:
		return FromIP(v.IP)
	case *net.TCPAddr:
		return FromIP(v.IP)
	case nil:
		return ""
	default:
		return a.String()
	}
}

// FromIP returns the accounting key for a net.IP: the exact address for IPv4
// (including IPv4-mapped IPv6, which is unmapped first), the /64 prefix for IPv6.
// An address that cannot be parsed falls back to its textual form.
func FromIP(ip net.IP) string {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return ip.String()
	}
	return FromNetipAddr(addr)
}

// FromNetipAddr is the core rule, for callers that already hold a netip.Addr.
func FromNetipAddr(addr netip.Addr) string {
	// Unmap FIRST: ::ffff:a.b.c.d must share the plain IPv4 key, or the mapped
	// form is a second free budget for the same host.
	addr = addr.Unmap()
	if addr.Is6() {
		if p, err := addr.Prefix(V6Bits); err == nil {
			return p.String()
		}
	}
	return addr.String()
}
