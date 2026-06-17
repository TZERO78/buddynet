// Package dns is BuddyNet's MagicDNS resolver for the .buddy TLD.
//
// Peers that set --name announce a self-asserted label. The handshake server
// relays it verbatim; the receiving buddy TOFU-pins it in the peer registry.
// This package turns those pinned names into a local stub resolver so that
// "dig alice.buddy" or "ping bob.buddy" resolves to the peer's virtual IP
// without touching any external DNS infrastructure.
//
// The resolver is split into a pure, syscall-free core (this file) and a
// network-bound server layer (server.go) so the core can be unit-tested
// without opening sockets.
package dns

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"

	"github.com/tzero78/buddynet/pkg/protocol"
)

const buddyTLD = ".buddy"

// Resolve looks up qname in table and returns the matching address.
// qname is normalised (lowercased, trailing dot stripped) before the lookup.
// Only names ending in ".buddy" are answered; anything else returns false
// so the caller can return NXDOMAIN immediately — we never forward upstream.
func Resolve(table map[string]netip.Addr, qname string) (netip.Addr, bool) {
	// Lowercase first, then strip trailing dot and the .buddy suffix.
	q := strings.ToLower(qname)
	q = strings.TrimSuffix(q, ".")
	if !strings.HasSuffix(q, buddyTLD) {
		return netip.Addr{}, false // non-.buddy query
	}
	q = strings.TrimSuffix(q, buddyTLD)
	if q == "" || strings.Contains(q, ".") {
		return netip.Addr{}, false // empty or multi-label
	}
	addr, ok := table[q]
	return addr, ok
}

// BuildTable constructs the name→IP lookup table the DNS server uses.
// For every peer with a pinned name, "name" maps to its virtual IP.
// Every peer (named or not) also gets a fingerprint entry "<fp8>" (the first
// 8 hex chars of SHA-256(pubkey)) so unnamed peers remain reachable.
// selfName and selfIP add this node's own entry if selfName is non-empty.
func BuildTable(peers []protocol.Peer, selfName string, selfIP netip.Addr) map[string]netip.Addr {
	table := make(map[string]netip.Addr, len(peers)*2+2)
	for _, p := range peers {
		ip, err := netip.ParseAddr(p.VirtualIP)
		if err != nil {
			continue
		}
		if p.Name != "" {
			table[p.Name] = ip
		}
		table[fingerprint(p.PubKey)] = ip
	}
	if selfName != "" && selfIP.IsValid() {
		table[selfName] = selfIP
	}
	return table
}

// fingerprint returns the first 8 hex chars of SHA-256(base64-pubkey),
// used as a stable, short, collision-resistant alias for any peer.
func fingerprint(pubkeyB64 string) string {
	sum := sha256.Sum256([]byte(pubkeyB64))
	return hex.EncodeToString(sum[:])[:8]
}
