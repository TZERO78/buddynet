package role

import (
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
)

// Where the relay endpoint a buddy binds to may come from.
//
// The handshake server advertises one in every paired PEER_LIST (Peer.Relay).
// That value is signed, so it is authentic — but authentic only says WHO chose
// it. A compromised server that still signs correctly is inside the threat model
// (SECURITY.md), and until this check the buddy resolved whatever host the
// roster named and sent relay binds there: the server picked a target. The
// packets are small and the window is bounded, but a pinned party must not be
// able to aim a buddy at an address of its own choosing.
//
// So the endpoint comes from LOCAL trust, in this order, and a roster value is
// never a target in its own right:
//
//  1. --peer-relay, set by the operator. Valid in both modes now (it used to be
//     direct-mode only) and the only way to reach a relay on a host other than
//     the server's.
//  2. The same-host rule: without the flag, the server's offer is taken only if
//     its host is LITERALLY the host the operator wrote in --server. The
//     operator chose that host and pinned its key; the server can at most name
//     a port on it — which is the standard deployment, one VPS running
//     handshake and relay. What is trusted here is the HOST, deliberately, not
//     the full HOST:PORT: the port is the server's to pick, on its own machine.
//     Hosts are compared as strings (case-folded, trailing dot dropped, IPv6
//     literals normalised) and never resolved — resolving would let DNS decide
//     what is trusted.
//  3. Neither: no relayed path at all. Direct and cached candidates are
//     unaffected, so the direct connection keeps working; the skipped offer is
//     logged once per distinct value as a SECURITY event, because a foreign
//     host in the offer is either a misconfiguration or exactly the attacker
//     modelled above, and the line says which flag would allow it.
//
// The relay ticket is untouched by any of this: it binds a session to a relay
// ID, not to an endpoint.

// relayOffer is the outcome of trustedRelay: the endpoint to use (empty = no
// relayed path) and, when an advertised value was set aside, why.
type relayOffer struct {
	endpoint string
	skipped  string // the advertised value that was not trusted, "" if none
	reason   string // fixed text for the log line
}

// trustedRelay decides the relay endpoint for this attempt from local trust
// only. local is --peer-relay, server is --server as configured, advertised is
// Peer.Relay from the roster (or the cache, which was filled from rosters).
func trustedRelay(local, server, advertised string) relayOffer {
	if local != "" {
		// The operator named a relay. It wins over any offer, including a
		// same-host one: a local decision is never overridden by a remote hint.
		return relayOffer{endpoint: local}
	}
	if advertised == "" {
		return relayOffer{}
	}
	aHost, ok := hostOf(advertised)
	if !ok {
		return relayOffer{skipped: advertised, reason: "offer is not a HOST:PORT"}
	}
	sHost, ok := hostOf(server)
	if !ok || sHost == "" {
		return relayOffer{skipped: advertised, reason: "no --server host to compare against"}
	}
	if aHost != sHost {
		return relayOffer{skipped: advertised, reason: "offer names a host other than --server; pass it as --peer-relay to allow it"}
	}
	return relayOffer{endpoint: advertised}
}

// hostOf extracts the comparison key for a HOST:PORT: the host, case-folded,
// without a trailing dot, and — for an IP literal — in canonical textual form so
// two spellings of one address compare equal. No name resolution, ever.
func hostOf(hostport string) (string, bool) {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.Unmap().String()
	}
	return host, true
}

// maxRelayOfferLatch bounds the per-process set of skipped offers already
// logged. A hostile server can send a different value per poll; the latch keeps
// the log at one line per value and stops growing at the cap (the counter of
// skipped offers is not affected — only the log line is).
const maxRelayOfferLatch = 64

// relayOfferLatch remembers which untrusted offers have been logged, so a
// server repeating (or rotating) an offer cannot turn every reconnect into a
// log line. Process-wide, like the trust store it sits next to on node.
type relayOfferLatch struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

// noteSkipped logs an untrusted relay offer once per distinct value.
func (l *relayOfferLatch) noteSkipped(o relayOffer) {
	if o.skipped == "" {
		return
	}
	l.mu.Lock()
	if l.seen == nil {
		l.seen = map[string]struct{}{}
	}
	_, done := l.seen[o.skipped]
	if !done && len(l.seen) < maxRelayOfferLatch {
		l.seen[o.skipped] = struct{}{}
	}
	l.mu.Unlock()
	if done {
		return
	}
	log.Printf("SECURITY: event=relay-offer-untrusted relay=%q detail=%q", o.skipped,
		"server-advertised relay skipped: "+o.reason+"; only --peer-relay or a relay on the --server host is used")
}
