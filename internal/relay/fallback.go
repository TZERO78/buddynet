package relay

import "github.com/tzero78/buddynet/pkg/protocol"

// Kind distinguishes the two ways a buddy can reach a partner.
type Kind int

const (
	// Direct hole-punches to the partner's candidate endpoints and runs QUIC
	// straight over the punched path — no third party in the data path.
	Direct Kind = iota
	// Relayed binds a session on a relay and runs the same end-to-end QUIC
	// through it; the relay forwards encrypted packets blindly.
	Relayed
	// Configured is direct mode: the partner's endpoint was configured by the
	// operator (--peer-endpoint), not learned from a handshake server. It is
	// resolved fresh and dialled straight — deliberately WITHOUT a hole punch,
	// because there is no server to arrange a simultaneous one and the listening
	// side would otherwise block waiting for a punch that never comes.
	//
	// DNS here is route-finding ONLY. Whatever the name resolves to still has to
	// prove it holds the pinned key in the QUIC/TLS handshake, so a hijacked
	// record costs availability, never identity.
	Configured
)

func (k Kind) String() string {
	switch k {
	case Relayed:
		return "relayed"
	case Configured:
		return "configured"
	default:
		return "direct"
	}
}

// Path is one hop to try in the fallback chain. For Direct, Candidates are the
// punch targets. For Relayed, RelayEndpoint is the relay to bind through. The
// relay is NOT pinned or authenticated — it only ever forwards the end-to-end
// QUIC ciphertext, whose partner key the buddy pins itself — so there is no
// relay key here on purpose (a key field would imply a guarantee we do not make).
type Path struct {
	Kind          Kind
	Desc          string // short label for logs
	Candidates    []protocol.Candidate
	RelayEndpoint string
	// Endpoint is the configured partner address for Configured paths, as the
	// operator wrote it (host:port, possibly a name). Kept unresolved on purpose:
	// it is re-resolved at every attempt so a dynamic-DNS record that moved is
	// picked up on the next reconnect.
	Endpoint string
}

// DirectChain is the fallback chain for direct mode (--direct): the configured
// partner endpoint, then an optional relay. There is no handshake server in this
// mode, so there are no observed candidates, no server-advertised relay and no
// cached roster to fall back to — everything here was configured by the operator.
//
// endpoint may be empty on the LISTENING side (a buddy that only waits to be
// dialled); the path is still emitted so the QUIC listener runs, and the empty
// endpoint is simply never dialled.
func DirectChain(endpoint, relayEndpoint string) []Path {
	var chain []Path
	chain = append(chain, Path{
		Kind:     Configured,
		Desc:     "direct (configured endpoint)",
		Endpoint: endpoint,
	})
	if relayEndpoint != "" {
		chain = append(chain, Path{
			Kind:          Relayed,
			Desc:          "configured relay " + relayEndpoint,
			RelayEndpoint: relayEndpoint,
		})
	}
	return chain
}

// Chain builds the ordered fallback chain a buddy walks to reach partner. The
// order encodes the spec's priority — cheapest and most private first:
//
//  1. Direct P2P     — punch to the partner's live candidates.
//  2. Known relay    — any relay the handshake server offered for this pair.
//  3. Server relay    — the handshake server itself acting as a relay of last
//     resort (serverRelay set only if the server also runs --role=relay).
//  4. Cached peer     — the partner's last-known candidates from peers.json,
//     tried only when nothing above was available (e.g. the server was offline
//     when we started), so a pair that has met before can still reconnect.
//
// offers are RELAY_OFFER messages the server attached for this pair; cached is
// the partner's entry from the local registry, or nil if none.
func Chain(partner protocol.Peer, offers []protocol.Message, serverRelay string, cached *protocol.Peer) []Path {
	var chain []Path

	if len(partner.Candidates) > 0 {
		chain = append(chain, Path{
			Kind:       Direct,
			Desc:       "direct P2P",
			Candidates: partner.Candidates,
		})
	}

	for _, o := range offers {
		if o.RelayEndpoint == "" {
			continue
		}
		chain = append(chain, Path{
			Kind:          Relayed,
			Desc:          "known relay " + o.RelayEndpoint,
			RelayEndpoint: o.RelayEndpoint,
		})
	}

	if serverRelay != "" {
		chain = append(chain, Path{
			Kind:          Relayed,
			Desc:          "handshake server as relay",
			RelayEndpoint: serverRelay,
		})
	}

	// Last resort: a cached partner we can't currently see via the server.
	// Only add candidates the live roster didn't already give us.
	if cached != nil && len(partner.Candidates) == 0 && len(cached.Candidates) > 0 {
		chain = append(chain, Path{
			Kind:       Direct,
			Desc:       "cached peer (server offline)",
			Candidates: cached.Candidates,
		})
	}

	return chain
}
