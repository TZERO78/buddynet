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
)

func (k Kind) String() string {
	if k == Relayed {
		return "relayed"
	}
	return "direct"
}

// Path is one hop to try in the fallback chain. For Direct, Candidates are the
// punch targets. For Relayed, RelayEndpoint is the relay to bind through and
// RelayPubKey pins it.
type Path struct {
	Kind          Kind
	Desc          string // short label for logs
	Candidates    []protocol.Candidate
	RelayEndpoint string
	RelayPubKey   string
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
			RelayPubKey:   o.RelayPubKey,
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
