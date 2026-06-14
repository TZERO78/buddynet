package peer

import (
	"time"

	"github.com/tzero78/buddynet/pkg/protocol"
)

// KeepalivePeriod is how often a buddy re-registers / pings to keep its NAT
// mapping and its handshake-server registration fresh (the spec's 25s).
const KeepalivePeriod = 25 * time.Second

// Merge applies a freshly-received PEER_LIST to the registry: every peer in the
// roster (except ourselves) is upserted with an updated LastSeen, so the
// on-disk cache always reflects the most recent view the server gave us. It
// returns the peers that were merged, in the order the server sent them.
//
// This is the "gossip" of v1: the handshake server is the rendezvous point that
// every buddy learns the roster from. A peer-to-peer gossip overlay (peers
// relaying rosters to each other) is a v2 concern; merging the server's signed
// list keeps v1 simple while still populating the offline cache.
func (r *Registry) Merge(selfPubKey string, list []protocol.Peer) []protocol.Peer {
	now := time.Now().Unix()
	merged := make([]protocol.Peer, 0, len(list))
	for _, p := range list {
		if p.PubKey == "" || p.PubKey == selfPubKey {
			continue
		}
		p.LastSeen = now
		_ = r.Upsert(p)
		merged = append(merged, p)
	}
	return merged
}

// Fresh reports whether a cached peer was seen within ttl. A buddy uses this to
// decide whether a cached endpoint is worth trying before giving up when the
// handshake server is unreachable.
func Fresh(p protocol.Peer, ttl time.Duration) bool {
	if p.LastSeen == 0 {
		return false
	}
	return time.Since(time.Unix(p.LastSeen, 0)) <= ttl
}
