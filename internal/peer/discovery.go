package peer

import (
	"time"

	"github.com/tzero78/buddynet/pkg/protocol"
)

// Fresh reports whether a cached peer was seen within ttl. A buddy uses this to
// decide whether a cached endpoint is worth trying before giving up when the
// handshake server is unreachable.
func Fresh(p protocol.Peer, ttl time.Duration) bool {
	if p.LastSeen == 0 {
		return false
	}
	return time.Since(time.Unix(p.LastSeen, 0)) <= ttl
}
