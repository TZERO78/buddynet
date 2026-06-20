package role

import "fmt"

// MaxBuddies is the hard limit on simultaneous peers in one BuddyNet node.
// BuddyNet is a personal P2P overlay for small, trusted groups — it is NOT a
// large-scale mesh VPN. For deployments needing more than 48 peers, use a
// solution designed for large-scale meshes instead.
//
// The limit is enforced at:
//   - --peers-file loading / peer assembly (assemblePeers)
//   - the session-store multi-peer path (Buddy)
//   - the supervisor (defensive belt-and-suspenders)
//   - `peers add`
//
// 48 peers = 1128 possible connection pairs (fully meshed).
// VIP birthday collision probability at 48 nodes: ~1.7% (acceptable).
// Above ~80 nodes the deterministic /16 space becomes a reliability risk.
//
// This is a DESIGN limit, not a performance one — there is deliberately no
// flag to raise it.
const MaxBuddies = 48

// errTooManyBuddies is the canonical over-limit error: it states the cap and the
// offending count, and points (without naming any product — operators choose
// their own) at scalable alternatives, so the message communicates the design
// decision wherever it surfaces.
func errTooManyBuddies(found int) error {
	return fmt.Errorf(
		"buddynet supports at most %d simultaneous peers (found %d); "+
			"for larger deployments use a solution designed for large-scale meshes",
		MaxBuddies, found,
	)
}
