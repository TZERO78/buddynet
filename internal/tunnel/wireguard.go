package tunnel

import "context"

// WireGuardTransport is the v2 seam. The whole point of the Transport interface
// is that a WireGuard data plane can replace QUIC without the buddy/relay/
// handshake roles changing: same Listen/Dial/Session/Stream shape, different
// bytes on the wire. v1 ships on QUIC (TLS 1.3, already end-to-end encrypted,
// and relay-blind), so this implementation is intentionally inert and returns
// ErrNotImplemented — it exists to keep the seam honest and compiled.
//
// A v2 implementation would, on the same punched UDP socket:
//   - run a userspace WireGuard device (golang.zx2c4.com/wireguard) keyed by the
//     two nodes' X25519 keys derived from their Ed25519 identities (see the
//     ed25519->x25519 mapping in package crypto),
//   - assign each end its deterministic 10.66.0.X virtual IP, and
//   - expose the resulting tun as Streams (or carry a small mux over the tunnel)
//     so the layers above are unchanged.
type WireGuardTransport struct{}

// NewWireGuard returns the inert v1 placeholder. It takes no arguments today; a
// v2 build would accept the punched socket and the two identities, mirroring
// NewQUIC.
func NewWireGuard() *WireGuardTransport { return &WireGuardTransport{} }

func (t *WireGuardTransport) Listen(ctx context.Context) (Session, error) {
	return nil, ErrNotImplemented
}

func (t *WireGuardTransport) Dial(ctx context.Context, endpoint string) (Session, error) {
	return nil, ErrNotImplemented
}

func (t *WireGuardTransport) Close() error { return nil }

// compile-time assertion that the seam really satisfies the interface.
var _ Transport = (*WireGuardTransport)(nil)
