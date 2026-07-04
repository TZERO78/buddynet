// Package tunnel is the default data plane: it brings up an end-to-end-encrypted,
// multiplexed session between two nodes and carries plain TCP across it. The
// transport is hidden behind an interface; the shipping implementation is QUIC
// (TLS 1.3, multiplexed streams).
//
// The opt-in kernel-WireGuard data plane (--wireguard, internal/wg +
// internal/role/wgpath.go) is deliberately NOT a Transport: it is packet/L3
// oriented (one kernel WG interface per buddy, the partner reachable natively at
// its VIP), so it cannot satisfy the stream-shaped Session contract below
// (OpenStream/CloseWrite/ExportKeyingMaterial). It is a separate, parallel plane
// that reuses the same control plane and fallback chain — see docs/WIREGUARD.md.
//
// The session model matches the BuddyNet stream layout:
//
//	Session (one encrypted connection between two nodes)
//	  ├── Stream: control   (REGISTER / PEER_LIST / RELAY_OFFER ride here)
//	  ├── Stream: data      (the forwarded TCP payload)
//	  └── Stream: keepalive (PING / PONG every ~25s)
//
// A Transport establishes a Session; a Session multiplexes Streams. (The v1
// interface sketch wrote Dial as returning a Stream directly; QUIC and the
// stream layout above are inherently multi-stream, so the real interface
// returns a Session that mints Streams — the same idea, made correct.)
package tunnel

import (
	"context"
	"io"
	"net"
)

// Stream is one bidirectional, ordered byte stream within a Session. CloseWrite
// half-closes the send direction (signals EOF to the peer) while still draining
// the receive direction — exactly what request/response tools like rsync rely
// on after they finish sending.
type Stream interface {
	io.ReadWriteCloser
	CloseWrite() error
}

// Session is one encrypted connection between two nodes. Whichever side took the
// listening role accepts streams the other opens, and vice versa; both can do
// both at once.
type Session interface {
	// OpenStream opens a new outbound stream.
	OpenStream(ctx context.Context) (Stream, error)
	// AcceptStream blocks for the next inbound stream the peer opens.
	AcceptStream(ctx context.Context) (Stream, error)
	// RemoteAddr is the peer's transport address.
	RemoteAddr() net.Addr
	// ExportKeyingMaterial returns RFC 5705 exported keying material from the
	// underlying TLS session (channel binding). Both ends of the same session
	// derive identical bytes, so it ties a value (e.g. the SAS) cryptographically
	// to THIS connection — a man in the middle, who terminates a different TLS
	// session to each side, cannot make the two ends agree on it.
	ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
	// Done is closed when the session ends; Close tears it down.
	Done() <-chan struct{}
	Close() error
}

// Transport establishes Sessions. The two ends of a punched path take opposite
// roles — one Listen()s, the other Dial()s — chosen deterministically by the
// caller (lower public key listens) so both never pick the same role.
type Transport interface {
	// Listen waits for the peer to dial and returns the accepted Session.
	Listen(ctx context.Context) (Session, error)
	// Dial connects to endpoint and returns the established Session.
	Dial(ctx context.Context, endpoint string) (Session, error)
	// Close releases the transport's socket/resources.
	Close() error
}
