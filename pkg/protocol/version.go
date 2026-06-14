// Package protocol is the single source of truth for the BuddyNet control-plane
// protocol: the messages exchanged over UDP between buddies, relays, and the
// handshake server, and the canonical bytes that get signed and verified.
//
// It is imported by every role (buddy, relay, handshake), so the wire format
// and the signed payloads have ONE definition. A one-byte drift between two
// implementations would silently break signature verification, so anything that
// crosses the wire or is fed to a signature lives here and nowhere else.
package protocol

// Version is the control-plane protocol version. Every message stamps it
// (Message.Ver) so an incompatible build is reported clearly ("server speaks
// v2, we speak v1 — update buddynet") instead of failing as an opaque signature
// error. Bump it on ANY breaking change to the message format or to the bytes
// covered by a signature.
const Version = 1

// MaxFieldLen bounds untrusted string fields (token, id, pubkey, virtual IP)
// before they are used as map keys on a server that takes raw internet input.
const MaxFieldLen = 128

// Default listen addresses for the server roles. These are the ONE definition of
// the well-known ports: the CLI defaults, the usage/help text, and the shipped
// deployment artifacts (Dockerfile, compose, firewall rules) all derive from
// these. The operator always overrides them with --listen / --relay-listen (or
// the BUDDYNET_HANDSHAKE_PORT / BUDDYNET_RELAY_PORT env in compose); these are
// only the fallback when nothing is set. Dual-stack [::] also accepts IPv4.
const (
	DefaultHandshakeAddr = "[::]:51820"
	DefaultRelayAddr     = "[::]:51821"
)
