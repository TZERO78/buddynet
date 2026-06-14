package protocol

import "encoding/json"

// Type is the discriminator of a control-plane message. One UDP datagram is one
// JSON-encoded Message; Type selects which fields are meaningful.
type Type string

const (
	// TypeRegister is sent by a peer (buddy or relay) to the handshake server:
	// "here is who I am and where I can be reached." Carries Role, PubKey,
	// VirtualIP and the server-observed Endpoint is filled in by the server.
	TypeRegister Type = "REGISTER"

	// TypePeerList is the handshake server's reply: the set of peers a node may
	// talk to. In 2-peer (BuddyPeer) mode this is exactly the one partner that
	// shares the token; in network mode it is the gossiped roster. Signed by the
	// server so a man in the middle cannot inject or alter peers.
	TypePeerList Type = "PEER_LIST"

	// TypeRelayOffer advertises a relay a buddy can fall back to when a direct
	// hole punch fails. From/To are virtual IPs; RelayEndpoint is the relay's
	// public address and RelayPubKey lets the buddy pin it.
	TypeRelayOffer Type = "RELAY_OFFER"

	// TypeConnect is the first frame a buddy sends to a relay (or directly to a
	// peer) to open a session: it names both identities and carries a
	// short-lived SessionToken that the relay uses to pair the two legs without
	// ever seeing plaintext.
	TypeConnect Type = "CONNECT"

	// TypePing / TypePong are the keepalive pair, exchanged every ~25s to keep
	// NAT mappings and registrations fresh.
	TypePing Type = "PING"
	TypePong Type = "PONG"
)

// Role is the explicit role a node runs as. BuddyNet never auto-detects a role;
// the operator always sets --role.
type Role string

const (
	RoleBuddy     Role = "buddy"     // ordinary peer; NAT is fine
	RoleRelay     Role = "relay"     // public IP; blindly forwards encrypted bytes
	RoleHandshake Role = "handshake" // bootstrap/matchmaking server on a VPS
)

// Candidate is one reachable transport endpoint of a peer, as observed by the
// handshake server. IPv6 candidates are tried first (no NAT to punch).
type Candidate struct {
	Addr string `json:"addr"`         // "ip:port"
	V6   bool   `json:"v6,omitempty"` // true => IPv6, try first
}

// Peer is one entry in a PEER_LIST: everything a buddy needs to reach another
// peer. VirtualIP is the deterministic 10.66.0.X derived from PubKey (see
// package crypto); Relay, when set, is a relay endpoint to use if the direct
// path fails.
type Peer struct {
	ID         string      `json:"id"`
	PubKey     string      `json:"pubkey"`               // base64 Ed25519 identity
	VirtualIP  string      `json:"virtual_ip"`           // 10.66.0.X
	Candidates []Candidate `json:"candidates,omitempty"` // observed endpoints
	Relay      string      `json:"relay,omitempty"`      // relay endpoint, if any
	LastSeen   int64       `json:"last_seen,omitempty"`  // unix seconds
}

// Message is the entire control-plane wire format: one JSON object per UDP
// datagram. Fields are shared across Types and tagged omitempty so each message
// carries only what it needs.
type Message struct {
	Type Type `json:"type"`
	Ver  int  `json:"ver"` // sender's protocol Version; mismatch is reported clearly

	// Identity / pairing (REGISTER).
	Token     string `json:"token,omitempty"`      // shared secret pairing two buddies
	Role      Role   `json:"role,omitempty"`       // sender's role
	ID        string `json:"id,omitempty"`         // ephemeral per-run id
	PubKey    string `json:"pubkey,omitempty"`     // base64 Ed25519 identity
	VirtualIP string `json:"virtual_ip,omitempty"` // sender's 10.66.0.X

	// Key-ownership proof for an allowlist (approval-mode) handshake server: the
	// peer signs RegistrationPayload(token,id,pubkey,ts) with its private key.
	Ts     int64  `json:"ts,omitempty"`
	RegSig string `json:"reg_sig,omitempty"`

	// Optional enrollment code, sealed to the server's identity key, so an
	// operator can approve by a short code instead of the long public key.
	CodeEnc string `json:"code_enc,omitempty"`

	// PEER_LIST payload (server -> peer). Peers is the roster; Sig is the
	// server's signature over PeerListPayload(token, ts, peers).
	Peers []Peer `json:"peers,omitempty"`
	Sig   string `json:"sig,omitempty"`

	// RELAY_OFFER payload.
	From          string `json:"from,omitempty"`           // virtual IP
	To            string `json:"to,omitempty"`             // virtual IP
	RelayEndpoint string `json:"relay_endpoint,omitempty"` // host:port
	RelayPubKey   string `json:"relay_pubkey,omitempty"`   // pin the relay

	// CONNECT payload (buddy -> relay/peer).
	FromPubKey   string `json:"from_pubkey,omitempty"`
	ToPubKey     string `json:"to_pubkey,omitempty"`
	SessionToken string `json:"session_token,omitempty"`
}

// PeerListPayload is the exact byte string the handshake server signs and a
// buddy must reconstruct to verify a PEER_LIST: the pairing token, a unix
// timestamp, and the peer roster. Binding the token and timestamp means a
// signed roster is valid only for THIS token and only within a freshness
// window, so an old one cannot be replayed. Peers MUST already be in canonical
// (ID-sorted) order so signer and verifier produce identical bytes.
func PeerListPayload(token string, ts int64, peers []Peer) []byte {
	b, _ := json.Marshal(struct {
		Token string `json:"token"`
		Ts    int64  `json:"ts"`
		Peers []Peer `json:"peers"`
	}{token, ts, peers})
	return b
}

// RegistrationPayload is the canonical byte string a peer signs to prove it owns
// the public key it registers (approval mode). The server reconstructs it from
// the received fields and verifies the signature against PubKey.
func RegistrationPayload(token, id, pubkey string, ts int64) []byte {
	b, _ := json.Marshal(struct {
		Token  string `json:"token"`
		ID     string `json:"id"`
		PubKey string `json:"pubkey"`
		Ts     int64  `json:"ts"`
	}{token, id, pubkey, ts})
	return b
}
