package role

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/tzero78/buddynet/internal/relay"
	"github.com/tzero78/buddynet/internal/ticket"
	"github.com/tzero78/buddynet/pkg/protocol"
)

// relayCred is one buddy's credentials for ONE relay session: a throwaway
// Ed25519 key pair, and the server-signed ticket issued against it.
//
// The key is minted per connection attempt and never persisted, never derived
// from the identity key and never reused. That is what turns the ticket from a
// bearer token into a permit only this process can spend: a ticket seen on the
// wire — or lifted from a compromised relay — is inert without the private half,
// which never leaves here.
//
// A buddy with no ticket is a normal state, not a broken one: the server may
// have no relay configured at all. It then simply has no relay fallback.
type relayCred struct {
	priv ed25519.PrivateKey
	pub  string // base64url, what travels as REGISTER epk

	// Filled in from the PEER_LIST when the server issues a ticket.
	payload []byte // the signed bytes, verbatim as received
	sig     []byte
	sid     string // the session id the SERVER named for this pairing
}

// newRelayCred mints the ephemeral key for one attempt.
func newRelayCred() (*relayCred, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mint the ephemeral relay key: %w", err)
	}
	return &relayCred{priv: priv, pub: base64.RawURLEncoding.EncodeToString(pub)}, nil
}

// adopt takes the ticket off a PEER_LIST after checking it is the one this buddy
// can actually use. The checks are not a security boundary — the relay repeats
// every one of them, and it is the relay that has to be convinced — they are
// there so a mismatch is reported HERE, where the diagnosis is possible, instead
// of surfacing as an unexplained relay timeout later.
//
// Two of them are worth naming:
//
//   - the ticket must be bound to OUR ephemeral key. A ticket for another epk is
//     one we cannot prove possession of, so binding with it would fail at the
//     relay for a reason no log on this side would explain.
//   - the signature is NOT re-verified here against the server key, on purpose:
//     the bytes must be forwarded verbatim, and re-deriving them from a parsed
//     structure is exactly the canonicalisation bug the format avoids. What this
//     buddy needs from the payload is the session id, which the relay checks
//     against the signed copy anyway.
func (c *relayCred) adopt(rt *protocol.RelayTicket) error {
	if c == nil || rt == nil {
		return errors.New("no relay ticket in this roster")
	}
	payload, err := base64.RawURLEncoding.DecodeString(rt.Payload)
	if err != nil {
		return errors.New("relay ticket payload is not base64url")
	}
	sig, err := base64.RawURLEncoding.DecodeString(rt.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("relay ticket signature is malformed")
	}
	p, err := ticket.Parse(payload)
	if err != nil {
		return fmt.Errorf("relay ticket is malformed: %w", err)
	}
	if p.EPK != c.pub {
		return errors.New("relay ticket is bound to a different ephemeral key — it cannot be used by this buddy")
	}
	c.payload, c.sig, c.sid = payload, sig, p.SID
	return nil
}

// have reports whether a usable ticket was adopted.
func (c *relayCred) have() bool { return c != nil && c.sid != "" }

// bindCred renders the credentials for relay.BindLeg, or nil when there is no
// ticket — in which case the bind is the plain one, which only a relay in
// network mode accepts.
func (c *relayCred) bindCred() *relay.BindCred {
	if !c.have() {
		return nil
	}
	return &relay.BindCred{Payload: c.payload, Sig: c.sig, Eph: c.priv}
}

// session returns the id to bind legs under: the server-named one when a ticket
// was issued, otherwise the value both buddies derive from the pairing token.
//
// The distinction matters for who decides. With a ticket the SERVER names the
// session, so two legs meet only if it put them together; without one the id is
// derived from a secret only the pair shares, which is all a network-mode relay
// ever had.
func (c *relayCred) session(derived string) string {
	if c.have() {
		return c.sid
	}
	return derived
}

// epk returns the ephemeral public key to register, or "" when there is no
// credential (the probe path, which never binds a relay leg).
func (c *relayCred) epk() string {
	if c == nil {
		return ""
	}
	return c.pub
}
