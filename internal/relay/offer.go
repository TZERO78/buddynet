// Package relay carries a session when a direct hole punch fails. The relay is
// a blind UDP forwarder: two buddies each bind a "leg" to it under a shared
// session token, and the relay pipes datagrams between the two legs without ever
// terminating the QUIC/TLS the buddies run end to end. It therefore sees only
// encrypted QUIC packets — virtual IPs and ciphertext, never content.
//
// This file is the signaling: the RELAY_OFFER a handshake server (or a buddy)
// uses to advertise a relay, and the tiny bind handshake a buddy speaks to the
// relay to claim its leg of a session.
package relay

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/tzero78/buddynet/pkg/protocol"
)

// BindPrefix tags a relay control datagram so the relay can tell a bind request
// from the QUIC data it forwards. QUIC's first byte is never our prefix, so
// there is no ambiguity.
const BindPrefix = "BNRELAY1"

// ChallengePrefix tags a relay's address-validation challenge. The relay sends
// it (carrying an opaque cookie) when a bind arrives without a valid cookie; the
// buddy echoes the cookie on its next bind to prove return-routability. The
// challenge is a fixed, compact binary message (prefix + raw cookie bytes). The
// sender compares its length against the received datagram and stays silent when
// it would not be strictly smaller — the same gate the handshake server's cookie
// has, and the actual anti-amplification control here (MinSessionTokenLen happens
// to keep it out of reach of honest traffic, but does not replace it). It closes the relay's
// only reflection/traffic-laundering vector: without it, a spoofed bind could
// register a victim's address as a leg and have attacker data forwarded to it.
const ChallengePrefix = "BNRLYC1"

// CookieLen is the length of the raw address-validation cookie a relay mints.
const CookieLen = 16

// MinSessionTokenLen is the shortest session token a relay will act on.
//
// This is a WIRE-POLICY TIGHTENING introduced by this branch, not a pre-existing
// rule — the relay used to accept a single character. It stands on its own
// security argument: the session token is the ONLY thing that splices two legs
// together, so a short one is guessable, and a third party that hits it lands in
// someone else's session (the leg cap then costs the real partner its slot).
//
// Compatibility: every buddy derives this token in role.sessionToken as 16 bytes
// of SHA-256 rendered base64url — 22 characters, always, in every released
// version. No client has ever sent anything shorter, so the floor rejects nothing
// that exists. An operator cannot set it by hand; it is derived, never configured.
//
// It is NOT the anti-amplification control. That is the length comparison in
// Server.bind, which holds whatever this constant is set to. The two are
// independent: this bounds guessability, the gate bounds the reply. A side effect
// is that the gate never fires on honest traffic — the smallest bind admitted here
// is 32 bytes against a 23-byte challenge.
const MinSessionTokenLen = 16

// Bind is the control message a buddy sends a relay to claim one leg of a
// session. Two legs presenting the same SessionToken are spliced together. The
// relay echoes the bind back as an ack. Cookie carries back the relay's
// address-validation challenge (base64); it is empty on the first bind.
//
// In TICKET MODE (the relay was given a handshake server's public key) the three
// ticket fields are mandatory and SessionToken must equal the session id inside
// the ticket: the SERVER names the session, so two legs can only meet if it put
// them together. In network mode (--allow-cidr alone) they are absent and the
// token is the buddy-derived value it has always been.
type Bind struct {
	SessionToken string `json:"s"`
	Cookie       string `json:"c,omitempty"`
	// Ticket and TicketSig are the server-signed permit, base64url, passed through
	// verbatim from the PEER_LIST — the relay verifies the signature over exactly
	// these bytes before parsing them.
	Ticket    string `json:"t,omitempty"`
	TicketSig string `json:"ts,omitempty"`
	// BindSig is the proof of possession: a signature by the EPHEMERAL private key
	// the ticket names, over the ticket and THIS relay's current cookie. It is what
	// makes a captured ticket (or a captured bind) worthless to anyone else.
	BindSig string `json:"b,omitempty"`
}

// Wire bounds for the ticket-carrying fields, checked before anything is
// decoded. A bind is refused outright above MaxBindLen, so an oversized
// datagram costs one length comparison rather than a JSON parse.
const (
	// MaxBindLen bounds the whole bind datagram. A real ticketed bind is ~520
	// bytes; the headroom is for a future field, not for a parser to chew on.
	MaxBindLen = 1024
	// maxTicketB64 is the base64url length of the largest ticket payload the
	// verifier will look at (internal/ticket caps the decoded form at 512).
	maxTicketB64 = 700
	// maxSigB64 bounds a base64url Ed25519 signature (64 bytes -> 86 chars).
	maxSigB64 = 96
)

// MarshalBind encodes a bind control datagram: BindPrefix || JSON(Bind).
func MarshalBind(b Bind) []byte {
	body, _ := json.Marshal(b)
	out := make([]byte, 0, len(BindPrefix)+len(body))
	out = append(out, BindPrefix...)
	return append(out, body...)
}

// ParseBind decodes a bind control datagram, reporting ok=false for anything
// that is not one (i.e. QUIC data to forward, or a challenge).
//
// This is step 1 of the relay's fixed check order: every field is length-bounded
// here, before any of it is looked at, so an unvalidated source can never make
// the relay decode a large blob — let alone verify a signature over one.
func ParseBind(pkt []byte) (Bind, bool) {
	if len(pkt) < len(BindPrefix) || len(pkt) > MaxBindLen || string(pkt[:len(BindPrefix)]) != BindPrefix {
		return Bind{}, false
	}
	var b Bind
	if json.Unmarshal(pkt[len(BindPrefix):], &b) != nil ||
		len(b.SessionToken) < MinSessionTokenLen ||
		len(b.SessionToken) > protocol.MaxFieldLen || len(b.Cookie) > protocol.MaxFieldLen ||
		len(b.Ticket) > maxTicketB64 || len(b.TicketSig) > maxSigB64 || len(b.BindSig) > maxSigB64 {
		return Bind{}, false
	}
	return b, true
}

// MarshalChallenge encodes an address-validation challenge: ChallengePrefix ||
// raw cookie bytes. It is deliberately compact (and smaller than a bind) so it
// is never an amplifier.
func MarshalChallenge(cookie []byte) []byte {
	out := make([]byte, 0, len(ChallengePrefix)+len(cookie))
	out = append(out, ChallengePrefix...)
	return append(out, cookie...)
}

// ParseChallenge decodes a challenge datagram, returning the raw cookie bytes
// and ok=true, or ok=false for anything that is not a challenge.
func ParseChallenge(pkt []byte) ([]byte, bool) {
	if len(pkt) != len(ChallengePrefix)+CookieLen || string(pkt[:len(ChallengePrefix)]) != ChallengePrefix {
		return nil, false
	}
	return pkt[len(ChallengePrefix):], true
}

// BindLeg claims this node's leg of a session on the relay over conn: it sends
// bind datagrams ~5x/second until the relay echoes an ack (which also opens the
// NAT path back), then returns. The relay first answers with an address-
// validation challenge (a cookie); BindLeg adopts the cookie and re-binds with
// it, proving return-routability before the relay creates any state — so a
// spoofed source can never have a leg bound on its behalf. The SAME conn must
// then be used to run QUIC, with the relay's address as the peer endpoint, so
// the relay forwards the punched/QUIC packets to the partner's leg.
func BindLeg(conn *net.UDPConn, relayAddr *net.UDPAddr, token string, timeout time.Duration) error {
	cookie := ""
	req := MarshalBind(Bind{SessionToken: token})
	deadline := time.Now().Add(timeout)
	next := time.Now()
	buf := make([]byte, 1500)
	for time.Now().Before(deadline) {
		if !time.Now().Before(next) {
			conn.WriteToUDP(req, relayAddr)
			next = time.Now().Add(200 * time.Millisecond)
		}
		conn.SetReadDeadline(next)
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if !sameAddr(src, relayAddr) {
			continue
		}
		// Address-validation challenge: adopt the cookie and re-bind at once
		// (proving return-routability) rather than waiting for the next tick.
		if c, ok := ParseChallenge(buf[:n]); ok {
			next64 := base64.RawURLEncoding.EncodeToString(c)
			if next64 != cookie {
				cookie = next64
				req = MarshalBind(Bind{SessionToken: token, Cookie: cookie})
				next = time.Now()
			}
			continue
		}
		if b, ok := ParseBind(buf[:n]); ok && b.SessionToken == token {
			conn.SetReadDeadline(time.Time{})
			return nil // relay acked our leg
		}
	}
	return errors.New("relay did not acknowledge the session (unreachable or wrong endpoint)")
}

func sameAddr(a, b *net.UDPAddr) bool {
	return a.Port == b.Port && a.IP.Equal(b.IP)
}
