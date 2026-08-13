// Package ticket is the relay authorization ticket: a short-lived, server-signed
// permit that lets a relay verify THAT a session was authorized without learning
// WHO is in it.
//
// The handshake server mints one per buddy alongside a PEER_LIST and signs it
// with its identity key; the relay holds only the matching PUBLIC key, so a
// compromised relay can withhold service (which it can do by being offline
// anyway) but can never authorize a session, nor forge one for another relay.
//
// Two properties carry the security, and both live in this package:
//
//   - The signature covers the EXACT bytes that travel. A ticket is an opaque
//     byte string on the wire; the relay verifies the signature over what it
//     received and parses only afterwards. There is no canonicalisation step —
//     re-serialising a parsed structure and hoping it matches the signed form is
//     how signature checks get bypassed.
//   - A bare ticket would be a BEARER token. It is therefore bound to a fresh
//     ephemeral public key (epk) that the buddy generates per relay session, and
//     the relay bind must carry a signature made with the matching private key
//     over the relay's own address-validation cookie (see BindSigningBytes). A
//     captured ticket, or a captured bind, is inert without that private key.
//
// The package is deliberately neutral — it imports nothing from the tree — so
// the relay and the control plane can both use it without importing each other
// (the same reason internal/netkey exists).
package ticket

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// FormatVersion versions the TICKET FORMAT, independent of protocol.Version: a
// ticket may need to change without a protocol bump, and vice versa. A relay
// rejects a version it does not know rather than guessing what the fields mean.
const FormatVersion = 1

// Lifetime bounds. They are enforced by the RELAY, which is the party that has
// to be convinced; the server's intent is not a control.
//
// MaxTTL caps how long a ticket may claim to be valid. Skew is the clock
// tolerance in EACH direction, so the worst-case real lifetime of a ticket
// against a shifted clock is MaxTTL + 2*Skew = 140s, not 120s and not 130s: a
// server whose clock runs Skew ahead issues iat=now+10/exp=now+130 as seen by
// the relay, and that ticket stays acceptable until exp+Skew. That worst case,
// not the nominal one, is the number to reason about when judging exposure.
const (
	MaxTTL = 120 * time.Second
	Skew   = 10 * time.Second
)

// IDLen is the raw byte length of the relay id (rid) and the session id (sid):
// 128 bits each. The rid only has to be unguessable enough that a ticket for one
// relay cannot be replayed at another by picking the right string; the sid names
// the session, so it must be unguessable outright.
const IDLen = 16

// The two legs of a session. Per sid a relay accepts exactly one of each, so a
// third party cannot join a pair even with a valid-looking ticket.
const (
	LegA = "a"
	LegB = "b"
)

// MaxPayloadLen bounds a ticket payload BEFORE it is decoded, so a malformed or
// hostile blob is rejected on a length check rather than by the JSON parser. A
// real payload is ~200 bytes; this leaves room for a future field without
// leaving room for an amplification target.
const MaxPayloadLen = 512

// Domain separation. Both strings are NUL-terminated so no signing context can
// ever be a prefix of another, and the two purposes (a server authorising a
// session, a buddy proving possession of an ephemeral key) can never be
// confused for one another even though both are Ed25519 over attacker-visible
// bytes.
var (
	ticketContext = []byte("buddynet-relay-ticket-v1\x00")
	bindContext   = []byte("buddynet-relay-bind-v1\x00")
)

// Payload is what the server signs. It travels base64url-encoded inside the
// control-plane JSON and reaches the relay as an opaque byte string.
//
// Every id-shaped field is base64url (unpadded) of a fixed raw length, so a
// parsed ticket can never carry an oversized or oddly-encoded value into a map
// key or a log line.
type Payload struct {
	V     int    `json:"v"`     // ticket FORMAT version
	RID   string `json:"rid"`   // which relay this is valid at (IDLen bytes)
	SID   string `json:"sid"`   // relay session id, server-chosen (IDLen bytes)
	Leg   string `json:"leg"`   // "a" or "b": which leg this ticket admits
	EPK   string `json:"epk"`   // ephemeral public key of the buddy that will use it
	IAT   int64  `json:"iat"`   // issued at, unix seconds
	EXP   int64  `json:"exp"`   // absolute expiry, unix seconds
	Nonce string `json:"nonce"` // server-chosen (IDLen bytes)
}

// Reason is a fixed, non-attacker-controlled rejection label. Every refusal path
// carries one so the relay can log WHY a ticket was refused without echoing any
// part of the ticket itself, and so an operator can tell one cause from another
// (the clock case in particular, which otherwise looks like any other refusal).
type Reason string

const (
	ReasonSize       Reason = "payload too large"
	ReasonMalformed  Reason = "payload is not a well-formed ticket"
	ReasonUnknownVer Reason = "unknown ticket version"
	ReasonSignature  Reason = "server signature did not verify"
	ReasonWindow     Reason = "issue/expiry time outside the accepted window"
	ReasonTTL        Reason = "ticket validity span out of bounds"
	ReasonRelay      Reason = "ticket is for a different relay"
	ReasonLeg        Reason = "ticket names no valid leg"
	ReasonProof      Reason = "proof of possession did not verify"
)

// Error is a rejection carrying its Reason. The reason is a constant from this
// package, never derived from the input, so logging it cannot become a log
// injection or a data leak.
type Error struct {
	Reason Reason
}

func (e *Error) Error() string { return string(e.Reason) }

func reject(r Reason) error { return &Error{Reason: r} }

// ReasonOf returns the fixed rejection label of an error from this package, or
// "" for anything else — so a caller can log a reason without type-asserting at
// every site.
func ReasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

// NewID returns IDLen bytes of CSPRNG, base64url-encoded: a fresh rid, sid or
// nonce. crypto/rand cannot fail under Go 1.24+ (it crashes the process itself),
// but the error is returned rather than swallowed so this can never silently
// become a constant id.
func NewID() (string, error) {
	b := make([]byte, IDLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ValidID reports whether s is a well-formed id: exactly the base64url spelling
// of IDLen bytes. Strict on both length and alphabet, so an id is safe as a map
// key and as a log tag before anything else has looked at it.
func ValidID(s string) bool {
	if len(s) != base64.RawURLEncoding.EncodedLen(IDLen) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(raw) == IDLen
}

// Sign marshals p and signs it with the server's identity key, returning the
// EXACT payload bytes that must travel and the signature over them. The caller
// must transmit the returned bytes verbatim: re-marshalling the struct at the
// other end is precisely what this API exists to prevent.
func Sign(priv ed25519.PrivateKey, p Payload) (payload, sig []byte, err error) {
	payload, err = json.Marshal(p)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal ticket: %w", err)
	}
	if len(payload) > MaxPayloadLen {
		// Unreachable with well-formed inputs; a guard so the signer can never mint
		// something the verifier is required to reject on size.
		return nil, nil, fmt.Errorf("ticket payload is %d bytes, over the %d cap", len(payload), MaxPayloadLen)
	}
	return payload, ed25519.Sign(priv, signedBytes(payload)), nil
}

// signedBytes is the domain-separated byte string a ticket signature covers.
func signedBytes(payload []byte) []byte {
	out := make([]byte, 0, len(ticketContext)+len(payload))
	out = append(out, ticketContext...)
	return append(out, payload...)
}

// Verify checks the server signature over the payload bytes AS RECEIVED. It is
// the first cryptographic step on the relay and runs before any parsing, so a
// malformed-but-unsigned blob never reaches the decoder.
//
// It accepts several server keys so a key rotation can be made before-break: the
// relay is configured with the current and the next key and accepts either while
// the handshake server switches over.
func Verify(keys []ed25519.PublicKey, payload, sig []byte) bool {
	if len(payload) == 0 || len(payload) > MaxPayloadLen || len(sig) != ed25519.SignatureSize {
		return false
	}
	msg := signedBytes(payload)
	for _, k := range keys {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, msg, sig) {
			return true
		}
	}
	return false
}

// Parse decodes a ticket payload strictly. It runs only AFTER Verify, so what it
// decodes is known to be exactly what the server signed; the strictness is
// therefore not a security control against an outsider but a guarantee that two
// implementations cannot disagree about what a signed ticket says.
//
// Strict means: a size cap before decoding, unknown fields rejected, DUPLICATE
// keys rejected (encoding/json silently keeps the last one, which would let one
// signed blob be read two ways), trailing data rejected, and every id-shaped
// field checked for exact length and alphabet.
func Parse(payload []byte) (Payload, error) {
	var p Payload
	if len(payload) == 0 || len(payload) > MaxPayloadLen {
		return p, reject(ReasonSize)
	}
	if err := noDuplicateKeys(payload); err != nil {
		return p, err
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, reject(ReasonMalformed)
	}
	// Anything after the object — a second value, trailing garbage — means the
	// blob is not exactly one ticket.
	if _, err := dec.Token(); err != io.EOF {
		return p, reject(ReasonMalformed)
	}
	if p.V != FormatVersion {
		return p, reject(ReasonUnknownVer)
	}
	if !ValidID(p.RID) || !ValidID(p.SID) || !ValidID(p.Nonce) {
		return p, reject(ReasonMalformed)
	}
	if p.Leg != LegA && p.Leg != LegB {
		return p, reject(ReasonLeg)
	}
	if _, err := p.EphPub(); err != nil {
		return p, reject(ReasonMalformed)
	}
	return p, nil
}

// noDuplicateKeys walks the raw token stream and rejects an object that names
// the same key twice. Only the top level is scanned because a ticket payload is
// a flat object by construction — a nested object is already refused as an
// unknown field or a type error by the strict decode that follows.
//
// Each value is consumed WHOLE (json.RawMessage), never token by token: a
// hand-rolled depth counter is how a scanner like this loses track of a nested
// value and starts reading its keys as top-level ones.
func noDuplicateKeys(payload []byte) error {
	dec := json.NewDecoder(bytes.NewReader(payload))
	tok, err := dec.Token()
	if err != nil {
		return reject(ReasonMalformed)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return reject(ReasonMalformed)
	}
	seen := map[string]struct{}{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return reject(ReasonMalformed)
		}
		key, ok := tok.(string)
		if !ok {
			return reject(ReasonMalformed)
		}
		if _, dup := seen[key]; dup {
			return reject(ReasonMalformed)
		}
		seen[key] = struct{}{}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return reject(ReasonMalformed)
		}
	}
	return nil
}

// EphPub decodes the ephemeral public key the ticket is bound to.
func (p Payload) EphPub() (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(p.EPK)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("ticket epk is not an Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

// CheckWindow enforces the lifetime rules against the relay's own clock:
//
//	0 < exp - iat <= MaxTTL     the span the server may claim
//	iat <= now + Skew           not issued implausibly in the future
//	exp >= now - Skew           not expired beyond the grace
//
// The "0 <" is not decoration: equal timestamps (a ticket valid for nothing) and
// a negative span (expiry before issuance) would both sail past a "<= MaxTTL"
// check on its own.
//
// A window failure is reported as its OWN reason, because a relay cannot tell a
// skewed clock from a tampered or wrongly-issued ticket — both look identical
// from here — and an operator needs to be told both possibilities rather than
// being sent to chase NTP while someone replays stale tickets.
func (p Payload) CheckWindow(now time.Time) error {
	span := p.EXP - p.IAT
	if span <= 0 || span > int64(MaxTTL/time.Second) {
		return reject(ReasonTTL)
	}
	sec := now.Unix()
	skew := int64(Skew / time.Second)
	if p.IAT > sec+skew || p.EXP < sec-skew {
		return reject(ReasonWindow)
	}
	return nil
}

// CheckRelay reports whether the ticket names this relay. Compared in whole, not
// by prefix, and against the relay's configured rid rather than its address:
// address, DNS name and port all change, and a ticket bound to a moving value
// either breaks on a migration or has to be reissued for cosmetic reasons.
func (p Payload) CheckRelay(rid string) error {
	if rid == "" || p.RID != rid {
		return reject(ReasonRelay)
	}
	return nil
}

// BindSigningBytes is what the buddy signs with its EPHEMERAL private key to
// prove possession, and what the relay reconstructs to check it:
//
//	"buddynet-relay-bind-v1\0" || SHA-256(payload || sig) || cookie
//
// Hashing payload||sig ties the bind to the COMPLETE ticket — version, rid, sid,
// leg, epk, iat, exp and nonce included — so no field can be swapped without
// invalidating the proof.
//
// The cookie is what stops replay, and it is the only value here that could do
// it: it is fresh, relay-chosen, bound to the source address and already rotates
// every 30-60s. Without it in the signature a captured bind could be resent by
// anyone who can reach the relay for as long as the ticket lives. With it, a
// copied bind is worth nothing from another address or after the cookie epoch
// turns — and the attacker cannot re-sign, because the ephemeral private key
// never leaves the buddy.
func BindSigningBytes(payload, sig, cookie []byte) []byte {
	sum := sha256.Sum256(append(append([]byte{}, payload...), sig...))
	out := make([]byte, 0, len(bindContext)+len(sum)+len(cookie))
	out = append(out, bindContext...)
	out = append(out, sum[:]...)
	return append(out, cookie...)
}

// SignBind produces the proof of possession for one bind.
func SignBind(eph ed25519.PrivateKey, payload, sig, cookie []byte) []byte {
	return ed25519.Sign(eph, BindSigningBytes(payload, sig, cookie))
}

// VerifyBind checks the proof of possession against the epk the TICKET names —
// never against a key supplied by the bind itself, which would prove nothing.
func VerifyBind(epk ed25519.PublicKey, payload, sig, cookie, bindSig []byte) error {
	if len(epk) != ed25519.PublicKeySize || len(bindSig) != ed25519.SignatureSize {
		return reject(ReasonProof)
	}
	if !ed25519.Verify(epk, BindSigningBytes(payload, sig, cookie), bindSig) {
		return reject(ReasonProof)
	}
	return nil
}

// ShortSID is the log form of a session id: enough to correlate the two legs of
// one session within one relay log, deliberately not enough to link a session to
// a buddy. The full sid never reaches a log line.
func ShortSID(sid string) string {
	if len(sid) > 8 {
		return sid[:8]
	}
	return sid
}
