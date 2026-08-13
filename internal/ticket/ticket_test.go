package ticket

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// mint builds a valid ticket for a fresh ephemeral key, the way the handshake
// server does. Every negative test below starts from this and breaks ONE thing,
// so a refusal can only be caused by what the test changed.
func mint(t *testing.T, mut func(*Payload)) (server ed25519.PublicKey, eph ed25519.PrivateKey, payload, sig []byte, p Payload, rid string) {
	t.Helper()
	spub, spriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	epub, epriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ephemeral key: %v", err)
	}
	rid, err = NewID()
	if err != nil {
		t.Fatalf("rid: %v", err)
	}
	sid, err := NewID()
	if err != nil {
		t.Fatalf("sid: %v", err)
	}
	nonce, err := NewID()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	now := time.Now()
	p = Payload{
		V:     FormatVersion,
		RID:   rid,
		SID:   sid,
		Leg:   LegA,
		EPK:   base64.RawURLEncoding.EncodeToString(epub),
		IAT:   now.Unix(),
		EXP:   now.Add(MaxTTL).Unix(),
		Nonce: nonce,
	}
	if mut != nil {
		mut(&p)
	}
	payload, sig, err = Sign(spriv, p)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return spub, epriv, payload, sig, p, rid
}

// accept runs the relay's full ticket check in the same order the relay does, so
// every test below exercises the real decision path rather than one predicate.
func accept(keys []ed25519.PublicKey, payload, sig, cookie, bindSig []byte, rid string, now time.Time) error {
	if !Verify(keys, payload, sig) {
		return reject(ReasonSignature)
	}
	p, err := Parse(payload)
	if err != nil {
		return err
	}
	if err := p.CheckWindow(now); err != nil {
		return err
	}
	if err := p.CheckRelay(rid); err != nil {
		return err
	}
	epk, err := p.EphPub()
	if err != nil {
		return reject(ReasonMalformed)
	}
	return VerifyBind(epk, payload, sig, cookie, bindSig)
}

// TestValidTicketIsAccepted is the positive control: without it every assertion
// below could be satisfied by a check that refuses everything.
func TestValidTicketIsAccepted(t *testing.T) {
	spub, eph, payload, sig, _, rid := mint(t, nil)
	cookie := []byte("cookie-0123456789")
	bs := SignBind(eph, payload, sig, cookie)
	if err := accept([]ed25519.PublicKey{spub}, payload, sig, cookie, bs, rid, time.Now()); err != nil {
		t.Fatalf("a valid ticket with a valid proof of possession was refused: %v", err)
	}
}

// TestTicketRejections covers plan cases 2-11 and 39: everything that must be
// refused about the ticket ITSELF. Each case starts from a valid ticket.
func TestTicketRejections(t *testing.T) {
	future := time.Now().Add(24 * time.Hour)
	past := time.Now().Add(-24 * time.Hour)

	tests := []struct {
		name string
		// mut alters the payload BEFORE signing (a wrongly-issued ticket).
		mut func(*Payload)
		// tamper alters the signed bytes AFTER signing (an attacker on the wire).
		tamper func(payload, sig []byte) (outPayload, outSig []byte)
		// otherKey signs with a different server key entirely.
		otherKey bool
		now      time.Time
		want     Reason
	}{
		{
			name:   "signature bit-flipped",
			tamper: func(p, s []byte) ([]byte, []byte) { s[0] ^= 0x01; return p, s },
			want:   ReasonSignature,
		},
		{
			name:   "payload altered after signing",
			tamper: func(p, s []byte) ([]byte, []byte) { return append([]byte{}, append(p[:len(p)-1], ' ', '}')...), s },
			want:   ReasonSignature,
		},
		{
			name:     "signed by a different server key",
			otherKey: true,
			want:     ReasonSignature,
		},
		{
			name: "iat missing",
			tamper: func(p, s []byte) ([]byte, []byte) {
				// Dropping a field changes the bytes, so the signature must fail first —
				// which is the point: a field cannot be removed in flight either.
				return []byte(strings.Replace(string(p), `"iat"`, `"xat"`, 1)), s
			},
			want: ReasonSignature,
		},
		{
			name: "iat far in the future",
			mut:  func(p *Payload) { p.IAT = future.Unix(); p.EXP = future.Add(MaxTTL).Unix() },
			want: ReasonWindow,
		},
		{
			name: "validity span over the cap",
			mut:  func(p *Payload) { p.EXP = p.IAT + int64(MaxTTL/time.Second) + 1 },
			want: ReasonTTL,
		},
		{
			name: "expired beyond the skew grace",
			mut:  func(p *Payload) { p.IAT = past.Unix(); p.EXP = past.Add(time.Minute).Unix() },
			want: ReasonWindow,
		},
		{
			name: "exp equals iat",
			mut:  func(p *Payload) { p.EXP = p.IAT },
			want: ReasonTTL,
		},
		{
			name: "exp before iat",
			mut:  func(p *Payload) { p.EXP = p.IAT - 1 },
			want: ReasonTTL,
		},
		{
			name: "unknown ticket version",
			mut:  func(p *Payload) { p.V = FormatVersion + 1 },
			want: ReasonUnknownVer,
		},
		{
			name: "no valid leg",
			mut:  func(p *Payload) { p.Leg = "c" },
			want: ReasonLeg,
		},
		{
			name: "sid is not a well-formed id",
			mut:  func(p *Payload) { p.SID = "short" },
			want: ReasonMalformed,
		},
		{
			name: "epk is not an Ed25519 key",
			mut:  func(p *Payload) { p.EPK = base64.RawURLEncoding.EncodeToString([]byte("too short")) },
			want: ReasonMalformed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spub, eph, payload, sig, _, rid := mint(t, tc.mut)
			keys := []ed25519.PublicKey{spub}
			if tc.otherKey {
				other, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("other key: %v", err)
				}
				keys = []ed25519.PublicKey{other}
			}
			if tc.tamper != nil {
				payload, sig = tc.tamper(payload, sig)
			}
			cookie := []byte("cookie-0123456789")
			bs := SignBind(eph, payload, sig, cookie)
			now := tc.now
			if now.IsZero() {
				now = time.Now()
			}
			err := accept(keys, payload, sig, cookie, bs, rid, now)
			if err == nil {
				t.Fatalf("accepted a ticket that must be refused (%s)", tc.want)
			}
			if got := ReasonOf(err); got != tc.want {
				t.Fatalf("refused for %q, want %q", got, tc.want)
			}
		})
	}
}

// TestTicketForAnotherRelay is plan case 9: a ticket minted for relay A must be
// worthless at relay B, whose rid is different.
func TestTicketForAnotherRelay(t *testing.T) {
	spub, eph, payload, sig, _, _ := mint(t, nil)
	otherRID, err := NewID()
	if err != nil {
		t.Fatalf("rid: %v", err)
	}
	cookie := []byte("cookie-0123456789")
	bs := SignBind(eph, payload, sig, cookie)
	err = accept([]ed25519.PublicKey{spub}, payload, sig, cookie, bs, otherRID, time.Now())
	if ReasonOf(err) != ReasonRelay {
		t.Fatalf("a ticket for another relay was refused as %q, want %q", ReasonOf(err), ReasonRelay)
	}
}

// TestUnknownAndDuplicateFields is plan case 11. Both are refused, and the
// duplicate case matters most: encoding/json silently keeps the LAST value, so
// without an explicit scan one signed blob could be read two ways.
func TestUnknownAndDuplicateFields(t *testing.T) {
	_, _, payload, _, _, _ := mint(t, nil)

	withExtra := strings.Replace(string(payload), `{`, `{"extra":1,`, 1)
	if _, err := Parse([]byte(withExtra)); ReasonOf(err) != ReasonMalformed {
		t.Fatalf("an unknown field parsed (reason %q)", ReasonOf(err))
	}

	// Duplicate "leg": the second one would win in a plain decode.
	dup := strings.Replace(string(payload), `"leg":"a"`, `"leg":"a","leg":"b"`, 1)
	if dup == string(payload) {
		t.Fatalf("test setup: could not inject a duplicate key into %s", payload)
	}
	if _, err := Parse([]byte(dup)); ReasonOf(err) != ReasonMalformed {
		t.Fatalf("a duplicate key parsed (reason %q) — encoding/json keeps the last value, so this blob would read two ways", ReasonOf(err))
	}

	// Trailing data after the object.
	if _, err := Parse(append(append([]byte{}, payload...), '{', '}')); ReasonOf(err) != ReasonMalformed {
		t.Fatalf("trailing data parsed (reason %q)", ReasonOf(err))
	}

	// Oversized payload, refused before the decoder ever runs.
	big := make([]byte, MaxPayloadLen+1)
	for i := range big {
		big[i] = ' '
	}
	if _, err := Parse(big); ReasonOf(err) != ReasonSize {
		t.Fatalf("an oversized payload was not refused on size (reason %q)", ReasonOf(err))
	}
}

// TestDuplicateScanSurvivesNestedValues pins the duplicate scanner directly. A
// value that is itself an object or array must be skipped WHOLE — a scanner that
// walks into it starts reading the nested keys as top-level ones and then
// mistakes the nested closing brace for the end of the ticket, so a duplicate
// after it goes unnoticed.
func TestDuplicateScanSurvivesNestedValues(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		dup  bool
	}{
		{name: "flat, no duplicate", raw: `{"v":1,"leg":"a"}`},
		{name: "nested object then duplicate", raw: `{"x":{"leg":"a"},"leg":"a","leg":"b"}`, dup: true},
		{name: "nested array then duplicate", raw: `{"x":[1,{"leg":"a"}],"leg":"a","leg":"b"}`, dup: true},
		{name: "nested object, no duplicate", raw: `{"x":{"leg":"a"},"leg":"b"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := noDuplicateKeys([]byte(tc.raw))
			if tc.dup && err == nil {
				t.Fatalf("duplicate key not detected in %s", tc.raw)
			}
			if !tc.dup && err != nil {
				t.Fatalf("valid object rejected as duplicate: %s (%v)", tc.raw, err)
			}
		})
	}
}

// TestProofOfPossession is plan cases 12, 13, 14 and 15 at this layer: a ticket
// alone admits nothing, only the holder of the ephemeral private key can bind,
// and a captured bind is inert once the cookie changes (another address, or a
// rotated epoch — both reach here as a different cookie).
func TestProofOfPossession(t *testing.T) {
	spub, eph, payload, sig, _, rid := mint(t, nil)
	cookie := []byte("cookie-0123456789")
	keys := []ed25519.PublicKey{spub}

	if err := accept(keys, payload, sig, cookie, nil, rid, time.Now()); ReasonOf(err) != ReasonProof {
		t.Fatalf("a bind with NO proof of possession was refused as %q, want %q", ReasonOf(err), ReasonProof)
	}

	_, wrong, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("wrong key: %v", err)
	}
	if err := accept(keys, payload, sig, cookie, SignBind(wrong, payload, sig, cookie), rid, time.Now()); ReasonOf(err) != ReasonProof {
		t.Fatalf("a proof signed by a key other than epk was accepted (reason %q)", ReasonOf(err))
	}

	// A bind captured under one cookie, replayed once the cookie differs — which
	// is what both "another address" and "after rotation" look like here.
	captured := SignBind(eph, payload, sig, cookie)
	if err := accept(keys, payload, sig, []byte("cookie-9876543210"), captured, rid, time.Now()); ReasonOf(err) != ReasonProof {
		t.Fatalf("a captured bind replayed under a different cookie was accepted (reason %q)", ReasonOf(err))
	}
}

// TestBindProofCoversTheWholeTicket: swapping any field of the ticket must
// invalidate the proof even if the attacker could somehow re-sign the payload,
// because the proof hashes payload||sig, not a field subset.
func TestBindProofCoversTheWholeTicket(t *testing.T) {
	_, eph, payload, sig, _, _ := mint(t, nil)
	cookie := []byte("cookie-0123456789")
	good := SignBind(eph, payload, sig, cookie)

	altered := append([]byte{}, payload...)
	altered[len(altered)-2] ^= 0x01
	epub := eph.Public().(ed25519.PublicKey)
	if err := VerifyBind(epub, altered, sig, cookie, good); err == nil {
		t.Fatal("the proof of possession still verified after the ticket payload changed")
	}

	otherSig := append([]byte{}, sig...)
	otherSig[0] ^= 0x01
	if err := VerifyBind(epub, payload, otherSig, cookie, good); err == nil {
		t.Fatal("the proof of possession still verified after the ticket signature changed")
	}
}

// TestKeyRotationAcceptsEitherKey is plan case 28: while the server switches
// keys, the relay is configured with both and a ticket from either verifies.
func TestKeyRotationAcceptsEitherKey(t *testing.T) {
	spub, eph, payload, sig, _, rid := mint(t, nil)
	next, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("next key: %v", err)
	}
	cookie := []byte("cookie-0123456789")
	bs := SignBind(eph, payload, sig, cookie)

	for _, keys := range [][]ed25519.PublicKey{
		{spub, next}, // current first
		{next, spub}, // next first
	} {
		if err := accept(keys, payload, sig, cookie, bs, rid, time.Now()); err != nil {
			t.Fatalf("a ticket from a configured key was refused during rotation: %v", err)
		}
	}
	// And the rotation window is not a free pass: an unrelated key still fails.
	stranger, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("stranger key: %v", err)
	}
	if err := accept([]ed25519.PublicKey{next, stranger}, payload, sig, cookie, bs, rid, time.Now()); ReasonOf(err) != ReasonSignature {
		t.Fatalf("a ticket signed by no configured key was accepted (reason %q)", ReasonOf(err))
	}
}

// TestClockSkewWithinTheAllowance: a ticket from a server whose clock is off by
// less than Skew is still usable, and the worst-case real lifetime is
// MaxTTL+2*Skew — the number the documentation has to state.
func TestClockSkewWithinTheAllowance(t *testing.T) {
	now := time.Now()
	ahead := now.Add(Skew - time.Second)
	spub, eph, payload, sig, _, rid := mint(t, func(p *Payload) {
		p.IAT = ahead.Unix()
		p.EXP = ahead.Add(MaxTTL).Unix()
	})
	cookie := []byte("cookie-0123456789")
	bs := SignBind(eph, payload, sig, cookie)
	if err := accept([]ed25519.PublicKey{spub}, payload, sig, cookie, bs, rid, now); err != nil {
		t.Fatalf("a ticket inside the skew allowance was refused: %v", err)
	}
	// Still acceptable at the far end of the worst case...
	edge := ahead.Add(MaxTTL).Add(Skew - time.Second)
	if err := accept([]ed25519.PublicKey{spub}, payload, sig, cookie, bs, rid, edge); err != nil {
		t.Fatalf("a ticket was refused before MaxTTL+2*Skew: %v", err)
	}
	// ...and refused past it, so the bound is a bound.
	if err := accept([]ed25519.PublicKey{spub}, payload, sig, cookie, bs, rid, ahead.Add(MaxTTL).Add(2*Skew)); ReasonOf(err) != ReasonWindow {
		t.Fatalf("a ticket past MaxTTL+2*Skew was accepted (reason %q)", ReasonOf(err))
	}
}

// TestSignedBytesAreTheBytesThatTravel guards the property the whole design
// rests on: the verifier must never re-marshal a parsed ticket. A payload whose
// key order differs from Go's struct order still verifies as received, and would
// NOT verify if anyone re-serialised it.
func TestSignedBytesAreTheBytesThatTravel(t *testing.T) {
	spub, _, payload, sig, p, _ := mint(t, nil)
	if !Verify([]ed25519.PublicKey{spub}, payload, sig) {
		t.Fatal("the payload as signed did not verify")
	}
	remarshalled, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := Parse(payload)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed != p {
		t.Fatalf("parsed ticket differs from the signed one:\n got %+v\nwant %+v", parsed, p)
	}
	// Not a security assertion, a documentation one: these bytes happen to match
	// today, and nothing in the design may depend on that.
	if string(remarshalled) != string(payload) {
		t.Logf("note: re-marshalling produced different bytes (%d vs %d) — which is exactly why the verifier uses the received bytes", len(remarshalled), len(payload))
	}
}

func TestValidID(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	if !ValidID(id) {
		t.Fatalf("NewID produced %q, which ValidID rejects", id)
	}
	for _, bad := range []string{"", "short", strings.Repeat("A", 64), "!!!!!!!!!!!!!!!!!!!!!!", id + "A"} {
		if ValidID(bad) {
			t.Fatalf("ValidID accepted %q", bad)
		}
	}
}
