package ticket

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

// FuzzParse throws arbitrary bytes at the ticket parser. On the relay this runs
// on a permanently open UDP port, behind a signature check — but a parser that
// panics is a parser that takes the process down with one crafted datagram, and
// the signature check is exactly the thing an implementation bug could bypass.
//
// Invariants: never panic, and anything ACCEPTED is fully well-formed — every id
// field the right length and alphabet, a known version, a real leg, an epk that
// decodes to an Ed25519 key, and a validity span inside the cap.
func FuzzParse(f *testing.F) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("key: %v", err)
	}
	epub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("ephemeral key: %v", err)
	}
	id := func() string {
		s, err := NewID()
		if err != nil {
			f.Fatalf("id: %v", err)
		}
		return s
	}
	now := time.Now()
	good, _, err := Sign(priv, Payload{
		V: FormatVersion, RID: id(), SID: id(), Leg: LegA,
		EPK: base64.RawURLEncoding.EncodeToString(epub),
		IAT: now.Unix(), EXP: now.Add(MaxTTL).Unix(), Nonce: id(),
	})
	if err != nil {
		f.Fatalf("sign: %v", err)
	}
	f.Add(good)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"v":1,"v":1}`))
	f.Add([]byte(`{"v":1,"rid":{"nested":true}}`))
	f.Add([]byte(`{"v":"one"}`))
	f.Add([]byte(`not json at all`))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, payload []byte) {
		p, err := Parse(payload)
		if err != nil {
			return
		}
		if p.V != FormatVersion {
			t.Fatalf("accepted version %d", p.V)
		}
		if !ValidID(p.RID) || !ValidID(p.SID) || !ValidID(p.Nonce) {
			t.Fatalf("accepted malformed ids: rid=%q sid=%q nonce=%q", p.RID, p.SID, p.Nonce)
		}
		if p.Leg != LegA && p.Leg != LegB {
			t.Fatalf("accepted leg %q", p.Leg)
		}
		if _, err := p.EphPub(); err != nil {
			t.Fatalf("accepted an epk that is not an Ed25519 key: %v", err)
		}
		// CheckWindow is the caller's step, but an accepted payload must at least be
		// arithmetically sane once it gets there.
		if err := p.CheckWindow(time.Unix(p.IAT, 0)); err != nil {
			if span := p.EXP - p.IAT; span > 0 && span <= int64(MaxTTL/time.Second) {
				t.Fatalf("a payload with a valid span was rejected at its own issue time: %v", err)
			}
		}
	})
}

// FuzzVerify throws arbitrary bytes at the signature check, which is the FIRST
// thing an unvalidated (well, cookie-validated) source reaches on the relay.
// Invariant: never panic, and nothing verifies under a key that did not sign it.
func FuzzVerify(f *testing.F) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("key: %v", err)
	}
	payload := []byte(`{"v":1}`)
	sig := ed25519.Sign(priv, signedBytes(payload))
	f.Add(payload, sig)
	f.Add(payload, []byte("short"))
	f.Add([]byte(""), []byte(""))

	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("other key: %v", err)
	}
	f.Fuzz(func(t *testing.T, payload, sig []byte) {
		if Verify([]ed25519.PublicKey{other}, payload, sig) {
			t.Fatal("a payload verified under a key that did not sign it")
		}
		// The real key must still accept exactly what it signed, so the fuzzer
		// cannot pass by making Verify reject everything.
		if got := Verify([]ed25519.PublicKey{pub}, payload, ed25519.Sign(priv, signedBytes(payload))); !got &&
			len(payload) > 0 && len(payload) <= MaxPayloadLen {
			t.Fatal("a freshly signed payload did not verify")
		}
	})
}
