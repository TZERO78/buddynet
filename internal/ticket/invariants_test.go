package ticket

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The tests in this file pin what the rest of the suite deliberately does not.
//
// Every other test here is written RELATIVE to the package's own constants and
// helpers — `p.EXP = p.IAT + int64(MaxTTL/time.Second) + 1`, `signedBytes(...)`
// on both sides of a signature. That is the right way to write them: it keeps
// them readable and it keeps them honest about intent. But it means the whole
// suite moves together. Change MaxTTL to 121 seconds, add a byte to the signing
// context, or return a 9-character session id from ShortSID, and every one of
// those tests still passes — while every relay already deployed starts refusing
// tickets, or a full session id starts appearing in a log line.
//
// These were found by running tools/mutate over ticket.go: each test below kills
// a mutant that the existing suite let through. They are therefore written the
// opposite way round — against literal values, never against the constant they
// are checking — because a test that reads the value it is verifying verifies
// nothing.
//
//	go run ./tools/mutate -pkg ./internal/ticket -src internal/ticket/ticket.go
//
// That run should report 100 of 105 compiling mutants killed, with exactly five
// survivors. All five are EQUIVALENT mutants — no test can kill them, and the
// reasoning is recorded here so the next run does not have to re-derive it:
//
//   - ValidID's length pre-check, deleted. The canonical check that follows
//     (re-encode and compare) cannot be true for a string of the wrong length,
//     so the guard saves work and decides nothing.
//   - ValidID's `err != nil || len(raw) != IDLen`, flipped to `&&`. After the
//     length check s is exactly 22 characters, so a decode error always yields
//     fewer than IDLen bytes: both conditions are true together or not at all.
//   - Sign's `if err != nil` after json.Marshal, deleted. Payload holds only
//     string/int/int64; marshalling it cannot fail, so nothing reaches the branch.
//   - ShortSID's `len(sid) > 8`, weakened to `>=`. It differs only at len == 8,
//     where sid[:8] returns the same string.
//   - ShortSID's literal 8, lowered to 7. That gives `if len(sid) > 7 { return
//     sid[:8] }`, which returns the whole string at len == 8 exactly as before.
//
// If a run reports a DIFFERENT survivor, something regressed or a new gap opened.

// TestWireConstantsArePinned fixes the numbers that two independent programs
// have to agree on. None of these is a style choice: a relay compiled last month
// and a handshake server compiled today must reach the same verdict about the
// same ticket, and nothing in the wire format announces these values — they are
// agreed by both sides being built from this line.
//
// Changing one is a compatibility break. That may well be the right thing to do;
// this test only makes sure it happens on purpose, with the release notes it
// needs, rather than as an unremarked edit.
func TestWireConstantsArePinned(t *testing.T) {
	if FormatVersion != 1 {
		t.Errorf("FormatVersion is %d, pinned at 1 — a relay that knows only v1 refuses everything this server now mints", FormatVersion)
	}
	if IDLen != 16 {
		t.Errorf("IDLen is %d, pinned at 16 (128 bits of unguessable session id)", IDLen)
	}
	if MaxPayloadLen != 512 {
		t.Errorf("MaxPayloadLen is %d, pinned at 512", MaxPayloadLen)
	}
	if MaxTTL != 120*time.Second {
		t.Errorf("MaxTTL is %v, pinned at 120s", MaxTTL)
	}
	if Skew != 10*time.Second {
		t.Errorf("Skew is %v, pinned at 10s", Skew)
	}

	// The number SECURITY.md and the package comment both state. It is not
	// MaxTTL, and it is not MaxTTL+Skew: a server whose clock runs Skew ahead
	// issues a ticket that stays acceptable until exp+Skew. Worst-case exposure
	// of a stolen ticket is this value, so it is the one that must not drift
	// quietly — and it moves if EITHER constant does.
	if worst := MaxTTL + 2*Skew; worst != 140*time.Second {
		t.Errorf("worst-case ticket lifetime is %v, documented as 140s", worst)
	}

	// An id is exactly 22 base64url characters. Both ends size buffers and log
	// fields by this, and ValidID is the only thing enforcing it.
	if got := base64.RawURLEncoding.EncodedLen(IDLen); got != 22 {
		t.Errorf("an id encodes to %d characters, expected 22", got)
	}
}

// TestSigningBytesAreAKnownAnswer is a known-answer test for the two byte
// strings this package puts under a signature.
//
// It exists because the existing tests cannot see a change here at all: they
// sign with signedBytes and verify with signedBytes, so ANY edit that is
// symmetric — a different context string, an extra leading byte, the hash taken
// over sig||payload instead of payload||sig — keeps them green while making
// every ticket this build mints unverifiable to every other build.
//
// So the expected bytes are spelled out here as literals. This test must never
// be "fixed" by calling the function it is testing.
func TestSigningBytesAreAKnownAnswer(t *testing.T) {
	payload := []byte(`{"v":1,"probe":"kat"}`)

	t.Run("ticket", func(t *testing.T) {
		want := []byte("buddynet-relay-ticket-v1\x00" + string(payload))
		got := signedBytes(payload)
		if !bytes.Equal(got, want) {
			t.Fatalf("the bytes a ticket signature covers changed\n got %q\nwant %q", got, want)
		}
	})

	t.Run("bind", func(t *testing.T) {
		sig := make([]byte, ed25519.SignatureSize)
		for i := range sig {
			sig[i] = byte(i)
		}
		cookie := []byte("cookie-abcdefgh")

		// Rebuilt independently: context, then SHA-256 over payload THEN sig,
		// then the cookie. Nothing here reads bindContext.
		sum := sha256.Sum256(append(append([]byte{}, payload...), sig...))
		want := append([]byte("buddynet-relay-bind-v1\x00"), sum[:]...)
		want = append(want, cookie...)

		got := BindSigningBytes(payload, sig, cookie)
		if !bytes.Equal(got, want) {
			t.Fatalf("the bytes a bind proof covers changed\n got %x\nwant %x", got, want)
		}
	})

	// The two contexts must stay distinct AND neither may be a prefix of the
	// other, which is what the trailing NUL buys. A ticket signature must never
	// be replayable as a bind proof.
	t.Run("contexts are separated", func(t *testing.T) {
		a := string(signedBytes(nil))
		b := "buddynet-relay-bind-v1\x00"
		if strings.HasPrefix(a, b) || strings.HasPrefix(b, a) {
			t.Fatalf("one signing context is a prefix of the other: %q vs %q", a, b)
		}
	})
}

// TestVerifyRejectsOversizeBeforeCrypto proves the length guard in Verify is not
// redundant with ed25519's own checks.
//
// The distinction matters because Verify is the FIRST thing a relay runs on
// bytes from an unauthenticated source. If the guard were removed, a correctly
// signed 100 KB blob would still be refused eventually — by Parse, after the
// relay had already paid for an Ed25519 verification over 100 KB. The guard is
// what keeps that cost off the table, and only a ticket whose signature is
// VALID can show the difference: an invalid one is refused either way.
func TestVerifyRejectsOversizeBeforeCrypto(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	keys := []ed25519.PublicKey{pub}

	// Deliberately not via Sign, which refuses to mint this at all.
	oversize := bytes.Repeat([]byte("x"), MaxPayloadLen+1)
	if Verify(keys, oversize, ed25519.Sign(priv, signedBytes(oversize))) {
		t.Errorf("a correctly signed %d-byte payload was accepted; the cap is %d", len(oversize), MaxPayloadLen)
	}

	// The empty payload, likewise correctly signed. Nothing downstream can be
	// asked to parse zero bytes into a ticket.
	if Verify(keys, nil, ed25519.Sign(priv, signedBytes(nil))) {
		t.Error("a correctly signed empty payload was accepted")
	}

	// A payload of exactly the cap is NOT refused on length — the bound is
	// inclusive, and a ticket that grows into it must keep working.
	atCap := bytes.Repeat([]byte("x"), MaxPayloadLen)
	if !Verify(keys, atCap, ed25519.Sign(priv, signedBytes(atCap))) {
		t.Errorf("a payload of exactly MaxPayloadLen (%d) was refused on length", MaxPayloadLen)
	}
}

// TestParseSizeBoundIsExact pins where Parse switches from "too big" to "let the
// decoder look at it". Both directions matter: one byte too strict silently
// caps how far the ticket format can grow, one byte too loose is a cap that does
// not hold.
func TestParseSizeBoundIsExact(t *testing.T) {
	// Junk, not a ticket: what is asserted here is WHICH refusal comes back, so
	// the payload only has to be the right length.
	atCap := bytes.Repeat([]byte("x"), MaxPayloadLen)
	if _, err := Parse(atCap); ReasonOf(err) == ReasonSize {
		t.Errorf("a %d-byte payload was refused on size; the cap is %d and inclusive", len(atCap), MaxPayloadLen)
	}

	overCap := bytes.Repeat([]byte("x"), MaxPayloadLen+1)
	if _, err := Parse(overCap); ReasonOf(err) != ReasonSize {
		t.Errorf("a %d-byte payload was refused as %q, want %q", len(overCap), ReasonOf(err), ReasonSize)
	}

	// Empty is a size refusal, not a parse error: there is nothing to parse, and
	// an operator reading the log should be told the blob was empty rather than
	// sent looking for malformed JSON.
	if _, err := Parse(nil); ReasonOf(err) != ReasonSize {
		t.Errorf("an empty payload was refused as %q, want %q", ReasonOf(err), ReasonSize)
	}
}

// TestCheckWindowBoundsAreExact walks each edge of the lifetime rules one second
// at a time. The suite already covers "far in the future" and "long expired";
// what it cannot see is a bound that moved by one, which is the difference
// between a rule and roughly a rule.
func TestCheckWindowBoundsAreExact(t *testing.T) {
	now := time.Unix(1_700_000_000, 0) // fixed: a window test must not race the clock
	sec := now.Unix()
	const maxTTLSec = 120
	const skewSec = 10

	tests := []struct {
		name string
		iat  int64
		exp  int64
		want Reason // "" means it must be accepted
	}{
		{name: "span of exactly MaxTTL", iat: sec, exp: sec + maxTTLSec},
		{name: "span one second over MaxTTL", iat: sec, exp: sec + maxTTLSec + 1, want: ReasonTTL},
		{name: "span of one second", iat: sec, exp: sec + 1},
		{name: "zero span (valid for nothing)", iat: sec, exp: sec, want: ReasonTTL},
		{name: "negative span (expiry before issue)", iat: sec, exp: sec - 1, want: ReasonTTL},

		{name: "issued exactly Skew ahead", iat: sec + skewSec, exp: sec + skewSec + 60},
		{name: "issued one second past Skew", iat: sec + skewSec + 1, exp: sec + skewSec + 61, want: ReasonWindow},

		{name: "expired exactly Skew ago", iat: sec - skewSec - 60, exp: sec - skewSec},
		{name: "expired one second past Skew", iat: sec - skewSec - 61, exp: sec - skewSec - 1, want: ReasonWindow},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Payload{IAT: tc.iat, EXP: tc.exp}.CheckWindow(now)
			if got := ReasonOf(err); got != tc.want {
				t.Fatalf("iat=%+d exp=%+d relative to now: got %q, want %q",
					tc.iat-sec, tc.exp-sec, orAccepted(got), orAccepted(tc.want))
			}
		})
	}
}

func orAccepted(r Reason) string {
	if r == "" {
		return "accepted"
	}
	return string(r)
}

// TestVerifyBindRejectsMisSizedInputs covers the guard whose absence is not a
// wrong answer but a CRASH: ed25519.Verify panics on a public key that is not
// 32 bytes. The epk reaching it comes from a ticket, so a relay that skipped
// this check could be brought down by a crafted one.
//
// internal/safe would turn that panic into a logged SECURITY event rather than a
// dead process — which is exactly why it must not be relied on here. Recovering
// from a crash is not the same as not crashing.
func TestVerifyBindRejectsMisSizedInputs(t *testing.T) {
	epub, epriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	payload := []byte(`{"v":1}`)
	sig := make([]byte, ed25519.SignatureSize)
	cookie := []byte("cookie-abcdefgh")
	good := SignBind(epriv, payload, sig, cookie)

	// The positive control: everything below must fail for the reason under test
	// and not because the fixture was broken to begin with.
	if err := VerifyBind(epub, payload, sig, cookie, good); err != nil {
		t.Fatalf("a valid bind proof was refused: %v", err)
	}

	cases := []struct {
		name    string
		epk     ed25519.PublicKey
		bindSig []byte
	}{
		{name: "epk truncated", epk: epub[:16], bindSig: good},
		{name: "epk empty", epk: nil, bindSig: good},
		{name: "epk one byte long", epk: append(append([]byte{}, epub...), 0), bindSig: good},
		{name: "proof truncated", epk: epub, bindSig: good[:32]},
		{name: "proof empty", epk: epub, bindSig: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A panic here fails the test by itself; the assertion is that the
			// refusal is the ordinary one.
			if got := ReasonOf(VerifyBind(tc.epk, payload, sig, cookie, tc.bindSig)); got != ReasonProof {
				t.Fatalf("got %q, want %q", orAccepted(got), ReasonProof)
			}
		})
	}
}

// TestShortSIDNeverLeaksTheWholeSID covers a function nothing tested at all.
//
// Its one job is a privacy property stated in its own comment — "the full sid
// never reaches a log line" — and every way of breaking it (drop the guard,
// flip the comparison, widen the prefix) leaves a function that still returns a
// plausible-looking string. Only an assertion about the LENGTH catches it.
func TestShortSIDNeverLeaksTheWholeSID(t *testing.T) {
	const prefix = 8

	full, err := NewID() // 22 characters, a real session id
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	short := ShortSID(full)
	if len(short) != prefix {
		t.Errorf("ShortSID(%q) returned %d characters, want %d", full, len(short), prefix)
	}
	if short == full {
		t.Errorf("ShortSID returned the whole session id (%q)", full)
	}
	if !strings.HasPrefix(full, short) {
		t.Errorf("ShortSID(%q) = %q, which is not its prefix", full, short)
	}

	// Anything at or under the prefix length is passed through: there is nothing
	// to shorten, and truncating further would lose the correlation the log form
	// exists to provide.
	for _, s := range []string{"", "a", "12345678"} {
		if got := ShortSID(s); got != s {
			t.Errorf("ShortSID(%q) = %q, want it unchanged", s, got)
		}
	}
	// One character past the boundary is where truncation must start.
	if got := ShortSID("123456789"); got != "12345678" {
		t.Errorf(`ShortSID("123456789") = %q, want "12345678"`, got)
	}
}

// TestParseRejectsAnUnusableEphemeralKey pins that Parse itself refuses a ticket
// whose epk is not a key, rather than leaving it to the caller.
//
// The relay's own path checks EphPub again afterwards, so removing the check
// inside Parse changes nothing that the end-to-end tests can observe. It still
// matters: Parse is documented to return a payload whose id-shaped fields are
// all valid, and every future caller will read it that way.
func TestParseRejectsAnUnusableEphemeralKey(t *testing.T) {
	for _, tc := range []struct{ name, epk string }{
		{name: "not base64", epk: "!!!!not-base64!!!!"},
		{name: "too short for a key", epk: base64.RawURLEncoding.EncodeToString([]byte("short"))},
		{name: "one byte too long", epk: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, ed25519.PublicKeySize+1))},
		{name: "empty", epk: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, payload, _, _, _ := mint(t, func(p *Payload) { p.EPK = tc.epk })
			if _, err := Parse(payload); ReasonOf(err) != ReasonMalformed {
				t.Fatalf("Parse accepted epk %q (reason %q)", tc.epk, orAccepted(ReasonOf(err)))
			}
		})
	}
}

// TestValidIDAcceptsOnlyTheCanonicalSpelling covers the property ValidID's
// comment claims and that a length-plus-decode check does not actually provide.
//
// encoding/base64 ignores the four unused bits in the final character of a
// 22-character id, so sixteen different strings decode to the same sixteen
// bytes. This test builds those aliases from a real id and requires every one
// but the canonical spelling to be refused.
func TestValidIDAcceptsOnlyTheCanonicalSpelling(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	if !ValidID(id) {
		t.Fatalf("ValidID refused the canonical spelling %q produced by NewID", id)
	}
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		t.Fatalf("decode %q: %v", id, err)
	}

	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	aliases := 0
	for _, c := range alphabet {
		cand := id[:len(id)-1] + string(c)
		if cand == id {
			continue
		}
		// Only spellings of the SAME bytes are aliases. A different final
		// character usually means a different id, which ValidID should accept.
		out, derr := base64.RawURLEncoding.DecodeString(cand)
		if derr != nil || !bytes.Equal(out, raw) {
			continue
		}
		aliases++
		if ValidID(cand) {
			t.Errorf("ValidID accepted %q, a second spelling of %q", cand, id)
		}
	}

	// Without this the test passes trivially the day Go's decoder turns strict or
	// the id length changes — green because it checked nothing.
	if aliases == 0 {
		t.Fatal("found no alias spellings to test; the fixture, not ValidID, is what this would have proved")
	}
	if aliases != 15 {
		t.Logf("note: %d alias spellings for a %d-byte id (expected 15)", aliases, IDLen)
	}
}

// TestSignRefusesToMintOverTheCap covers the guard in Sign whose own comment
// calls it unreachable "with well-formed inputs". It IS reachable through the
// API — the id fields are plain strings — and worth reaching: a signer that
// mints a ticket the verifier is required to refuse on size produces a failure
// with a valid signature on it, which is the most confusing kind to debug.
func TestSignRefusesToMintOverTheCap(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	base := Payload{V: FormatVersion, Leg: LegA}

	over := base
	over.RID = strings.Repeat("A", MaxPayloadLen)
	payload, sig, err := Sign(priv, over)
	if err == nil {
		t.Errorf("Sign minted a %d-byte payload; the cap is %d", len(payload), MaxPayloadLen)
	}
	if payload != nil || sig != nil {
		t.Errorf("Sign returned bytes alongside its error (payload %d, sig %d)", len(payload), len(sig))
	}

	// And the bound is inclusive: a payload of exactly the cap must still be
	// mintable, or the cap is one byte smaller than it claims.
	atCap := padToLength(t, base, MaxPayloadLen)
	if _, _, err := Sign(priv, atCap); err != nil {
		t.Errorf("Sign refused a payload of exactly %d bytes: %v", MaxPayloadLen, err)
	}
}

// padToLength grows p.RID until the marshalled payload is exactly n bytes. Every
// added character adds exactly one byte, so this lands on n or fails the test.
func padToLength(t *testing.T, p Payload, n int) Payload {
	t.Helper()
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pad := n - len(encoded)
	if pad < 0 {
		t.Fatalf("the empty payload is already %d bytes, over the %d target", len(encoded), n)
	}
	p.RID = strings.Repeat("A", pad)
	got, err := json.Marshal(p)
	if err != nil || len(got) != n {
		t.Fatalf("padding produced %d bytes (err %v), want %d", len(got), err, n)
	}
	return p
}

// TestNoDuplicateKeysRequiresAnObject pins that the duplicate-key scan refuses
// anything that is not a JSON object at the top level.
//
// Parse would refuse an array anyway, on the strict decode that follows, so this
// is not reachable through the exported API and is tested directly. It matters
// because the scan is what guarantees "one signed blob cannot be read two ways",
// and a scanner that quietly accepts a shape it was not written for is one
// refactor away from being the thing that reads it the second way.
func TestNoDuplicateKeysRequiresAnObject(t *testing.T) {
	for _, tc := range []struct{ name, payload string }{
		{name: "array", payload: `[1,2,3]`},
		// An array of STRINGS is the case that separates "refused because it is
		// not an object" from "refused because a token was the wrong type". The
		// scan reads a JSON array as alternating key/value pairs quite happily —
		// `["a","b"]` looks exactly like one key with one value — so without the
		// opening-brace check it returns success on input that is not a ticket.
		{name: "array of strings", payload: `["a","b"]`},
		{name: "array with a repeated string", payload: `["a","a"]`},
		{name: "bare number", payload: `123`},
		{name: "bare string", payload: `"ticket"`},
		{name: "null", payload: `null`},
		{name: "empty", payload: ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := noDuplicateKeys([]byte(tc.payload)); ReasonOf(err) != ReasonMalformed {
				t.Fatalf("noDuplicateKeys(%s) = %q, want %q", tc.payload, orAccepted(ReasonOf(err)), ReasonMalformed)
			}
		})
	}
	// The positive control: a flat object still passes, so the assertions above
	// cannot be satisfied by a scan that refuses everything.
	if err := noDuplicateKeys([]byte(`{"v":1,"rid":"x"}`)); err != nil {
		t.Fatalf("a well-formed object was refused: %v", err)
	}
}
