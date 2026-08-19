package invite

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

func testKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub
}

// A minted blob round-trips: same token, same key, and it survives the
// whitespace a messenger paste tends to add.
func TestMintParseRoundTrip(t *testing.T) {
	pub := testKey(t)
	const token = "sZ8Qm3n-t0ken_value"

	blob := Mint(token, pub)
	if !IsBlob(blob) {
		t.Fatalf("minted blob %q not recognised as a blob", blob)
	}
	for _, in := range []string{blob, "  " + blob + "\n"} {
		gotTok, gotPub, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
		if gotTok != token {
			t.Fatalf("token = %q, want %q", gotTok, token)
		}
		if !gotPub.Equal(pub) {
			t.Fatalf("key does not round-trip")
		}
	}
}

// A bare token from an older inviter still pairs — returned unchanged with no
// key, which is the caller's signal to fall back to trust-on-first-use.
func TestParseBareToken(t *testing.T) {
	const token = "plain-token-no-prefix"
	gotTok, gotPub, err := Parse("  " + token + " ")
	if err != nil {
		t.Fatalf("Parse bare token: %v", err)
	}
	if gotTok != token {
		t.Fatalf("token = %q, want %q", gotTok, token)
	}
	if gotPub != nil {
		t.Fatalf("bare token yielded a key: %x", gotPub)
	}
	if IsBlob(token) {
		t.Fatalf("bare token reported as a blob")
	}
}

// Anything that claims to be a blob but does not parse must FAIL, never quietly
// degrade to the unpinned path — that would let a mangled paste silently drop
// the pinning this whole format exists to provide.
func TestParseMalformedBlobFails(t *testing.T) {
	pub := testKey(t)
	good := Mint("tok", pub)

	cases := map[string]string{
		"no separator":  "bnet1.justonepart",
		"empty token":   "bnet1..AAAA",
		"empty key":     "bnet1.tok.",
		"key not b64":   "bnet1.tok.not base64!!",
		"key too short": "bnet1.tok.AAAA",
		"truncated":     good[:len(good)-4],
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Parse(in); !errors.Is(err, ErrBadBlob) {
				t.Fatalf("Parse(%q) err = %v, want ErrBadBlob", in, err)
			}
			if !IsBlob(in) {
				t.Fatalf("IsBlob(%q) = false, want true", in)
			}
		})
	}
}

// A key substituted in the blob decodes to a DIFFERENT key, which is what makes
// the joiner's pin refuse the swap.
func TestParseDistinguishesKeys(t *testing.T) {
	a, b := testKey(t), testKey(t)
	_, gotA, err := Parse(Mint("tok", a))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if gotA.Equal(b) {
		t.Fatalf("two distinct keys compared equal")
	}
}

// The blob stays one shell- and paste-safe word: no padding, no characters that
// need quoting or that a messenger might mangle.
func TestBlobIsPasteSafe(t *testing.T) {
	blob := Mint("tok_-09", testKey(t))
	if strings.ContainsAny(blob, "=+/ \t\n\"'") {
		t.Fatalf("blob %q contains a character that needs quoting", blob)
	}
}
