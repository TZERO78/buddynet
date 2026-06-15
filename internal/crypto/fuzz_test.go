package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// FuzzOpenCode hardens the sealed-enrollment-code path, which decrypts
// attacker-supplied blobs on the handshake server. Two properties:
//
//  1. Robustness: OpenCode must never panic on arbitrary input (truncated boxes,
//     bad base64, wrong sizes) — it may only return an error.
//  2. Round-trip: anything SealCode produced for a key must OpenCode back to the
//     same plaintext under the matching key, for any code string.
func FuzzOpenCode(f *testing.F) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}

	f.Add("")
	f.Add("hunter2")
	f.Add("a-longer-enrollment-code-with-symbols !@#\x00\xff")
	if enc, err := SealCode("seed", pub); err == nil {
		f.Add(enc) // a real sealed blob, so the success branch is in the corpus
	}

	f.Fuzz(func(t *testing.T, s string) {
		// (1) Treat the fuzzed string as an untrusted blob to open: must not panic.
		_, _ = OpenCode(s, priv)

		// (2) Treat the fuzzed string as a code to seal+open: must round-trip.
		enc, err := SealCode(s, pub)
		if err != nil {
			return // SealCode itself failed (e.g. RNG) — nothing to round-trip
		}
		got, err := OpenCode(enc, priv)
		if err != nil {
			t.Fatalf("OpenCode failed to open a freshly SealCode'd blob: %v", err)
		}
		if got != s {
			t.Fatalf("round-trip mismatch: sealed %q, opened %q", s, got)
		}
	})
}

// FuzzDecodePubKey ensures the public-key decoder never panics and only ever
// returns a key of exactly the Ed25519 size.
func FuzzDecodePubKey(f *testing.F) {
	f.Add(PubKeyB64(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))))
	f.Add("not base64!!")
	f.Add("")
	f.Add("QUFB") // valid base64, wrong length

	f.Fuzz(func(t *testing.T, b64 string) {
		pub, err := DecodePubKey(b64)
		if err != nil {
			return
		}
		if len(pub) != ed25519.PublicKeySize {
			t.Fatalf("accepted a key of wrong size %d", len(pub))
		}
	})
}
