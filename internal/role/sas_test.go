package role

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"regexp"
	"testing"
	"time"
)

func genKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return pub
}

var sasFormat = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{6}$`) // Crockford base32, 6 chars

// Both ends must compute the identical SAS regardless of key order, in the right
// format, and it must change with the session binding.
func TestComputeSASDeterministicAndSymmetric(t *testing.T) {
	a, b := genKey(t), genKey(t)
	sid := []byte("session-binding-1")

	if !sasFormat.MatchString(ComputeSAS(a, b, sid)) {
		t.Fatalf("SAS = %q, want 6 Crockford-base32 chars", ComputeSAS(a, b, sid))
	}
	if ComputeSAS(a, b, sid) != ComputeSAS(a, b, sid) {
		t.Fatal("SAS not deterministic")
	}
	if ComputeSAS(a, b, sid) != ComputeSAS(b, a, sid) {
		t.Fatal("SAS must be identical regardless of which side is 'me' (keys are sorted)")
	}
	if ComputeSAS(a, b, sid) == ComputeSAS(a, b, []byte("session-binding-2")) {
		t.Fatal("SAS must change with the session binding")
	}
}

// The core MITM property: with a man in the middle, each side pairs with the
// MITM key over a different channel binding, so the two SAS values differ and
// the humans notice the mismatch.
func TestComputeSASDetectsMITM(t *testing.T) {
	alice, bob := genKey(t), genKey(t)
	mitm := genKey(t)

	// Legit A<->B over one session: both compute the same SAS.
	sid := []byte("real-session")
	if ComputeSAS(alice, bob, sid) != ComputeSAS(bob, alice, sid) {
		t.Fatal("legit peers should agree")
	}

	// MITM: Alice talks to MITM over session sidA, Bob over session sidB.
	aliceSAS := ComputeSAS(alice, mitm, []byte("session-A"))
	bobSAS := ComputeSAS(bob, mitm, []byte("session-B"))
	if aliceSAS == bobSAS {
		t.Fatal("MITM not detected: the two sides computed the same SAS")
	}
}

// PromptSAS confirms only when the typed code matches; a wrong code, a bare "yes"
// (no longer accepted — the code must be entered), or a timeout all reject.
func TestPromptSAS(t *testing.T) {
	// Silence the prompt written to stderr during the test.
	devnull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	oldStderr, oldStdin := os.Stderr, os.Stdin
	os.Stderr = devnull
	defer func() { os.Stderr, os.Stdin = oldStderr, oldStdin; devnull.Close() }()

	withStdin := func(input string) error {
		r, w, _ := os.Pipe()
		os.Stdin = r
		if input != "" {
			go func() { w.WriteString(input); w.Close() }()
		}
		return PromptSAS("K7QX2M", 2*time.Second)
	}

	if err := withStdin("K7QX2M\n"); err != nil {
		t.Errorf("correct code should confirm, got %v", err)
	}
	if err := withStdin("k7 qx2m\n"); err != nil { // case + spaces are forgiven
		t.Errorf("normalised correct code should confirm, got %v", err)
	}
	if err := withStdin("K7QX2M"); err != nil { // EOF right after the code, no newline
		t.Errorf("correct code without trailing newline should confirm, got %v", err)
	}
	if err := withStdin("AAAAAA\n"); err != ErrSASRejected {
		t.Errorf("wrong code should reject, got %v", err)
	}
	if err := withStdin("yes\n"); err != ErrSASRejected {
		t.Errorf("'yes' is no longer a valid confirmation, should reject, got %v", err)
	}
	if err := withStdin("\n"); err != ErrSASRejected {
		t.Errorf("blank line should reject, got %v", err)
	}

	// Timeout with no input must reject (never silently confirm), distinctly from
	// an explicit mismatch so callers can log them differently.
	r, w, _ := os.Pipe()
	os.Stdin = r
	defer w.Close()
	if err := PromptSAS("K7QX2M", 100*time.Millisecond); err != ErrSASTimeout {
		t.Errorf("timeout should return ErrSASTimeout, got %v", err)
	}
}

// normalizeSAS forgives cosmetics (case, spaces, hyphens) and the Crockford
// look-alikes a human mistypes (O→0, I/L→1), so a correct code is never rejected.
func TestSASMatches(t *testing.T) {
	cases := []struct {
		typed, expected string
		want            bool
	}{
		{"K7QX2M", "K7QX2M", true},
		{"k7qx2m", "K7QX2M", true},
		{" K7-QX2M ", "K7QX2M", true},
		{"OQIZM2", "0Q1ZM2", true}, // O→0, I→1
		{"lqizm2", "1Q1ZM2", true}, // l→1, i→1
		{"K7QX2N", "K7QX2M", false},
		{"", "K7QX2M", false},
	}
	for _, c := range cases {
		if got := sasMatches(c.typed, c.expected); got != c.want {
			t.Errorf("sasMatches(%q, %q) = %v, want %v", c.typed, c.expected, got, c.want)
		}
	}
}
