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

// PromptSAS confirms only on an explicit yes; no/garbage/timeout all reject.
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

	if err := withStdin("y\n"); err != nil {
		t.Errorf("'y' should confirm, got %v", err)
	}
	if err := withStdin("yes\n"); err != nil {
		t.Errorf("'yes' should confirm, got %v", err)
	}
	if err := withStdin("n\n"); err != ErrSASRejected {
		t.Errorf("'n' should reject, got %v", err)
	}
	if err := withStdin("maybe\n"); err != ErrSASRejected {
		t.Errorf("garbage should reject, got %v", err)
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
