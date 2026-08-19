package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tzero78/buddynet/internal/invite"
)

// --lab disables ALL buddy identity verification (full MITM exposure), so it is
// refused unless the operator explicitly opts in with BUDDYNET_LAB=1. Without the
// env the process must fail loudly with exit code 2 — never run insecurely by
// accident (e.g. a lab command copy-pasted into production).
func TestLabFlagRefusedWithoutEnv(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "buddynet")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	cmd := exec.Command(bin,
		"--role=buddy", "--server", "127.0.0.1:51820", "--server-key", "x",
		"--lab", "-L", "127.0.0.1:0")
	// Force BUDDYNET_LAB unset regardless of the test runner's environment (the
	// trailing assignment wins), so the opt-in guard must fire.
	cmd.Env = append(os.Environ(), "BUDDYNET_LAB=")

	out, err := cmd.CombinedOutput()
	ee, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("want a non-zero exit, got err=%v\noutput:\n%s", err, out)
	}
	if ee.ExitCode() != 2 {
		t.Fatalf("want exit 2 for --lab without BUDDYNET_LAB=1, got %d\noutput:\n%s", ee.ExitCode(), out)
	}
	if !strings.Contains(string(out), "BUDDYNET_LAB=1") {
		t.Fatalf("refusal message should name BUDDYNET_LAB=1, got:\n%s", out)
	}
}

// --join is where the invite blob turns into a pin. The three outcomes have to
// stay strictly separated: a key-bearing invite pins, a bare token does not (but
// still pairs), and anything mangled is an ERROR — a malformed invite that fell
// back to the unpinned path would silently drop the protection the blob exists
// to provide, at the exact moment the user thinks they are being careful.
func TestResolveJoin(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	blob := invite.Mint("tok-123", pub)

	t.Run("key-bearing invite pins the inviter", func(t *testing.T) {
		tok, pin, show, err := resolveJoin(blob, "")
		if err != nil {
			t.Fatalf("resolveJoin: %v", err)
		}
		if tok != "tok-123" {
			t.Errorf("token = %q, want %q", tok, "tok-123")
		}
		if pin != pubB64 {
			t.Errorf("pin = %q, want the inviter key %q", pin, pubB64)
		}
		if !show {
			t.Error("a pinned joiner must take the display half of first contact, not prompt")
		}
	})

	t.Run("bare token still pairs, unpinned", func(t *testing.T) {
		tok, pin, show, err := resolveJoin("plain-token", "")
		if err != nil {
			t.Fatalf("resolveJoin: %v", err)
		}
		if tok != "plain-token" || pin != "" || show {
			t.Errorf("bare token = (%q, %q, %v), want the token with no pin and no display half", tok, pin, show)
		}
	})

	t.Run("bare token keeps an explicit --peer-key", func(t *testing.T) {
		_, pin, _, err := resolveJoin("plain-token", pubB64)
		if err != nil {
			t.Fatalf("resolveJoin: %v", err)
		}
		if pin != pubB64 {
			t.Errorf("pin = %q, want the explicit --peer-key %q left untouched", pin, pubB64)
		}
	})

	t.Run("a mangled invite is refused, not downgraded", func(t *testing.T) {
		for _, bad := range []string{blob[:len(blob)-3], "bnet1.tok.", "bnet1.onlyonepart"} {
			if _, _, _, err := resolveJoin(bad, ""); err == nil {
				t.Errorf("resolveJoin(%q) accepted a malformed invite — it must never fall back to the unpinned path", bad)
			}
		}
	})

	t.Run("a --peer-key that contradicts the invite is refused", func(t *testing.T) {
		other, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := resolveJoin(blob, base64.StdEncoding.EncodeToString(other)); err == nil {
			t.Error("a --peer-key naming a different identity than the invite must be an error, not a silent choice between two buddies")
		}
		// The matching one is fine: the user just spelled out what the invite says.
		if _, _, _, err := resolveJoin(blob, pubB64); err != nil {
			t.Errorf("a --peer-key agreeing with the invite should be accepted, got %v", err)
		}
	})
}
