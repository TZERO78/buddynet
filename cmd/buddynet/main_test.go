package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
