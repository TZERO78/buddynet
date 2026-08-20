package main

// Gate for finding A-05, buddynet half. See internal/flagdrift for why the flag
// names come from registerFlags rather than from a pattern over this file, and
// why only active artifacts are scanned.

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/tzero78/buddynet/internal/flagdrift"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func buddynetFlags() map[string]bool {
	return flagdrift.Names(func(fs *flag.FlagSet) { registerFlags(fs) })
}

// TestShippedArtifactsUseOnlyRealBuddynetFlags: every long flag an active
// artifact passes to `buddynet` must exist. A shipped file that invokes the
// binary with a removed flag makes it exit 2 — which is how the public handshake
// unit spent a whole release unable to start.
func TestShippedArtifactsUseOnlyRealBuddynetFlags(t *testing.T) {
	findings, scanned, err := flagdrift.Scan(repoRoot(t), "buddynet", buddynetFlags())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if scanned == 0 {
		t.Fatal("no artifacts were scanned — the gate would pass by looking at nothing")
	}
	for _, f := range findings {
		t.Errorf("flag drift: %s", f)
	}
	t.Logf("scanned %d artifacts against %d buddynet flags", scanned, len(buddynetFlags()))
}

// TestFlagDriftGateActuallyFires is the positive control. A gate that silently
// matches nothing — broken regexp, wrong repo root, empty artifact list — looks
// exactly like a clean run, which is the failure mode this whole audit keeps
// finding. So: plant a flag the binary does not define into a temporary copy of
// the artifact tree and require the scan to report it.
func TestFlagDriftGateActuallyFires(t *testing.T) {
	root := t.TempDir()
	unit := filepath.Join(root, "deployments", "systemd", "planted.service")
	if err := os.MkdirAll(filepath.Dir(unit), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "[Service]\n" +
		"# --this-comment-flag-must-be-ignored\n" +
		"ExecStart=/usr/local/bin/buddynet --role=handshake --key /x --quic-handshake\n"
	if err := os.WriteFile(unit, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, scanned, err := flagdrift.Scan(root, "buddynet", buddynetFlags())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if scanned != 1 {
		t.Fatalf("expected to scan the one planted artifact, scanned %d", scanned)
	}
	if len(findings) != 1 {
		t.Fatalf("the gate did not fire on a planted removed flag: %v", findings)
	}
	if findings[0].Flag != "quic-handshake" {
		t.Fatalf("gate reported --%s, want --quic-handshake", findings[0].Flag)
	}
	// And the flags that DO exist must not be reported, or the gate is noise.
	for _, f := range findings {
		if f.Flag == "role" || f.Flag == "key" {
			t.Fatalf("gate reported the real flag --%s", f.Flag)
		}
	}
}
