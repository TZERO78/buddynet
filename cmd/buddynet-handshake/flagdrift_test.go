package main

// Gate for finding A-05, the half that actually broke: this binary's shipped
// systemd unit passed --quic-handshake for a full release after protocol v8
// removed the flag, so the service exited 2 on every start.

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

func handshakeFlags() map[string]bool {
	return flagdrift.Names(func(fs *flag.FlagSet) { registerFlags(fs) })
}

func TestShippedUnitsUseOnlyRealHandshakeFlags(t *testing.T) {
	known := handshakeFlags()
	if known["quic-handshake"] {
		t.Fatal("this binary still defines --quic-handshake; the finding's premise is stale")
	}
	findings, scanned, err := flagdrift.Scan(repoRoot(t), "buddynet-handshake", known)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if scanned == 0 {
		t.Fatal("no artifacts were scanned — the gate would pass by looking at nothing")
	}
	for _, f := range findings {
		t.Errorf("flag drift: %s", f)
	}
	t.Logf("scanned %d artifacts against %d buddynet-handshake flags", scanned, len(known))
}

// The A-05 artifact itself: the unit must exist, must invoke this binary, and
// must be clean. Asserting the file is REACHED matters as much as asserting it
// is clean — the scan skips files it cannot open, so a renamed unit would
// otherwise turn this test green by removing its subject.
func TestPublicHandshakeUnitIsScannedAndClean(t *testing.T) {
	unit := filepath.Join(repoRoot(t), "deployments/systemd/buddynet-public-handshake.service")
	data, err := os.ReadFile(unit)
	if err != nil {
		t.Fatalf("the shipped public-handshake unit is missing: %v", err)
	}
	found := false
	for _, line := range splitLines(string(data)) {
		if flagdrift.BinaryOf(line, nil) == "buddynet-handshake" && len(line) > 0 && line[0] != '#' {
			found = true
		}
	}
	if !found {
		t.Fatal("no line in the unit invokes buddynet-handshake — the gate would never look at it")
	}
	findings, _, err := flagdrift.Scan(repoRoot(t), "buddynet-handshake", handshakeFlags())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if filepath.Base(f.Path) == "buddynet-public-handshake.service" {
			t.Errorf("the public handshake unit still passes a removed flag: %s", f)
		}
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}
