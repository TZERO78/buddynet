package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// firewallRule matches a line that looks like a packet-filter rule for one of
// BuddyNet's UDP ports, in either nftables or iptables syntax.
var firewallRule = regexp.MustCompile(`(?m)^\s*(udp dport \$?port_(handshake|relay)|-A INPUT -p udp --dport)\b.*$`)

// TestDocsDoNotRestateShippedFirewall is the same failure as A-05 (see
// internal/flagdrift), one artifact over: docs/VPS-HOWTO.md carried its own copy
// of the shipped nftables ruleset, the two drifted, and the copy in the docs was
// the one with the hole in it — `ct state established,related accept` placed
// BEFORE the rate limit, no explicit drop for the excess, and a packets-per-second
// cap on the relay port that would throttle tunnel data. An operator who trusted
// the page instead of the file got the weaker policy, and nothing noticed for
// releases.
//
// The fix was to stop keeping a second copy. This test keeps it that way: no
// document under docs/ may restate a BuddyNet UDP filter rule. Prose describing
// what the shipped file does is fine and encouraged — a copyable rule is not,
// because a copyable rule is a second source of truth that can rot.
//
// deployments/ is exempt: that IS the source of truth.
func TestDocsDoNotRestateShippedFirewall(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}

	// Guard against a vacuously green test: the rules must be findable where
	// they really live, or the regexp has rotted and the check below proves
	// nothing.
	var shippedHits int
	for _, f := range []string{"deployments/nftables.conf", "deployments/iptables.rules"} {
		b, rerr := os.ReadFile(filepath.Join(root, f)) // #nosec G304 -- fixed path in this module
		if rerr != nil {
			t.Fatalf("read %s: %v", f, rerr)
		}
		shippedHits += len(firewallRule.FindAllString(string(b), -1))
	}
	if shippedHits < 4 {
		t.Fatalf("found only %d firewall rules in the shipped files — the pattern no longer "+
			"matches them, so this test would pass no matter what the docs contain", shippedHits)
	}

	docs := filepath.Join(root, "docs")
	walkErr := filepath.WalkDir(docs, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// docs/plans is gitignored working material and may quote anything.
		if d.IsDir() && d.Name() == "plans" {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		b, rerr := os.ReadFile(path) // #nosec G304 -- walking this module's own docs
		if rerr != nil {
			return rerr
		}
		if hits := firewallRule.FindAllString(string(b), -1); len(hits) > 0 {
			rel, _ := filepath.Rel(root, path)
			t.Errorf("%s restates %d shipped firewall rule(s), e.g. %q — describe what "+
				"deployments/nftables.conf does instead of copying it; the copy is what drifted last time",
				rel, len(hits), strings.TrimSpace(hits[0]))
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk docs: %v", walkErr)
	}
}
