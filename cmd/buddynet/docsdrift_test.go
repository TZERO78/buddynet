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
// internal/flagdrift), one artifact over: docs/SETUP.md carried its own copy
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

// refutedClaim is a statement about BuddyNet's security boundary that the code
// once made true, later stopped making true, and that survived in prose because
// the sweep that changed the behaviour only updated some of the places that
// described it.
type refutedClaim struct {
	name    string         // short label for the failure message
	pattern *regexp.Regexp // matches the refuted wording
	why     string         // what is actually true, and where that is written down
	example string         // a sentence the pattern MUST match (anti-vacuum guard)
}

// refutedClaims is the list. Each entry is a real drift that shipped, not a
// hypothetical one — see the audit trail in the test doc below.
var refutedClaims = []refutedClaim{
	{
		name:    "firewall-is-optional",
		pattern: regexp.MustCompile(`(?i)no separate firewall|firewall is (not needed|unnecessary)|needs no firewall`),
		why: "--allow-cidr runs before any crypto on the RELAY only. On the handshake server " +
			"quic-go owns the packet path, so TLS has already run (SECURITY.md 5.5). A host or " +
			"cloud firewall is the only layer that caps the pre-TLS cost, and the docs must say so.",
		example: "a private relay/handshake needs no separate firewall.",
	},
	{
		name: "authorized-gates-tls",
		// pins/pinning/pinned: docs/WIREGUARD.md carried the claim as "pinning
		// clients to the allowlist at the TLS handshake" and slipped a narrower
		// pattern that only knew "pins".
		pattern: regexp.MustCompile(`(?i)pin(s|ning|ned)? clients ([^.\n]{0,40})?(to the allowlist|by key) at the \*{0,2}TLS handshake`),
		why: "TLS AUTHENTICATES every client by its Ed25519 key but AUTHORIZES none. A TLS-layer " +
			"allowlist gate would make code-based enrollment impossible (fixed in 0081a42), so the " +
			"allowlist decision is made per signed REGISTER in pairRegister. Say 'authenticates', " +
			"and put the allowlist decision at REGISTER.",
		example: "with --authorized, pinning clients to the allowlist at the TLS handshake.",
	},
	{
		name:    "join-is-a-fixed-token",
		pattern: regexp.MustCompile("(?i)fixed token (used|reused)|`--join`[^.\n]{0,60}legacy mode"),
		why: "--token, the long-lived bearer secret replayed on every reconnect, was removed in v5. " +
			"Both --invite and --join set the ephemeral one-time path (cmd/buddynet/main.go) and " +
			"retire the token in favour of the derived session secret.",
		example: "`--join` is the legacy mode: a single fixed token used for rendezvous.",
	},
	{
		name: "invite-expires-server-side",
		// Deliberately narrow: SECURITY.md and docs/SETUP.md both say a leaked
		// invite is NOT worthless after 15 minutes, which is the correct claim.
		// A pattern that cannot tell those apart from the wrong one is worse
		// than no pattern — it trains people to weaken the true sentence.
		pattern: regexp.MustCompile(`(?i)valid (only )?\d+ ?min`),
		why: "\"One-time\" is a client-side property. The server keeps no list of spent tokens and " +
			"never marks an invite spent; --invite-timeout bounds how long the INVITER WAITS. " +
			"See docs/SETUP.md 'What a leaked invite is worth'.",
		example: "a one-time invite (valid 15 min or until first pairing):",
	},
	{
		name:    "both-ports-rate-limited",
		pattern: regexp.MustCompile(`(?i)(both|two)[^.\n]{0,40}ports[^.\n]{0,30}\n?[^.\n]{0,20}rate-limited`),
		why: "Only the handshake port carries a packet-rate limit. The relay port deliberately does " +
			"not: it carries tunnel DATA, and a control-plane rate would throttle the tunnel. " +
			"See the comments in deployments/nftables.conf.",
		example: "opens only SSH and the two BuddyNet UDP ports\n(rate-limited against floods).",
	},
}

// TestDocsDoNotRestateRefutedClaims is the root-cause gate for the 2026-08-25
// audit. Every finding in it had the same shape: a commit changed what the code
// guarantees and updated ONE of the places that described the old guarantee.
//
//   - a023614 added allowlist pinning at the TLS handshake and 761b6fb wrote it up;
//     0081a42 then removed it (it made enrollment unreachable) and updated only
//     docs/SETUP.md. OPERATIONS.md, WIREGUARD.md and --help kept the old claim
//     for four releases — OPERATIONS.md even quoted a log line the server had
//     stopped printing.
//   - 546fdf9 removed the plain-UDP control plane; docs/SETUP.md kept a
//     dangling "Without this, a REGISTER travels in cleartext".
//   - the commit removing --token left SECURITY.md and docs/PROTOCOL.md calling
//     --join a fixed-token legacy mode.
//
// TestDocsDoNotRestateShippedFirewall gates a copied artifact; this gates a
// claim, and — unlike that test — it walks the WHOLE repository. Scoping the
// firewall test to docs/ is exactly why the README sentence telling operators a
// firewall was unnecessary survived the previous audit round.
//
// Adding an entry is the intended way to close a documentation finding: fix the
// prose, then make the old wording unsayable.
func TestDocsDoNotRestateRefutedClaims(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}

	// Anti-vacuum: a pattern that no longer matches the wording it was written
	// for proves nothing about the tree. Every claim must still catch its own
	// historical sentence.
	for _, c := range refutedClaims {
		if !c.pattern.MatchString(c.example) {
			t.Fatalf("claim %q no longer matches its own example %q — the pattern has rotted "+
				"and this test would pass no matter what the tree says", c.name, c.example)
		}
	}

	// CHANGELOG.md is the historical record: it MUST be able to state what was
	// once true. docs/plans is gitignored working material, and lab/ documents
	// attacks against past versions. Everything else describes the shipped
	// system and has to be true of it.
	// .claude holds detached worktrees — snapshots of OLDER trees, which legitimately
	// still carry the old wording; gating them would report the past as a regression.
	skipDirs := map[string]bool{".git": true, ".claude": true, "plans": true, "lab": true, "media": true}
	// This file carries every refuted sentence verbatim as its anti-vacuum guard.
	skipFiles := map[string]bool{"CHANGELOG.md": true, "cmd/buddynet/docsdrift_test.go": true}

	var scanned int
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if skipFiles[rel] {
			return nil
		}
		// Prose, deployment templates, and the operator-facing help text in
		// cmd/ — the three places a boundary claim reaches an operator.
		switch {
		case strings.HasSuffix(path, ".md"),
			strings.HasPrefix(rel, "deployments/"),
			strings.HasPrefix(rel, "cmd/") && strings.HasSuffix(path, ".go"):
		default:
			return nil
		}
		b, rerr := os.ReadFile(path) // #nosec G304 -- walking this module's own tree
		if rerr != nil {
			return rerr
		}
		scanned++
		for _, c := range refutedClaims {
			if hit := c.pattern.FindString(string(b)); hit != "" {
				t.Errorf("%s states a refuted claim (%s): %q\n  → %s",
					rel, c.name, strings.TrimSpace(hit), c.why)
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk repository: %v", walkErr)
	}
	if scanned < 20 {
		t.Fatalf("only %d files scanned — the walk is not reaching the docs, so this test "+
			"would pass vacuously", scanned)
	}
}

// mdLink matches a relative Markdown link, capturing the file part and the
// optional #anchor: [text](../SECURITY.md#82-revoking-access).
var mdLink = regexp.MustCompile(`\]\(([^)#\s]*\.md)?(?:#([^)\s]+))?\)`)

// mdHeading matches an ATX heading so the anchors a file OFFERS can be derived.
var mdHeading = regexp.MustCompile(`(?m)^#{1,6}\s+(.*?)\s*$`)

// githubSlug reproduces GitHub's heading-to-anchor rule closely enough for this
// repository: strip code spans and link syntax, lowercase, drop punctuation,
// spaces to hyphens. An em dash surrounded by spaces therefore becomes "--".
func githubSlug(heading string) string {
	s := regexp.MustCompile("`([^`]*)`").ReplaceAllString(heading, "$1")
	s = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`).ReplaceAllString(s, "$1")
	s = strings.ToLower(s)
	s = regexp.MustCompile(`[^\p{L}\p{N}\s-]`).ReplaceAllString(s, "")
	return regexp.MustCompile(`\s`).ReplaceAllString(s, "-")
}

// TestMarkdownLinksAndAnchorsResolve walks every Markdown file and proves that
// each relative link points at a file that exists AND, when it carries a
// #anchor, at a heading that exists in that file.
//
// TestDocReferencesExist (internal/role) covers doc paths named in GO source. It
// does NOT read Markdown, which is why consolidating docs/ could silently break
// prose links — the 2026-08-25 consolidation folded 7 files into 2 and rewrote
// references in 17 files; one anchor survived the rewrite pointing at a heading
// that had moved, and nothing would have caught it.
//
// Dead anchors are worse than dead files: GitHub serves the page and silently
// ignores the fragment, so the reader lands at the top of a long document and
// never learns the section they were sent to no longer exists.
func TestMarkdownLinksAndAnchorsResolve(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}

	anchors := map[string]map[string]bool{} // abs path -> set of slugs
	anchorsOf := func(path string) map[string]bool {
		if a, ok := anchors[path]; ok {
			return a
		}
		a := map[string]bool{}
		if b, rerr := os.ReadFile(path); rerr == nil { // #nosec G304 -- this module's own docs
			for _, m := range mdHeading.FindAllStringSubmatch(string(b), -1) {
				a[githubSlug(m[1])] = true
			}
		}
		anchors[path] = a
		return a
	}

	skip := map[string]bool{".git": true, ".claude": true, "plans": true, "dist": true, "node_modules": true}
	var files, links int
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".md") {
			return nil
		}
		b, rerr := os.ReadFile(path) // #nosec G304 -- this module's own docs
		if rerr != nil {
			return rerr
		}
		files++
		rel, _ := filepath.Rel(root, path)
		for _, m := range mdLink.FindAllStringSubmatch(string(b), -1) {
			file, anchor := m[1], m[2]
			if file == "" && anchor == "" {
				continue
			}
			target := path // an anchor with no file is same-page
			if file != "" {
				// Resolve against the linking file's directory, the way a
				// reader's browser does. The captured path keeps its ../ prefix.
				target = filepath.Join(filepath.Dir(path), file)
				if _, statErr := os.Stat(target); statErr != nil {
					t.Errorf("%s links to %q, which does not exist", rel, file)
					continue
				}
			}
			links++
			if anchor == "" {
				continue
			}
			if !anchorsOf(target)[anchor] {
				trel, _ := filepath.Rel(root, target)
				t.Errorf("%s links to %s#%s — that file has no such heading. GitHub will "+
					"serve the page and silently drop the fragment, dumping the reader at the top",
					rel, trel, anchor)
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk repository: %v", walkErr)
	}
	if files < 10 || links < 30 {
		t.Fatalf("only %d markdown files and %d resolvable links seen — the walk or the "+
			"pattern is broken, and this test would pass vacuously", files, links)
	}
}

// TestShippedFirewallLimitsPerSourceBeforeGlobal pins the rule ORDER on the
// handshake port in both shipped rulesets.
//
// The port is limited twice: a per-source bucket (nftables `meter`, iptables
// `hashlimit`) and a global ceiling (`limit`). Which comes first is not a matter
// of taste. A global limit is source-blind, so ahead of the per-source rule it
// drops a share of every sender's packets — including those of the buddy the
// fairness rule exists to protect. lab/test-firewall-fairness.sh measures the
// difference: a legitimate buddy keeps 15% of its unopposed throughput with the
// global limit alone, 77% with global first, and 100% with per-source first.
//
// That lab test needs root, netns and a few minutes. This one is the cheap
// always-on guard that runs in CI on every change, so the order cannot be
// swapped back by an edit that never gets a lab run.
//
// It deliberately checks the RULES, not the prose around them. The comment above
// these rules once numbered them in the opposite order to the rules themselves,
// which is how this test came to exist — but a gate on comment wording would be
// guessing at English, while the order of two lines is a fact.
func TestShippedFirewallLimitsPerSourceBeforeGlobal(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}

	for _, tc := range []struct {
		file      string
		perSource *regexp.Regexp
		global    *regexp.Regexp
	}{
		{
			file:      "deployments/nftables.conf",
			perSource: regexp.MustCompile(`(?m)^\s*udp dport \$?port_handshake.*\bmeter\b`),
			global:    regexp.MustCompile(`(?m)^\s*udp dport \$?port_handshake\s+limit rate`),
		},
		{
			file:      "deployments/iptables.rules",
			perSource: regexp.MustCompile(`(?m)^-A INPUT -p udp --dport \d+ .*\bhashlimit\b`),
			global:    regexp.MustCompile(`(?m)^-A INPUT -p udp --dport \d+ -m limit\b`),
		},
	} {
		b, rerr := os.ReadFile(filepath.Join(root, tc.file)) // #nosec G304 -- fixed path in this module
		if rerr != nil {
			t.Errorf("read %s: %v", tc.file, rerr)
			continue
		}
		body := string(b)

		ps := tc.perSource.FindStringIndex(body)
		gl := tc.global.FindStringIndex(body)
		if ps == nil {
			t.Errorf("%s has no per-source rate limit on the handshake port — one loud "+
				"source can spend the whole budget (audit finding M-02)", tc.file)
		}
		if gl == nil {
			t.Errorf("%s has no global rate ceiling on the handshake port — nothing bounds "+
				"what many sources together cost the box", tc.file)
		}
		if ps == nil || gl == nil {
			continue
		}
		if ps[0] > gl[0] {
			t.Errorf("%s puts the global ceiling BEFORE the per-source limit. A global limit "+
				"is source-blind: ahead of the per-source rule it drops a share of every "+
				"sender's packets, so a flood still costs your buddies ~23%% of their "+
				"throughput (measured by lab/test-firewall-fairness.sh). Per-source first.",
				tc.file)
		}
	}
}

// TestShippedIptablesRulesAreLoadable guards two things iptables-restore is
// strict about and a reader's eye is not.
//
// `iptables-restore` parses line by line and has NO line-continuation syntax: a
// rule broken across lines with a trailing backslash makes the whole file fail
// to load with "Bad argument `\'". Reformatting a long rule for readability —
// which is exactly what happened when the per-source limit was added — turns the
// shipped ruleset into one that cannot be applied at all. nftables tolerates the
// same edit, so a change tested only against nftables looks fine.
//
// It also pins the IPv6 note. hashlimit keys on the full address unless told
// otherwise, and a /64 is what one subscriber gets, so without
// --hashlimit-srcmask an attacker holding a single /64 gets a fresh bucket per
// address and the per-source limit buys nothing. Measured in
// lab/test-firewall-fairness.sh --iptables --ipv6: 249 packets through with /64
// keying, 1245 with /128. iptables(v4) refuses a mask above 32, so the file
// cannot carry both values and has to document the per-family edit instead.
func TestShippedIptablesRulesAreLoadable(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}
	path := filepath.Join(root, "deployments/iptables.rules")
	b, err := os.ReadFile(path) // #nosec G304 -- fixed path in this module
	if err != nil {
		t.Fatalf("read iptables.rules: %v", err)
	}
	body := string(b)

	for i, line := range strings.Split(body, "\n") {
		if strings.HasSuffix(strings.TrimRight(line, " \t"), `\`) && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			t.Errorf("deployments/iptables.rules:%d ends in a backslash. iptables-restore has "+
				"no line continuation and rejects the WHOLE file with \"Bad argument\". "+
				"Keep rules on one line, however long: %s", i+1, strings.TrimSpace(line))
		}
	}

	// The per-source rule must state its mask explicitly, so the IPv6 edit is a
	// visible one-token change rather than a silently missing default.
	if strings.Contains(body, "hashlimit-mode srcip") && !strings.Contains(body, "hashlimit-srcmask") {
		t.Error("the hashlimit rule has no --hashlimit-srcmask. On IPv6 it then keys on the " +
			"full /128, and one attacker /64 yields a bucket per address — the per-source " +
			"limit buys nothing (measured: 1245 packets through vs 249 with /64 keying)")
	}
	if !strings.Contains(body, "ip6tables-restore") {
		t.Error("iptables.rules no longer documents the ip6tables edits. The file cannot carry " +
			"both masks (iptables refuses > 32), so the note is the only thing standing " +
			"between an operator and a v6 ruleset whose fairness rule does nothing")
	}
}
