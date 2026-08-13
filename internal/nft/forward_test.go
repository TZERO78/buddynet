//go:build linux

package nft

// Regression tests for M-1: --expose installs its rules in ONE base chain on the
// NF_INET_LOCAL_IN hook (internal/nft/nft_linux.go:319, chain "in"). Nothing is
// installed on the FORWARD hook, so a packet that arrives on bnetN and is
// ROUTED onward never traverses these rules at all.
//
// WireGuard's AllowedIPs constrains the SOURCE of an inbound packet (crypto
// routing: a packet decrypted from peer P is dropped unless its source is inside
// P's AllowedIPs). It says nothing about the DESTINATION. So a buddy may send a
// packet with its own permitted VIP as source and any LAN address behind the
// victim as destination; if the victim forwards, --expose never sees it.
//
// These tests read the batch the production builder emits, decode it, and assert
// on the hooks and chains that are actually programmed.

import (
	"syscall"
	"testing"
)

const nfInetForwardHook = 2 // NF_INET_FORWARD (uapi/linux/netfilter.h)

// chainSpec is one base chain decoded out of a batch.
type chainSpec struct {
	name    string
	hook    uint32
	policy  uint32
	present bool
}

// decodeChains pulls every NEWCHAIN message out of a batch and decodes its name,
// hook number and policy.
func decodeChains(t *testing.T, batch []byte) []chainSpec {
	t.Helper()
	msgs, err := syscall.ParseNetlinkMessage(batch)
	if err != nil {
		t.Fatalf("batch does not parse: %v", err)
	}
	newChain := uint16(nfnlSubsysNftables<<8 | nftMsgNewChain)
	var out []chainSpec
	for _, m := range msgs {
		if m.Header.Type != newChain {
			continue
		}
		if len(m.Data) < 4 {
			t.Fatalf("short nfgenmsg in a NEWCHAIN message")
		}
		c := chainSpec{present: true}
		attrWalk(m.Data[4:], func(typ uint16, val []byte) {
			switch typ {
			case nftaChainName:
				if len(val) > 0 {
					c.name = string(val[:len(val)-1]) // strip NUL
				}
			case nftaChainPolicy:
				if len(val) >= 4 {
					c.policy = beUint32(val)
				}
			case nftaChainHook:
				attrWalk(val, func(ht uint16, hv []byte) {
					if ht == nftaHookHooknum && len(hv) >= 4 {
						c.hook = beUint32(hv)
					}
				})
			}
		})
		out = append(out, c)
	}
	return out
}

func beUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func hooksOf(chains []chainSpec) []uint32 {
	out := make([]uint32, 0, len(chains))
	for _, c := range chains {
		out = append(out, c.hook)
	}
	return out
}

func chainAtHook(chains []chainSpec, hook uint32) chainSpec {
	for _, c := range chains {
		if c.hook == hook {
			return c
		}
	}
	return chainSpec{}
}

// TestInputChainIsProgrammed is the positive control: the batch really does
// contain a decodable base chain on the INPUT hook with policy accept. If this
// fails, the decoder below is broken, not the ruleset.
func TestInputChainIsProgrammed(t *testing.T) {
	s, err := ParseScope("tcp/445")
	if err != nil {
		t.Fatal(err)
	}
	chains := decodeChains(t, buildBatch(map[string]Scope{"bnet0": s}, []string{"bnet0"}))
	in := chainAtHook(chains, nfInetLocalIn)
	if !in.present {
		t.Fatalf("no chain on the INPUT hook; decoded hooks: %v", hooksOf(chains))
	}
	if in.name != chainName {
		t.Fatalf("INPUT chain is named %q, want %q", in.name, chainName)
	}
	if in.policy != nfAccept {
		t.Fatalf("INPUT chain policy = %d, want accept (%d)", in.policy, nfAccept)
	}
}

// TestForwardChainBlocksRoutedTraffic states the security invariant:
//
//	"A scoped buddy interface must not be a route into anything behind the host."
//
// With --expose naming host ports, traffic arriving on bnetN and destined
// ELSEWHERE must be dropped on the FORWARD hook. That requires a second base
// chain at NF_INET_FORWARD; there is none.
func TestForwardChainBlocksRoutedTraffic(t *testing.T) {
	s, err := ParseScope("tcp/445")
	if err != nil {
		t.Fatal(err)
	}
	chains := decodeChains(t, buildBatch(map[string]Scope{"bnet0": s}, []string{"bnet0"}))

	fwd := chainAtHook(chains, nfInetForwardHook)
	if !fwd.present {
		t.Fatalf(`M-1: BuddyNet programs no base chain on the FORWARD hook.

  chains programmed : %d
  hooks             : %v  (want to include %d = NF_INET_FORWARD)
  built from        : --expose tcp/445 on bnet0

--expose only filters NF_INET_LOCAL_IN (internal/nft/nft_linux.go:319). A packet
that arrives on bnet0 with a destination other than the host is handled by the
FORWARD path, which BuddyNet leaves untouched. WireGuard AllowedIPs only pins the
SOURCE of that packet, so a buddy may address anything the victim can route to.`,
			len(chains), hooksOf(chains), nfInetForwardHook)
	}
}

// TestForwardChainExistsEvenForExposeAll pins the second half of the invariant:
// `--expose all` means "the whole HOST", never "and everything behind it", so
// the forward block must be programmed for that scope too.
func TestForwardChainExistsEvenForExposeAll(t *testing.T) {
	s, err := ParseScope("all")
	if err != nil {
		t.Fatal(err)
	}
	if !s.All {
		t.Fatalf("setup: ParseScope(\"all\") did not set All")
	}
	chains := decodeChains(t, buildBatch(map[string]Scope{"bnet0": s}, []string{"bnet0"}))
	if !chainAtHook(chains, nfInetForwardHook).present {
		t.Fatalf(`M-1: with --expose all, BuddyNet programs no FORWARD chain either.

  hooks programmed : %v

`+"`--expose all`"+` opens the host on purpose. It must not silently also open every
network the host can route to.`, hooksOf(chains))
	}
}

// TestForwardRuleIsExactlyOneDrop pins the SHAPE of the forward block for v5, and
// is deliberately strict in both directions.
//
// It must be one rule — `iifname bnetN drop` — and nothing else. In particular it
// must NOT carry a `ct state established,related accept` or a destination match:
// either would already permit part of a routed conversation, i.e. a slice of
// subnet routing, which is a separate feature with its own threat model and its
// own explicit opt-in. Shipping half of it early, under a flag that says
// "expose ports on this host", is exactly what this test exists to prevent.
//
// Replies to connections the HOST itself opened are unaffected and need no rule
// here: they are addressed to the host's own VIP and traverse the input hook.
func TestForwardRuleIsExactlyOneDrop(t *testing.T) {
	for _, spec := range []string{"tcp/445", "all"} {
		t.Run(spec, func(t *testing.T) {
			s, err := ParseScope(spec)
			if err != nil {
				t.Fatal(err)
			}
			rules := forwardExprs("bnet0")
			if len(rules) != 1 {
				t.Fatalf("want exactly 1 forward rule, got %d", len(rules))
			}
			got := exprNames(t, rules[0])
			want := []string{"meta", "cmp", "immediate"} // iifname match + verdict
			if len(got) != len(want) {
				t.Fatalf("forward rule shape %v, want %v — an extra expression here is\n"+
					"an accept or a destination match, i.e. subnet routing shipped early", got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("forward rule shape %v, want %v", got, want)
				}
			}
			// No conntrack expression: no established/related accept.
			for _, n := range got {
				if n == "ct" || n == "bitwise" {
					t.Fatalf("the forward rule carries a conntrack match (%v) — that would accept\n"+
						"replies to FORWARDED connections, which is subnet routing, not --expose", got)
				}
				if n == "payload" {
					t.Fatalf("the forward rule carries a payload match (%v) — a port or address\n"+
						"condition here is subnet routing, not --expose", got)
				}
			}
			// The scope must not influence the forward block at all: `all` means this
			// host, never the networks behind it.
			_ = s
		})
	}
}

// TestForwardBlockIsEmittedForEveryInterface: with several buddies, each one gets
// its own forward drop. A missing rule for bnet1 would leave that buddy routing.
func TestForwardBlockIsEmittedForEveryInterface(t *testing.T) {
	s0, _ := ParseScope("tcp/445")
	s1, _ := ParseScope("all")
	batch := buildBatch(map[string]Scope{"bnet0": s0, "bnet1": s1}, []string{"bnet0", "bnet1"})
	msgs, err := syscall.ParseNetlinkMessage(batch)
	if err != nil {
		t.Fatalf("batch does not parse: %v", err)
	}
	newRule := uint16(nfnlSubsysNftables<<8 | nftMsgNewRule)
	fwdRules := 0
	for _, m := range msgs {
		if m.Header.Type != newRule || len(m.Data) < 4 {
			continue
		}
		attrWalk(m.Data[4:], func(typ uint16, val []byte) {
			if typ == nftaRuleChain && len(val) > 0 && string(val[:len(val)-1]) == fwdChainName {
				fwdRules++
			}
		})
	}
	if fwdRules != 2 {
		t.Fatalf("want one forward drop per interface (2), got %d — a buddy without one still routes", fwdRules)
	}
}

// TestNoRuleTargetsTheForwardPath is the finer statement: even if a chain were
// added later, the rules must actually cover routed traffic. Today ruleExprs
// yields the same iifname-matched rules regardless of path, and no rule set is
// emitted for a forward chain at all.
func TestNoRuleTargetsTheForwardPath(t *testing.T) {
	s, _ := ParseScope("tcp/445")
	batch := buildBatch(map[string]Scope{"bnet0": s}, []string{"bnet0"})
	msgs, err := syscall.ParseNetlinkMessage(batch)
	if err != nil {
		t.Fatalf("batch does not parse: %v", err)
	}
	newRule := uint16(nfnlSubsysNftables<<8 | nftMsgNewRule)
	counts := map[string]int{}
	for _, m := range msgs {
		if m.Header.Type != newRule || len(m.Data) < 4 {
			continue
		}
		attrWalk(m.Data[4:], func(typ uint16, val []byte) {
			if typ == nftaRuleChain && len(val) > 0 {
				counts[string(val[:len(val)-1])]++
			}
		})
	}
	// Positive control: the input chain does carry rules.
	if counts[chainName] == 0 {
		t.Fatalf("decoder found no rules in the %q chain at all: %v", chainName, counts)
	}
	if len(counts) < 2 {
		t.Fatalf(`M-1: every rule BuddyNet emits lives in the single %q (INPUT) chain.

  rules per chain : %v

Routed traffic entering on bnet0 is filtered by nothing BuddyNet installs.`,
			chainName, counts)
	}
}
