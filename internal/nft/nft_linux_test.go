//go:build linux

package nft

import (
	"encoding/binary"
	"syscall"
	"testing"
)

// attrWalk iterates netlink attributes, mirroring the wg package's test helper.
func attrWalk(b []byte, fn func(typ uint16, val []byte)) {
	for len(b) >= 4 {
		l := nativeEndian.Uint16(b[0:2])
		t := nativeEndian.Uint16(b[2:4])
		if int(l) < 4 || int(l) > len(b) {
			return
		}
		fn(t&nlaTypeMask, b[4:l])
		adv := (int(l) + 3) &^ 3
		if adv > len(b) {
			return
		}
		b = b[adv:]
	}
}

// exprNames decodes the expression names of one rule's NFTA_RULE_EXPRESSIONS payload.
func exprNames(t *testing.T, exprs []byte) []string {
	t.Helper()
	var names []string
	attrWalk(exprs, func(typ uint16, val []byte) {
		if typ != nftaListElem {
			t.Fatalf("unexpected attr %d in expression list", typ)
		}
		attrWalk(val, func(typ uint16, v []byte) {
			if typ == nftaExprName {
				names = append(names, string(v[:len(v)-1])) // strip NUL
			}
		})
	})
	return names
}

func TestRuleExprsShape(t *testing.T) {
	s, err := ParseScope("tcp/873,udp/51820")
	if err != nil {
		t.Fatal(err)
	}
	rules := ruleExprs("bnet0", s)
	// est/rel + 2 ports + icmp + icmpv6 + final drop
	if len(rules) != 6 {
		t.Fatalf("want 6 rules, got %d", len(rules))
	}
	want := [][]string{
		{"meta", "cmp", "ct", "bitwise", "cmp", "immediate"},          // est,rel accept
		{"meta", "cmp", "meta", "cmp", "payload", "cmp", "immediate"}, // tcp/873
		{"meta", "cmp", "meta", "cmp", "payload", "cmp", "immediate"}, // udp/51820
		{"meta", "cmp", "meta", "cmp", "immediate"},                   // icmp
		{"meta", "cmp", "meta", "cmp", "immediate"},                   // icmpv6
		{"meta", "cmp", "immediate"},                                  // drop
	}
	for i, w := range want {
		got := exprNames(t, rules[i])
		if len(got) != len(w) {
			t.Fatalf("rule %d: expr names %v, want %v", i, got, w)
		}
		for j := range w {
			if got[j] != w[j] {
				t.Fatalf("rule %d: expr names %v, want %v", i, got, w)
			}
		}
	}
}

func TestRuleExprsAllYieldsNoRules(t *testing.T) {
	if rules := ruleExprs("bnet0", Scope{All: true}); rules != nil {
		t.Fatalf("expose all must render no rules (policy accept), got %d", len(rules))
	}
}

func TestRuleExprsZeroScopeStillDrops(t *testing.T) {
	rules := ruleExprs("bnet0", Scope{})
	// est/rel + icmp + icmpv6 + drop — fail-closed floor with no ports.
	if len(rules) != 4 {
		t.Fatalf("want 4 rules for the fail-closed floor, got %d", len(rules))
	}
	last := exprNames(t, rules[len(rules)-1])
	if last[len(last)-1] != "immediate" {
		t.Fatalf("final rule must end in a verdict, got %v", last)
	}
}

// The batch must be parseable netlink, be delimited by BATCH_BEGIN/END, and
// use the add-del(-add) table idiom so stale state is always cleared.
func TestBuildBatchStructure(t *testing.T) {
	s, _ := ParseScope("873")
	batch := buildBatch(map[string]Scope{"bnet0": s}, []string{"bnet0"})
	msgs, err := syscall.ParseNetlinkMessage(batch)
	if err != nil {
		t.Fatalf("batch does not parse: %v", err)
	}
	var types []uint16
	for _, m := range msgs {
		types = append(types, m.Header.Type)
	}
	nft := func(m uint16) uint16 { return nfnlSubsysNftables<<8 | m }
	if types[0] != nfnlMsgBatchBegin || types[len(types)-1] != nfnlMsgBatchEnd {
		t.Fatalf("batch not delimited: %v", types)
	}
	if types[1] != nft(nftMsgNewTable) || types[2] != nft(nftMsgDelTable) || types[3] != nft(nftMsgNewTable) {
		t.Fatalf("missing add-del-add table idiom: %v", types)
	}
	// Two base chains follow the table: "in" (input hook) and "fwd" (forward hook).
	if types[4] != nft(nftMsgNewChain) || types[5] != nft(nftMsgNewChain) {
		t.Fatalf("both base chains must follow the table: %v", types)
	}
	chains := 0
	rules := 0
	for _, tt := range types {
		switch tt {
		case nft(nftMsgNewChain):
			chains++
		case nft(nftMsgNewRule):
			rules++
		}
	}
	if chains != 2 { // input scope + forward block
		t.Fatalf("want 2 base chains, got %d (%v)", chains, types)
	}
	if rules != 6 { // in: est/rel + tcp/873 + icmp + icmpv6 + drop; fwd: drop
		t.Fatalf("want 6 rule messages, got %d (%v)", rules, types)
	}
	// BATCH_BEGIN/END res_id must name the nftables subsystem (big endian).
	resID := binary.BigEndian.Uint16(msgs[0].Data[2:4])
	if resID != nfnlSubsysNftables {
		t.Fatalf("batch res_id = %d, want %d", resID, nfnlSubsysNftables)
	}
}

// An empty scope map renders a batch that only removes the table.
func TestBuildBatchEmptyRemovesTable(t *testing.T) {
	batch := buildBatch(map[string]Scope{}, nil)
	msgs, err := syscall.ParseNetlinkMessage(batch)
	if err != nil {
		t.Fatalf("batch does not parse: %v", err)
	}
	if len(msgs) != 4 { // begin, newtable, deltable, end
		t.Fatalf("want 4 messages, got %d", len(msgs))
	}
}
