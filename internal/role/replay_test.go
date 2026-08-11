package role

import (
	"fmt"
	"testing"
	"time"
)

// A full replay cache must NOT fail open: a brand-new signature is still
// recorded (so a later replay of it is caught) and the cache stays bounded.
func TestReplayCacheNoFailOpenWhenFull(t *testing.T) {
	a := &authorizer{recentRegs: map[string]time.Time{}}
	now := time.Now()
	for i := 0; i < maxReplayRegs; i++ {
		a.recentRegs["key\x00"+fmt.Sprintf("s%d", i)] = now // all fresh, so pruning frees nothing
	}
	if a.replayed("key", "brand-new") {
		t.Fatal("a never-seen signature must not be reported as replayed")
	}
	if _, ok := a.recentRegs["key\x00brand-new"]; !ok {
		t.Fatal("new signature should have been recorded (no fail-open admit-without-record)")
	}
	if len(a.recentRegs) > maxReplayRegs {
		t.Fatalf("cache exceeded cap: %d > %d", len(a.recentRegs), maxReplayRegs)
	}
	if !a.replayed("key", "brand-new") {
		t.Fatal("a just-recorded signature must be detected as replayed")
	}
}

// When full of still-fresh entries, the OLDEST is evicted to make room.
func TestReplayEvictsOldestWhenFull(t *testing.T) {
	a := &authorizer{recentRegs: map[string]time.Time{}}
	now := time.Now()
	for i := 0; i < maxReplayRegs; i++ {
		// All within regReplayWindow (~4s spread), with "s0" the oldest.
		a.recentRegs["key\x00"+fmt.Sprintf("s%d", i)] = now.Add(-time.Duration(maxReplayRegs-i) * time.Millisecond)
	}
	a.replayed("key", "brand-new") // full + all fresh -> evict the oldest (s0)
	if _, ok := a.recentRegs["key\x00s0"]; ok {
		t.Fatal("oldest entry should have been evicted")
	}
	if _, ok := a.recentRegs["key\x00brand-new"]; !ok {
		t.Fatal("new entry should have been recorded")
	}
	if len(a.recentRegs) != maxReplayRegs {
		t.Fatalf("cache size = %d, want %d", len(a.recentRegs), maxReplayRegs)
	}
}
