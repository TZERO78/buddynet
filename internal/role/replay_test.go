package role

import (
	"fmt"
	"testing"
	"time"
)

// A full replay cache must NOT fail open: a brand-new signature is still
// recorded (so a later replay of it is caught) and the cache stays bounded.
func TestReplayCacheNoFailOpenWhenFull(t *testing.T) {
	a := &authorizer{recentSigs: map[string]time.Time{}}
	now := time.Now()
	for i := 0; i < maxReplaySigs; i++ {
		a.recentSigs[fmt.Sprintf("s%d", i)] = now // all fresh, so pruning frees nothing
	}
	if a.replayed("brand-new") {
		t.Fatal("a never-seen signature must not be reported as replayed")
	}
	if _, ok := a.recentSigs["brand-new"]; !ok {
		t.Fatal("new signature should have been recorded (no fail-open admit-without-record)")
	}
	if len(a.recentSigs) > maxReplaySigs {
		t.Fatalf("cache exceeded cap: %d > %d", len(a.recentSigs), maxReplaySigs)
	}
	if !a.replayed("brand-new") {
		t.Fatal("a just-recorded signature must be detected as replayed")
	}
}

// When full of still-fresh entries, the OLDEST is evicted to make room.
func TestReplayEvictsOldestWhenFull(t *testing.T) {
	a := &authorizer{recentSigs: map[string]time.Time{}}
	now := time.Now()
	for i := 0; i < maxReplaySigs; i++ {
		// All within regReplayWindow (~4s spread), with "s0" the oldest.
		a.recentSigs[fmt.Sprintf("s%d", i)] = now.Add(-time.Duration(maxReplaySigs-i) * time.Millisecond)
	}
	a.replayed("brand-new") // full + all fresh -> evict the oldest (s0)
	if _, ok := a.recentSigs["s0"]; ok {
		t.Fatal("oldest entry should have been evicted")
	}
	if _, ok := a.recentSigs["brand-new"]; !ok {
		t.Fatal("new entry should have been recorded")
	}
	if len(a.recentSigs) != maxReplaySigs {
		t.Fatalf("cache size = %d, want %d", len(a.recentSigs), maxReplaySigs)
	}
}
