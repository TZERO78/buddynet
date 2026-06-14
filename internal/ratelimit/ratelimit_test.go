package ratelimit

import "testing"

// A single source may burst up to its ceiling, then is throttled.
func TestPerSourceBurstThenThrottle(t *testing.T) {
	l := New(1e6, 10, 64) // global effectively unlimited; per-source burst = 20
	allowed := 0
	for i := 0; i < 100; i++ {
		if l.Allow("1.2.3.4") {
			allowed++
		}
	}
	if allowed == 0 || allowed > 21 {
		t.Fatalf("per-source burst not enforced: admitted %d (want 1..21)", allowed)
	}
}

// The global ceiling caps total admissions even across many distinct sources.
func TestGlobalCeilingAcrossSources(t *testing.T) {
	l := New(10, 1e6, 100000) // global burst = 20; per-source effectively unlimited
	allowed := 0
	for i := 0; i < 1000; i++ {
		if l.Allow(string(rune(i))) { // a fresh source each time
			allowed++
		}
	}
	if allowed > 21 {
		t.Fatalf("global ceiling not enforced: admitted %d (want <=21)", allowed)
	}
}

// The per-source map stays bounded under a flood of distinct sources.
func TestSourceMapBounded(t *testing.T) {
	const max = 128
	l := New(1e6, 1e6, max)
	for i := 0; i < 10000; i++ {
		l.Allow(string(rune(i)))
	}
	if len(l.perSrc) > max {
		t.Fatalf("source map grew past bound: %d > %d", len(l.perSrc), max)
	}
}
