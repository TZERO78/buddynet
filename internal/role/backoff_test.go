package role

import (
	"testing"
	"time"
)

// jitter must stay within [d/2, d] so the reconnect delay is spread but never
// shrinks below half the backoff nor exceeds it.
func TestJitterBounds(t *testing.T) {
	for _, d := range []time.Duration{reconnectBase, reconnectMax, 17 * time.Second} {
		for i := 0; i < 1000; i++ {
			j := jitter(d)
			if j < d/2 || j > d {
				t.Fatalf("jitter(%s) = %s, want within [%s, %s]", d, j, d/2, d)
			}
		}
	}
	if got := jitter(0); got != 0 {
		t.Fatalf("jitter(0) = %s, want 0", got)
	}
}

// Successive jitter draws must actually vary, otherwise clients would still
// reconnect in lockstep.
func TestJitterVaries(t *testing.T) {
	seen := map[time.Duration]bool{}
	for i := 0; i < 100; i++ {
		seen[jitter(reconnectMax)] = true
	}
	if len(seen) < 50 {
		t.Fatalf("jitter barely varied: only %d distinct values in 100 draws", len(seen))
	}
}
