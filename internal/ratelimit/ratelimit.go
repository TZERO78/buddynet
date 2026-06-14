// Package ratelimit is a small, dependency-free token-bucket limiter for the
// public-facing UDP servers (handshake, relay). It gates work BEFORE the
// expensive per-packet crypto so a flood is dropped with a cheap map lookup
// instead of saturating the single read loop.
//
// Two buckets cooperate per Allow:
//
//   - a GLOBAL bucket caps total admitted packets per second regardless of
//     source address — the hard ceiling that holds even when the source is
//     spoofed (and the source is always forgeable on UDP), and
//   - a PER-SOURCE bucket adds fairness so one address cannot consume the whole
//     global budget and starve everyone else.
//
// The per-source map is itself attacker-growable (spoofed sources), so it is
// bounded and pruned; when it is full of active sources a new one is dropped.
package ratelimit

import (
	"sync"
	"time"
)

// bucket is a single token bucket. It is not safe for concurrent use on its
// own; Limiter.mu guards every access.
type bucket struct {
	tokens float64
	last   time.Time
}

// take refills by elapsed time (capped at burst) and removes one token,
// reporting whether a token was available.
func (b *bucket) take(now time.Time, rate, burst float64) bool {
	b.tokens += now.Sub(b.last).Seconds() * rate
	if b.tokens > burst {
		b.tokens = burst
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// full reports whether the bucket has refilled to its burst ceiling, i.e. the
// source has been idle long enough that forgetting it loses no state. Used to
// pick prune victims.
func (b *bucket) full(now time.Time, rate, burst float64) bool {
	return b.tokens+now.Sub(b.last).Seconds()*rate >= burst
}

// Limiter combines a global ceiling with bounded per-source fairness.
type Limiter struct {
	globalRate, globalBurst float64
	srcRate, srcBurst       float64
	maxSources              int

	mu     sync.Mutex
	global bucket
	perSrc map[string]*bucket
}

// New builds a Limiter. globalRate/globalBurst cap total admitted packets per
// second; srcRate/srcBurst do the same per source; maxSources bounds the
// per-source map. Bursts default to 2x the rate when given as 0.
func New(globalRate, srcRate float64, maxSources int) *Limiter {
	return &Limiter{
		globalRate:  globalRate,
		globalBurst: 2 * globalRate,
		srcRate:     srcRate,
		srcBurst:    2 * srcRate,
		maxSources:  maxSources,
		global:      bucket{tokens: 2 * globalRate, last: time.Now()},
		perSrc:      map[string]*bucket{},
	}
}

// Allow reports whether a packet from src may be processed. It charges the
// per-source bucket first (so an over-quota source is dropped cheaply without
// spending global budget), then the global bucket.
func (l *Limiter) Allow(src string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.perSrc[src]
	if b == nil {
		if len(l.perSrc) >= l.maxSources {
			l.pruneLocked(now)
			if len(l.perSrc) >= l.maxSources {
				return false // map full of active sources: drop to stay bounded
			}
		}
		b = &bucket{tokens: l.srcBurst, last: now}
		l.perSrc[src] = b
	}
	if !b.take(now, l.srcRate, l.srcBurst) {
		return false
	}
	return l.global.take(now, l.globalRate, l.globalBurst)
}

// pruneLocked drops fully-refilled (idle) per-source buckets. Caller holds mu.
func (l *Limiter) pruneLocked(now time.Time) {
	for src, b := range l.perSrc {
		if b.full(now, l.srcRate, l.srcBurst) {
			delete(l.perSrc, src)
		}
	}
}
