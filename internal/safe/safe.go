// Package safe converts a panic in a per-request or per-connection goroutine into
// a logged, rate-limited SECURITY event instead of letting it crash the whole
// process. A long-running network daemon must treat every input as potentially
// panic-triggering — a bug in our own parsers, or in a dependency that handles
// untrusted bytes (quic-go, miekg/dns) — and survive it by dropping the one
// request, not the service. Go propagates an un-recovered panic in ANY goroutine
// to the whole process, so without this a single crafted datagram could take the
// VPS roles (and every other tunnel they carry) down.
//
// The wrappers sit at transport-agnostic seams (the control-plane read loops and
// the Session/Stream data-plane handlers), so a future WireGuard transport behind
// the same Transport interface inherits the same panic isolation for free.
package safe

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// logThrottle bounds how often a panic at a given component is logged, so a
// reliably-triggerable panic cannot turn each request into a log line (the
// codebase gates all per-packet load this way). The counter carries the volume.
const logThrottle = 30 * time.Second

var (
	panicCount atomic.Int64

	mu         sync.Mutex
	lastLogged map[string]time.Time // component -> last log time (bounded: fixed set of call-site literals)
)

// Do runs fn and recovers any panic, returning ok=false when it panicked. The
// panic is counted and logged as a throttled SECURITY event tagged with
// component (a fixed call-site label, e.g. "handshake.register"). Use it to wrap
// the body of any goroutine or loop iteration that processes untrusted input.
func Do(component string, fn func()) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			ok = false
			panicCount.Add(1)
			logPanic(component, r)
		}
	}()
	fn()
	return true
}

// Go runs fn in a new goroutine wrapped by Do — a drop-in for `go fn()` at sites
// that handle untrusted input, so a panic there cannot crash the process.
func Go(component string, fn func()) {
	go Do(component, fn)
}

// PanicCount is the total number of panics recovered since start, for an optional
// metric or stats line.
func PanicCount() int64 { return panicCount.Load() }

func logPanic(component string, r any) {
	now := time.Now()
	mu.Lock()
	if lastLogged == nil {
		lastLogged = map[string]time.Time{}
	}
	last, seen := lastLogged[component]
	throttled := seen && now.Sub(last) < logThrottle
	if !throttled {
		lastLogged[component] = now
	}
	mu.Unlock()
	if throttled {
		return
	}
	log.Printf("SECURITY: event=panic-recovered component=%s detail=%q", component, oneline(r))
}

// oneline renders a recovered panic value as a single, length-bounded line so it
// cannot inject newlines into the log or blow up its size (the value may carry
// attacker-influenced bytes).
func oneline(r any) string {
	s := fmt.Sprintf("%v", r)
	s = strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(s)
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
