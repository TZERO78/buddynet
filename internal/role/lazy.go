package role

import (
	"context"
	"log"
	"net"
	"sync"
	"sync/atomic"

	"github.com/tzero78/buddynet/internal/tunnel"
)

// lazyTunnel coordinates on-demand tunnel establishment for --lazy mode.
// State transitions:
//
//	SLEEPING (sess==nil, !waking) ──get()──► WAKING (waking==true)
//	WAKING ──setSession()──► CONNECTED (sess!=nil)
//	WAKING ──setFailed()───► SLEEPING (via markIdle)
//	CONNECTED ──markIdle()─► SLEEPING
//
// SLEEPING can persist indefinitely — --idle-timeout only fires on an active
// QUIC connection (CONNECTED), never during SLEEPING.
// On ctx cancel in SLEEPING the reconnect loop's select fires via ctx.Done().
type lazyTunnel struct {
	mu     sync.Mutex
	sess   tunnel.Session // nil = SLEEPING or WAKING; non-nil = CONNECTED
	ready  chan struct{}  // closed when sess/err set; replaced on markIdle
	waking bool           // true = WAKING (dial in flight)
	err    error

	// wake is 1-buffered so N concurrent get() callers safely signal the
	// reconnect loop to start a dial without blocking or losing the signal.
	wake chan struct{}
}

func newLazyTunnel() *lazyTunnel {
	return &lazyTunnel{
		ready: make(chan struct{}),
		wake:  make(chan struct{}, 1),
	}
}

// get returns the current session (CONNECTED fast-path) or blocks until one
// becomes available (WAKING) or ctx is cancelled.
func (lt *lazyTunnel) get(ctx context.Context) (tunnel.Session, error) {
	lt.mu.Lock()
	if lt.sess != nil {
		sess := lt.sess
		lt.mu.Unlock()
		return sess, nil
	}
	// Transition to WAKING on first waiter; subsequent callers share the same
	// ready channel.
	firstWake := false
	if !lt.waking {
		lt.waking = true
		firstWake = true
		select {
		case lt.wake <- struct{}{}:
		default: // already queued; 1-buffered guarantees at most one pending wake
		}
	}
	ready := lt.ready
	lt.mu.Unlock()

	// Log the wake outside the lock; the tunnel coming up is then reported by the
	// usual CONNECTED: line, so an operator sees the full lazy timeline.
	if firstWake {
		log.Printf("LAZY: action=waking detail=%q", "local connection arrived, dialing tunnel")
	}

	select {
	case <-ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Re-lock to read; happens-before is guaranteed by the mutex release in
	// setSession/setFailed and acquisition here.
	lt.mu.Lock()
	sess, err := lt.sess, lt.err
	lt.mu.Unlock()
	return sess, err
}

// setSession signals all waiters that the tunnel is up.
// INVARIANT: lt.sess MUST be written before close(lt.ready), both under lt.mu,
// so that waiters always observe a non-nil sess after <-ready fires.
func (lt *lazyTunnel) setSession(sess tunnel.Session) {
	lt.mu.Lock()
	lt.sess = sess  // write payload first
	lt.err = nil    //
	close(lt.ready) // then unblock waiters — they re-lock mu to read sess
	lt.mu.Unlock()
}

// setFailed signals all waiters that the dial attempt failed.
// INVARIANT: lt.err MUST be written before close(lt.ready), both under lt.mu,
// so that waiters always observe a non-nil err after <-ready fires.
func (lt *lazyTunnel) setFailed(err error) {
	lt.mu.Lock()
	lt.err = err  // write payload first
	lt.sess = nil //
	lt.waking = false
	close(lt.ready) // then unblock waiters
	lt.mu.Unlock()
}

// markIdle resets the tunnel to SLEEPING so the next get() triggers a fresh
// wakeup. Must be called after setFailed or after the session ends (idle-timeout
// or peer-close fires sess.Done()).
func (lt *lazyTunnel) markIdle() {
	lt.mu.Lock()
	lt.sess = nil
	lt.err = nil
	lt.waking = false
	lt.ready = make(chan struct{}) // fresh channel; the old one was already closed
	lt.mu.Unlock()
}

// lazyForward is the -L acceptor for --lazy mode. It runs for the lifetime of
// Buddy() — across tunnel reconnects — and fetches the session on-demand via
// lt.get(). The existing maxConcurrentStreams semaphore bounds goroutine count.
// No application-level read buffer is needed: the OS TCP receive buffer holds
// client data while the tunnel is WAKING (~64–128 KB default).
func lazyForward(ctx context.Context, ln net.Listener, lt *lazyTunnel, count *atomic.Int64) {
	sem := make(chan struct{}, maxConcurrentStreams)
	for {
		c, err := ln.Accept()
		if err != nil {
			return // listener closed (ctx cancel or shutdown)
		}
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			sess, err := lt.get(ctx)
			if err != nil {
				c.Close()
				return
			}
			st, err := sess.OpenStream(ctx)
			if err != nil {
				c.Close()
				return
			}
			count.Add(1)
			splice(c, st)
		}()
	}
}
