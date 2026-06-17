package role

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tzero78/buddynet/internal/tunnel"
)

// lazyTestSession is a minimal tunnel.Session stub for lazy-mode tests.
// It is separate from fakeSession (session_test.go) because it needs a
// closeable Done() channel rather than the static EKM fixture.
type lazyTestSession struct{ done chan struct{} }

func newLazyTestSession() *lazyTestSession                                       { return &lazyTestSession{done: make(chan struct{})} }
func (s *lazyTestSession) OpenStream(_ context.Context) (tunnel.Stream, error)   { return nil, nil }
func (s *lazyTestSession) AcceptStream(_ context.Context) (tunnel.Stream, error) { return nil, nil }
func (s *lazyTestSession) RemoteAddr() net.Addr                                  { return (*net.TCPAddr)(nil) }
func (s *lazyTestSession) ExportKeyingMaterial(string, []byte, int) ([]byte, error) {
	return nil, nil
}
func (s *lazyTestSession) Done() <-chan struct{} { return s.done }
func (s *lazyTestSession) Close() error          { close(s.done); return nil }

var _ tunnel.Session = (*lazyTestSession)(nil)

// TestLazyConnectSuccess: a single get() blocks until setSession fires, then
// returns the session without error.
func TestLazyConnectSuccess(t *testing.T) {
	lt := newLazyTunnel()
	sess := newLazyTestSession()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var got tunnel.Session
	var getErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		got, getErr = lt.get(ctx)
	}()

	// Confirm a wake signal was sent before setting the session.
	select {
	case <-lt.wake:
	case <-time.After(time.Second):
		t.Fatal("wake signal not sent within 1s")
	}

	lt.setSession(sess)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("get() did not return after setSession")
	}

	if getErr != nil {
		t.Fatalf("unexpected error: %v", getErr)
	}
	if got != sess {
		t.Fatalf("got wrong session")
	}
}

// TestLazyThunderingHerd: N concurrent get() callers all resolve to the same
// session, and exactly one wake signal is queued (no extra goroutines started).
func TestLazyThunderingHerd(t *testing.T) {
	const n = 10
	lt := newLazyTunnel()
	sess := newLazyTestSession()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var errCount atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := lt.get(ctx)
			if err != nil {
				errCount.Add(1)
				return
			}
			if got != sess {
				errCount.Add(1)
			}
		}()
	}

	// Let all goroutines reach get() and block on ready.
	time.Sleep(50 * time.Millisecond)

	lt.setSession(sess)
	wg.Wait()

	if errCount.Load() != 0 {
		t.Fatalf("%d goroutine(s) got wrong session or error", errCount.Load())
	}

	// Exactly one wake signal should have been queued (1-buffered channel).
	select {
	case <-lt.wake:
		// expected: one signal consumed
	default:
		t.Fatal("expected exactly one wake signal in channel")
	}
	// Channel should now be empty.
	select {
	case <-lt.wake:
		t.Fatal("unexpected second wake signal")
	default:
	}
}

// TestLazyPeerUnreachable: setFailed unblocks all waiters with the error;
// markIdle resets state so the next get() triggers a fresh wake.
func TestLazyPeerUnreachable(t *testing.T) {
	lt := newLazyTunnel()
	dialErr := errors.New("peer unreachable")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, err := lt.get(ctx)
		errCh <- err
	}()

	// Wait for wake signal then simulate failed dial.
	select {
	case <-lt.wake:
	case <-time.After(time.Second):
		t.Fatal("no wake signal")
	}
	lt.setFailed(dialErr)

	select {
	case err := <-errCh:
		if !errors.Is(err, dialErr) {
			t.Fatalf("want %v, got %v", dialErr, err)
		}
	case <-time.After(time.Second):
		t.Fatal("get() did not return after setFailed")
	}

	// After markIdle the next get() must send a fresh wake signal.
	lt.markIdle()
	go func() { lt.get(ctx) }() //nolint:errcheck
	select {
	case <-lt.wake:
	case <-time.After(time.Second):
		t.Fatal("no wake signal after markIdle")
	}
}

// TestLazyIdleWakeup: markIdle → SLEEPING; next get() transitions to WAKING
// and sends on wake again (fresh reconnect cycle).
func TestLazyIdleWakeup(t *testing.T) {
	lt := newLazyTunnel()
	sess := newLazyTestSession()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// First cycle: connect → idle.
	go func() { lt.get(ctx) }() //nolint:errcheck
	<-lt.wake
	lt.setSession(sess)
	lt.markIdle()

	// Second cycle: a new get() must trigger another wake.
	done := make(chan struct{})
	go func() {
		defer close(done)
		lt.get(ctx) //nolint:errcheck
	}()

	select {
	case <-lt.wake:
	case <-time.After(time.Second):
		t.Fatal("no wake signal after second markIdle cycle")
	}
	lt.setSession(newLazyTestSession()) // satisfy the second waiter
	<-done
}

// TestLazyContextCancel: ctx cancel while WAKING unblocks all waiters with
// ctx.Err(), not a nil session.
func TestLazyContextCancel(t *testing.T) {
	lt := newLazyTunnel()

	ctx, cancel := context.WithCancel(context.Background())

	const n = 5
	var wg sync.WaitGroup
	var cancelCount atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := lt.get(ctx)
			if errors.Is(err, context.Canceled) {
				cancelCount.Add(1)
			}
		}()
	}

	// Let all goroutines reach get() and queue up on ready.
	time.Sleep(50 * time.Millisecond)
	cancel()
	wg.Wait()

	if int(cancelCount.Load()) != n {
		t.Fatalf("want %d context-cancelled returns, got %d", n, cancelCount.Load())
	}
}
