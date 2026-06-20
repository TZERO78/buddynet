package relay

import (
	"net"
	"sync"
	"testing"
	"time"
)

// The forwarding hot path must run without the global lock: many concurrent
// forward() calls (Load peer / Store seen) racing a slow-path mutator that flips
// peer under s.mu. The race detector proves the sync.Map + atomic access pattern
// is correct; the test just has to exercise it.
func TestRelayForwardConcurrentLockFree(t *testing.T) {
	s := NewServer(time.Minute, nil, 0, 0)
	conn := mustListen(t)
	defer conn.Close()

	dst := &net.UDPAddr{IP: net.IPv6loopback, Port: 9}
	src := &net.UDPAddr{IP: net.IPv6loopback, Port: 10}
	f := &fwd{}
	f.peer.Store(dst)
	s.byAddr.Store(src.String(), f)

	stop := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pkt := []byte("ciphertext")
			for {
				select {
				case <-stop:
					return
				default:
					s.forward(conn, src, pkt) // lock-free read of peer + atomic seen
				}
			}
		}()
	}

	// Slow-path mutator: bind/reap flip peer under s.mu while forwarders read it.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				s.mu.Lock()
				f.peer.Store(dst)
				f.peer.Store(nil)
				f.peer.Store(dst)
				s.mu.Unlock()
			}
		}
	}()

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
}
