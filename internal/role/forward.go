package role

import (
	"context"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/tzero78/buddynet/internal/tunnel"
)

// maxConcurrentStreams bounds how many local connections we forward at once, so
// a busy or runaway local client can't spawn unbounded streams/goroutines.
const maxConcurrentStreams = 256

// forward runs the data plane over an established session: -L opens a stream per
// local connection; -forward dials a local service for each incoming stream.
// Both can run at once. It returns the number of streams forwarded (for the
// session summary the caller logs) when the session ends or ctx is cancelled.
func forward(ctx context.Context, sess tunnel.Session, localListen, forwardTo string) (streams int64, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var count atomic.Int64
	var wg sync.WaitGroup
	if localListen != "" {
		wg.Add(1)
		go func() { defer wg.Done(); serveLocal(ctx, sess, localListen, &count) }()
	}
	if forwardTo != "" {
		wg.Add(1)
		go func() { defer wg.Done(); serveStreams(ctx, sess, forwardTo, &count) }()
	}

	select {
	case <-sess.Done():
		// Tunnel closed (peer/idle/reauth) — the caller logs DISCONNECTED with the
		// reason and duration; nothing to log here.
	case <-ctx.Done():
		log.Print("shutting down")
		sess.Close()
	}
	cancel()
	wg.Wait()
	return count.Load(), nil
}

// serveLocal accepts local connections and forwards each over a new stream.
func serveLocal(ctx context.Context, sess tunnel.Session, addr string, count *atomic.Int64) {
	ln, err := listenLocal(addr)
	if err != nil {
		log.Printf("-L %s: %v", addr, err)
		return
	}
	defer ln.Close()
	go func() { <-ctx.Done(); ln.Close() }()
	log.Printf("-L: listening on %s, forwarding to peer", addr)
	sem := make(chan struct{}, maxConcurrentStreams)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		sem <- struct{}{} // backpressure on Accept when full
		go func() {
			defer func() { <-sem }()
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

// serveStreams accepts incoming streams and forwards each to the local service.
func serveStreams(ctx context.Context, sess tunnel.Session, addr string, count *atomic.Int64) {
	log.Printf("-forward: incoming streams go to %s", addr)
	for {
		st, err := sess.AcceptStream(ctx)
		if err != nil {
			return
		}
		count.Add(1)
		go func() {
			c, err := dialLocal(addr)
			if err != nil {
				log.Printf("-forward dial %s: %v (closing peer stream)", addr, err)
				st.Close()
				return
			}
			splice(c, st)
		}()
	}
}

// splice copies bidirectionally between a local connection and a tunnel stream.
// On EOF in one direction it HALF-closes the other side so a response still in
// flight the reverse way can finish draining — what request/response tools like
// rsync rely on after they half-close.
func splice(local net.Conn, st tunnel.Stream) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(st, local)
		st.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		io.Copy(local, st)
		if cw, ok := local.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			local.Close()
		}
	}()
	wg.Wait()
	local.Close()
	st.Close()
}

// localNetwork interprets a -L/-forward address: a "unix:" prefix or absolute
// path selects a Unix domain socket (file-permission gated); otherwise TCP.
func localNetwork(addr string) (network, address string) {
	if s, ok := strings.CutPrefix(addr, "unix:"); ok {
		return "unix", s
	}
	if strings.HasPrefix(addr, "/") {
		return "unix", addr
	}
	return "tcp", addr
}

// listenLocal listens on a -L address; unix sockets are created 0600 (a stale
// socket from an unclean exit is removed first).
func listenLocal(addr string) (net.Listener, error) {
	network, address := localNetwork(addr)
	if network == "unix" {
		_ = os.Remove(address)
	}
	ln, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	if network == "unix" {
		if err := os.Chmod(address, 0o600); err != nil {
			ln.Close()
			return nil, err
		}
	}
	return ln, nil
}

// dialLocal dials a -forward target (TCP or unix socket).
func dialLocal(addr string) (net.Conn, error) {
	network, address := localNetwork(addr)
	return net.Dial(network, address)
}
