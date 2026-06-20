package role

import (
	"context"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/tzero78/buddynet/internal/tunnel"
	"github.com/tzero78/buddynet/internal/vip"
)

// maxConcurrentStreams bounds how many local connections we forward at once, so
// a busy or runaway local client can't spawn unbounded streams/goroutines.
const maxConcurrentStreams = 256

// forward runs the data plane over an established session: -L opens a stream per
// local connection; --vip-listen does the same but on the partner's virtual IP
// bound on lo (per-buddy routing); -forward dials a local service for each
// incoming stream. Any combination can run at once. It returns the number of
// streams forwarded (for the session summary the caller logs) when the session
// ends or ctx is cancelled. vipAddr is the partner's VIP (invalid = no VIP
// route); vipPort is the port to listen on it.
func forward(ctx context.Context, sess tunnel.Session, localListen, forwardTo string, vipAddr netip.Addr, vipPort string) (streams int64, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var count atomic.Int64
	var wg sync.WaitGroup
	if localListen != "" {
		wg.Add(1)
		go func() { defer wg.Done(); serveLocal(ctx, sess, localListen, &count) }()
	}
	if vipPort != "" && vipAddr.IsValid() {
		wg.Add(1)
		go func() { defer wg.Done(); serveVIP(ctx, sess, vipAddr, vipPort, &count) }()
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
	log.Printf("-L: listening on %s, forwarding to peer", addr)
	acceptAndForward(ctx, sess, ln, count)
}

// serveVIP binds the partner's virtual IP on the loopback interface and forwards
// connections to vipAddr:port over the tunnel — the Phase-1 per-buddy routing
// path (name.buddy:port → this buddy's tunnel). Adding the address needs
// NET_ADMIN; when it is missing we log a WARNING and serve nothing, leaving the
// tunnel itself working (graceful degradation, like the DNS bind). The VIP is
// removed again when the session ends.
func serveVIP(ctx context.Context, sess tunnel.Session, vipAddr netip.Addr, port string, count *atomic.Int64) {
	release, err := vip.Assign(vipAddr)
	if err != nil {
		log.Printf("WARNING: --vip-listen disabled for %s — cannot bind it on lo (need NET_ADMIN/root): %v", vipAddr, err)
		return
	}
	defer release()

	addr := net.JoinHostPort(vipAddr.String(), port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("--vip-listen %s: %v", addr, err)
		return
	}
	defer ln.Close()
	log.Printf("--vip-listen: listening on %s, forwarding to this buddy's tunnel", addr)
	acceptAndForward(ctx, sess, ln, count)
}

// acceptAndForward is the shared -L/--vip-listen accept loop: it opens one tunnel
// stream per accepted connection and splices them, bounded by maxConcurrentStreams.
func acceptAndForward(ctx context.Context, sess tunnel.Session, ln net.Listener, count *atomic.Int64) {
	go func() { <-ctx.Done(); ln.Close() }()
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
