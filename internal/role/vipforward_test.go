//go:build linux

package role

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/tzero78/buddynet/internal/tunnel"
	"github.com/tzero78/buddynet/internal/vip"
)

// pipeStream adapts a net.Pipe end to tunnel.Stream (adds CloseWrite). The test
// keeps both ends open through the assertions, so a no-op CloseWrite is enough.
type pipeStream struct{ net.Conn }

func (p pipeStream) CloseWrite() error { return nil }

// vipPipeSession is a tunnel.Session whose OpenStream hands back one end of a
// net.Pipe; the test drives the other end as the "remote service".
type vipPipeSession struct{ remote chan net.Conn }

func (s vipPipeSession) OpenStream(context.Context) (tunnel.Stream, error) {
	local, remote := net.Pipe()
	s.remote <- remote
	return pipeStream{local}, nil
}
func (vipPipeSession) AcceptStream(context.Context) (tunnel.Stream, error) {
	return nil, errors.New("not used")
}
func (vipPipeSession) RemoteAddr() net.Addr { return nil }
func (vipPipeSession) ExportKeyingMaterial(string, []byte, int) ([]byte, error) {
	return nil, errors.New("not used")
}
func (vipPipeSession) Done() <-chan struct{} { return nil }
func (vipPipeSession) Close() error          { return nil }

// TestServeVIPBindsAndForwards proves the Phase-1 routing path end to end: a
// connection to the partner's VIP bound on lo is accepted and spliced over a
// tunnel stream in both directions. Needs NET_ADMIN; skips without it.
func TestServeVIPBindsAndForwards(t *testing.T) {
	vipAddr := netip.MustParseAddr("10.66.211.178") // overlay range, test-only
	const port = "18080"

	// Pre-flight: can we assign at all? If not (CI/unprivileged), skip cleanly.
	if rel, err := vip.Assign(vipAddr); err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("no NET_ADMIN to bind loopback VIP: %v", err)
		}
		t.Fatalf("pre-flight Assign: %v", err)
	} else {
		rel() // serveVIP re-assigns; we only checked permission
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess := vipPipeSession{remote: make(chan net.Conn, 1)}
	var count atomic.Int64
	done := make(chan struct{})
	go func() { defer close(done); serveVIP(ctx, sess, vipAddr, port, &count) }()

	// Give serveVIP a moment to assign the VIP and start listening.
	addr := net.JoinHostPort(vipAddr.String(), port)
	var client net.Conn
	var derr error
	for i := 0; i < 50; i++ {
		if client, derr = net.DialTimeout("tcp", addr, 200*time.Millisecond); derr == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if derr != nil {
		t.Fatalf("dial %s (VIP not bound/listening?): %v", addr, derr)
	}
	defer client.Close()

	// The "remote service" end of the tunnel stream.
	var service net.Conn
	select {
	case service = <-sess.remote:
	case <-time.After(2 * time.Second):
		t.Fatal("serveVIP never opened a tunnel stream for the connection")
	}
	defer service.Close()

	// Client → tunnel → service.
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := service.Read(buf); err != nil {
		t.Fatalf("service read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("service got %q, want ping", buf)
	}
	// Service → tunnel → client.
	if _, err := service.Write([]byte("pong")); err != nil {
		t.Fatalf("service write: %v", err)
	}
	if _, err := client.Read(buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("client got %q, want pong", buf)
	}

	// Shut down and confirm the VIP was removed from lo (release on teardown).
	cancel()
	<-done
	lo, _ := net.InterfaceByName("lo")
	addrs, _ := lo.Addrs()
	for _, a := range addrs {
		if pfx, ok := a.(*net.IPNet); ok {
			if got, ok := netip.AddrFromSlice(pfx.IP.To4()); ok && got == vipAddr {
				t.Fatalf("VIP %s still on lo after serveVIP returned", vipAddr)
			}
		}
	}
}
