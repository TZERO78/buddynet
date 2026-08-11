package role

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tzero78/buddynet/internal/ratelimit"
	"github.com/tzero78/buddynet/internal/safe"
)

// The plain-UDP REGISTER loop is the path that parses raw internet datagrams, so
// one crafted packet must cost that packet and nothing else. safe.Do around the
// handler is what makes that true, and until now nothing tested it: removing the
// wrapper left the whole suite green (mutation M16 in the audit).
//
// This is deliberately the UDP path, NOT the QUIC one. The QUIC connection
// handler has its own coverage in internal/tunnel, and the missing read deadline
// in ControlClient.Roundtrip — which made an end-to-end QUIC version of this test
// hang — is a separate matter entirely.
func TestUDPRegisterPanicIsContained(t *testing.T) {
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	handled := make(chan string, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = serveRegisterUDP(ctx, srv, ratelimit.New(rlGlobalRate, rlSrcRate, rlMaxSources), nil,
			func(_ *net.UDPAddr, raw []byte) {
				if strings.HasPrefix(string(raw), "BOOM") {
					panic("crafted datagram")
				}
				handled <- string(raw)
			})
	}()
	// Stop the loop before the test returns, and WAIT for it: a goroutine still
	// running after the test would race with the next one over the socket.
	t.Cleanup(func() {
		cancel()
		srv.Close()
		<-done
	})

	cli, err := net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	before := safe.PanicCount()
	if _, err := cli.Write([]byte("BOOM")); err != nil {
		t.Fatal(err)
	}
	if !waitFor(t, 3*time.Second, func() bool { return safe.PanicCount() > before }) {
		t.Fatal("the panic was neither recovered nor counted — safe.Do is not covering the UDP register path")
	}

	// The loop survived: the NEXT datagram is processed normally.
	if _, err := cli.Write([]byte("second-datagram")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-handled:
		if got != "second-datagram" {
			t.Fatalf("handler saw %q, want the follow-up datagram", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the read loop stopped after the panicking datagram")
	}
}

// Negative control: the SAME loop body without safe.Do must take the process
// down. Run in a subprocess, or it would take this test binary with it.
//
// The child runs a local copy of the loop rather than a production flag, so
// nothing in the shipped code can be switched into the unprotected mode.
func TestUDPRegisterPanicKillsAnUnwrappedLoop(t *testing.T) {
	if os.Getenv("BUDDYNET_TEST_UNWRAPPED_UDP_LOOP") == "1" {
		runUnwrappedLoopForTest()
		return // unreachable: the panic above ends the process
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestUDPRegisterPanicKillsAnUnwrappedLoop", "-test.v")
	cmd.Env = append(os.Environ(), "BUDDYNET_TEST_UNWRAPPED_UDP_LOOP=1")
	out, err := cmd.CombinedOutput()

	if err == nil {
		t.Fatalf("the unwrapped loop SURVIVED a panicking datagram — then this test proves nothing "+
			"about safe.Do, because the positive control would pass either way.\nchild output:\n%s", out)
	}
	if !strings.Contains(string(out), "panic: crafted datagram") {
		t.Fatalf("the child died for some other reason than the crafted datagram (%v):\n%s", err, out)
	}
}

// runUnwrappedLoopForTest mirrors serveRegisterUDP WITHOUT its safe.Do, then
// feeds itself one crafted datagram. Only ever reached in the child process of
// the test above.
func runUnwrappedLoopForTest() {
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		os.Exit(2)
	}
	rl := ratelimit.New(rlGlobalRate, rlSrcRate, rlMaxSources)
	var allowed []netip.Prefix
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, rerr := srv.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			if !cidrAllowed(allowed, src.IP) || !rl.Allow(src.IP.String()) {
				continue
			}
			raw := make([]byte, n)
			copy(raw, buf[:n])
			// The one difference from production: no safe.Do.
			if strings.HasPrefix(string(raw), "BOOM") {
				panic("crafted datagram")
			}
		}
	}()

	cli, err := net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		os.Exit(2)
	}
	defer cli.Close()
	if _, err := cli.Write([]byte("BOOM")); err != nil {
		os.Exit(2)
	}
	time.Sleep(5 * time.Second) // give the panic time to reach the runtime
	os.Exit(3)                  // still alive: the negative control did not fire
}
