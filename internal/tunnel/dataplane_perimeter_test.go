package tunnel

// Tests for the two perimeter properties of a buddy's DATA-plane QUIC listener,
// the mirror of perimeter_test.go's control-plane pair. Both were missing here
// while the control plane had them:
//
//   - QUIC Retry: an unvalidated (possibly spoofed) source must not get a
//     connection, and with it a full TLS handshake, out of this process.
//   - The listener must not outlive its purpose. A buddy has exactly one
//     partner, so once the session is up the listener is only an open door for
//     strangers — for the whole lifetime of the tunnel, not just its bring-up.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
)

// dataPlanePair builds two QUIC transports on loopback that pin each other.
func dataPlanePair(t *testing.T) (srv, cli *QUICTransport, srvAddr string) {
	t.Helper()
	srvPub, srvPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cliPub, cliPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srvConn, cliConn := listenLoopback(t), listenLoopback(t)
	srv = NewQUIC(srvConn, srvPriv, cliPub, 5*time.Second)
	cli = NewQUIC(cliConn, cliPriv, srvPub, 5*time.Second)
	t.Cleanup(func() { cli.Close(); srv.Close() })
	return srv, cli, srvConn.LocalAddr().String()
}

// TestDataPlaneRequiresSourceValidation pins that Retry is switched on for the
// tunnel socket too. A unit test cannot spoof a source address, so it asserts the
// callback is installed and demands validation for every source.
func TestDataPlaneRequiresSourceValidation(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	tr := NewQUIC(listenLoopback(t), priv, pub, time.Second)
	defer tr.Close()

	if tr.tr.VerifySourceAddress == nil {
		t.Fatal(`the data-plane QUIC transport has no VerifySourceAddress callback.

Without it quic-go builds a connection — and runs the whole TLS handshake — for
any well-formed Initial, including a spoofed one, so a stranger who learns the
punched endpoint can spend this process's CPU and memory at will, and have it
answer forged source addresses while doing so.`)
	}
	for _, addr := range []net.Addr{
		&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1},
		&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1},
	} {
		if !tr.tr.VerifySourceAddress(addr) {
			t.Fatalf("VerifySourceAddress(%v) = false: this source would skip Retry", addr)
		}
	}
}

// TestListenerClosesAfterSuccessfulAccept covers the second property end to end:
// a real handshake (which also proves Retry did not break ordinary bring-up),
// then the listener is gone, the established session still works, and a second
// dial to the same socket no longer gets a connection.
func TestListenerClosesAfterSuccessfulAccept(t *testing.T) {
	srv, cli, addr := dataPlanePair(t)

	type accepted struct {
		sess Session
		err  error
	}
	done := make(chan accepted, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s, err := srv.Listen(ctx)
		done <- accepted{s, err}
	}()

	dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dcancel()
	clientSess, err := cli.Dial(dctx, addr)
	if err != nil {
		t.Fatalf("dial: %v (Retry must not break an ordinary bring-up)", err)
	}
	got := <-done
	if got.err != nil {
		t.Fatalf("listen: %v", got.err)
	}

	if srv.ln != nil {
		t.Fatal("the listener is still open after a session was accepted: a buddy has one partner, so it would answer strangers for the whole life of the tunnel")
	}

	// The accepted session must be unaffected by that close — this is the property
	// the whole fix rests on, so it is exercised, not assumed.
	writeErr := make(chan error, 1)
	go func() {
		st, err := clientSess.OpenStream(context.Background())
		if err != nil {
			writeErr <- err
			return
		}
		if _, err := st.Write([]byte("ping")); err != nil {
			writeErr <- err
			return
		}
		writeErr <- st.CloseWrite()
	}()
	actx, acancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer acancel()
	st, err := got.sess.AcceptStream(actx)
	if err != nil {
		t.Fatalf("the accepted session no longer carries streams after the listener closed: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("client side of the established session: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("read on the established session: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("read %q, want %q", buf, "ping")
	}

	// A fresh dial to the same socket must find nothing listening. Its own
	// transport, so this is a stranger arriving after the tunnel came up.
	_, strangerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stranger := NewQUIC(listenLoopback(t), strangerPriv, strangerPriv.Public().(ed25519.PublicKey), 2*time.Second)
	defer stranger.Close()
	sctx, scancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer scancel()
	if _, err := stranger.Dial(sctx, addr); err == nil {
		t.Fatal("a second dial to the tunnel socket still got a connection: the listener outlived the session")
	}
}

// TestListenerSurvivesFailedAccept guards the other half: the listener is reused
// across the fallback chain (direct, then relay), so a FAILED attempt must leave
// it in place. Closing it there would re-bind — and lose the punched mapping —
// on every fallback step.
func TestListenerSurvivesFailedAccept(t *testing.T) {
	srv, _, _ := dataPlanePair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := srv.Listen(ctx); err == nil {
		t.Fatal("Listen returned a session although nobody dialled")
	}
	if srv.ln == nil {
		t.Fatal("the listener was dropped after a failed attempt: the next path in the fallback chain would have to re-bind the socket")
	}
}
