package tunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

// TestQUICRejectsMITM verifies that dialing with the wrong partner key fails at
// the TLS handshake. This regression test keeps InsecureSkipVerify: true coupled
// to VerifyPeerCertificate — removing the callback would silently bypass all peer
// authentication without any compiler or linter warning.
func TestQUICRejectsMITM(t *testing.T) {
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, cliPriv, _ := ed25519.GenerateKey(rand.Reader)
	cliPub := cliPriv.Public().(ed25519.PublicKey)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)

	srvConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	srv := NewQUIC(srvConn, srvPriv, cliPub, 5*time.Second)

	cliConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	// Client pins wrongPub — VerifyPeerCertificate must reject the server's real cert.
	cli := NewQUIC(cliConn, cliPriv, wrongPub, 5*time.Second)

	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Listen(ctx) //nolint:errcheck // fails when client aborts; expected
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := cli.Dial(ctx, srvConn.LocalAddr().String()); err == nil {
		t.Error("QUIC dial with wrong partner key succeeded; VerifyPeerCertificate must reject this")
	}

	// Wait for the server goroutine before closing transports to avoid a race on srv.ln.
	<-srvDone
	cli.Close()
	srv.Close()
	cliConn.Close()
	srvConn.Close()
}

// A control client and server exchange a request/response over QUIC, and the
// client's Close leaves its UDP socket usable afterwards (the property the buddy
// relies on to then hole-punch on the same socket).
func TestControlRoundtripAndSocketReuse(t *testing.T) {
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	srvPub := srvPriv.Public().(ed25519.PublicKey)

	srvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer srvConn.Close()
	srv, err := ListenControl(srvConn, srvPriv, 30*time.Second)
	if err != nil {
		t.Fatalf("ListenControl: %v", err)
	}
	defer srv.Close()

	// Echo server: prepend "ok:" to whatever it receives.
	go func() {
		for {
			req, err := srv.Accept(context.Background())
			if err != nil {
				return
			}
			req.Reply(append([]byte("ok:"), req.Payload...))
		}
	}()

	cliConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer cliConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cli, err := DialControl(ctx, cliConn, srvConn.LocalAddr().(*net.UDPAddr), srvPub, 30*time.Second)
	if err != nil {
		t.Fatalf("DialControl: %v", err)
	}
	resp, err := cli.Roundtrip(ctx, []byte("ping"))
	if err != nil {
		t.Fatalf("Roundtrip: %v", err)
	}
	if !bytes.Equal(resp, []byte("ok:ping")) {
		t.Fatalf("got %q, want %q", resp, "ok:ping")
	}
	if err := cli.Close(); err != nil {
		t.Fatalf("client Close: %v", err)
	}

	// The socket must still be usable for raw I/O after the control transport
	// closed — this is what lets the buddy reuse it to hole-punch.
	if _, err := cliConn.WriteToUDP([]byte("raw"), srvConn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("socket not reusable after control Close: %v", err)
	}
	cliConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	cliConn.ReadFromUDP(make([]byte, 64)) // best-effort; must not panic on a live socket
}

// A client pinning the wrong server key must fail the handshake.
func TestControlRejectsWrongServerKey(t *testing.T) {
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)

	srvConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer srvConn.Close()
	srv, err := ListenControl(srvConn, srvPriv, 30*time.Second)
	if err != nil {
		t.Fatalf("ListenControl: %v", err)
	}
	defer srv.Close()

	cliConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer cliConn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := DialControl(ctx, cliConn, srvConn.LocalAddr().(*net.UDPAddr), wrongPub, 30*time.Second); err == nil {
		t.Fatal("dial succeeded against a mismatched server key; want failure")
	}
}
