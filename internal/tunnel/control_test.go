package tunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
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
	_, cliPriv, _ := ed25519.GenerateKey(rand.Reader)
	cli, err := DialControl(ctx, cliConn, srvConn.LocalAddr().(*net.UDPAddr), srvPub, cliPriv, 30*time.Second)
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
	_, cliPriv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := DialControl(ctx, cliConn, srvConn.LocalAddr().(*net.UDPAddr), wrongPub, cliPriv, 30*time.Second); err == nil {
		t.Fatal("dial succeeded against a mismatched server key; want failure")
	}
}

// The control server AUTHENTICATES every client by key at the TLS handshake and
// reports the authenticated identity to the application layer — but it authorizes
// nobody there. An unknown key must be able to complete the handshake, otherwise
// a client enrolling with a code could never deliver it (the app layer is what
// then allows, enrols or refuses it).
func TestControlReportsAuthenticatedClientKey(t *testing.T) {
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	srvPub := srvPriv.Public().(ed25519.PublicKey)

	srvConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer srvConn.Close()
	srv, err := ListenControl(srvConn, srvPriv, 30*time.Second)
	if err != nil {
		t.Fatalf("ListenControl: %v", err)
	}
	defer srv.Close()
	seen := make(chan ed25519.PublicKey, 4)
	go func() {
		for {
			req, err := srv.Accept(context.Background())
			if err != nil {
				return
			}
			seen <- req.ClientKey
			req.Reply([]byte("ok"))
		}
	}()
	srvAddr := srvConn.LocalAddr().(*net.UDPAddr)

	// A client the server has never heard of: the handshake completes and its
	// identity is handed up, so an enrollment code could reach the app layer.
	strangerPub, strangerPriv, _ := ed25519.GenerateKey(rand.Reader)
	cliConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer cliConn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cli, err := DialControl(ctx, cliConn, srvAddr, srvPub, strangerPriv, 30*time.Second)
	if err != nil {
		t.Fatalf("an unknown client must still be able to connect (enrollment): %v", err)
	}
	defer cli.Close()
	if _, err := cli.Roundtrip(ctx, []byte("hi")); err != nil {
		t.Fatalf("roundtrip failed: %v", err)
	}

	select {
	case got := <-seen:
		if !got.Equal(strangerPub) {
			t.Fatalf("ClientKey = %x, want the key the client authenticated with %x", got, strangerPub)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no request reached the application layer")
	}
}

// A client that presents no certificate at all must be refused at the TLS layer:
// enrollment relaxes AUTHORIZATION, never authentication.
func TestControlRequiresAClientCertificate(t *testing.T) {
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	srvPub := srvPriv.Public().(ed25519.PublicKey)

	srvConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer srvConn.Close()
	srv, err := ListenControl(srvConn, srvPriv, 30*time.Second)
	if err != nil {
		t.Fatalf("ListenControl: %v", err)
	}
	defer srv.Close()
	go func() {
		for {
			req, err := srv.Accept(context.Background())
			if err != nil {
				return
			}
			req.Reply([]byte("ok"))
		}
	}()
	srvAddr := srvConn.LocalAddr().(*net.UDPAddr)

	cliConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer cliConn.Close()
	tr := &quic.Transport{Conn: cliConn}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Same pinning as DialControl, but deliberately WITHOUT a client certificate.
	qc, err := tr.Dial(ctx, srvAddr, &tls.Config{
		InsecureSkipVerify:    true, //nosec G402 -- server identity is pinned below, as in DialControl
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{controlALPN},
		VerifyPeerCertificate: pinnedPeerVerify(srvPub),
	}, controlQUICConf(30*time.Second))
	if err != nil {
		return // refused during the handshake, as intended
	}
	defer qc.CloseWithError(0, "")
	st, err := qc.OpenStreamSync(ctx)
	if err != nil {
		return // refused as soon as the missing certificate is noticed
	}
	if _, err := st.Write([]byte("hi")); err != nil {
		return
	}
	st.Close()
	if b, err := io.ReadAll(io.LimitReader(st, 64)); err == nil && len(b) > 0 {
		t.Fatalf("a client with no certificate was served: %q", b)
	}
}
