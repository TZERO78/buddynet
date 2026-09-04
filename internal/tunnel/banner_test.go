package tunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// The certificate is handed to anyone who completes a handshake with the right
// ALPN, so it must not name the product. Pinning compares key bytes only, so an
// empty Subject costs nothing.
func TestCertificateCarriesNoBanner(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := selfSignedCert(priv)
	der := c.Certificate[0]
	if bytes.Contains(bytes.ToLower(der), []byte("buddynet")) {
		t.Fatalf("certificate DER contains the product name")
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s := parsed.Subject.String(); s != "" {
		t.Fatalf("certificate Subject = %q, want empty", s)
	}
	if !parsed.PublicKey.(ed25519.PublicKey).Equal(priv.Public().(ed25519.PublicKey)) {
		t.Fatalf("certificate does not carry the identity key")
	}
}

// remoteClose returns the application-level close the CLIENT observed on its
// control connection, failing the test if the connection was not closed by the
// remote side at all.
func remoteClose(t *testing.T, err error) *quic.ApplicationError {
	t.Helper()
	var ae *quic.ApplicationError
	if !errors.As(err, &ae) {
		t.Fatalf("expected a remote application close, got %T: %v", err, err)
	}
	if !ae.Remote {
		t.Fatalf("close was local, expected remote: %v", err)
	}
	return ae
}

// Every refusal the control server issues closes the connection with the SAME
// code and an EMPTY reason phrase, whatever the cause. A client that completed
// the TLS handshake must not be able to read off which check it failed, nor
// learn from the wording which software it is talking to.
func TestControlCloseReasonIsUniform(t *testing.T) {
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	srvPub := srvPriv.Public().(ed25519.PublicKey)

	// Case 1: the application layer drops requests, each with a different
	// internal reason — the wire must not distinguish them.
	srvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer srvConn.Close()
	srv, err := ListenControl(srvConn, srvPriv, 30*time.Second, nil)
	if err != nil {
		t.Fatalf("ListenControl: %v", err)
	}
	defer srv.Close()
	reasons := []string{"malformed registration", "server at capacity", "sealed pairing token does not open"}
	go func() {
		for i := 0; ; i++ {
			req, err := srv.Accept(context.Background())
			if err != nil {
				return
			}
			req.Drop(reasons[i%len(reasons)])
		}
	}()

	for i := range reasons {
		ae := dialAndGetClosed(t, srvConn.LocalAddr().(*net.UDPAddr), srvPub)
		if ae.ErrorCode != 0 || ae.ErrorMessage != "" {
			t.Fatalf("drop #%d: wire close = code %d reason %q; want code 0 and an empty reason", i, ae.ErrorCode, ae.ErrorMessage)
		}
	}

	// Case 2: a source refused by the allowlist BEFORE it gets a slot must look
	// exactly the same on the wire as an application-layer drop.
	srvConn2, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer srvConn2.Close()
	srv2, err := ListenControl(srvConn2, srvPriv, 30*time.Second, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	if err != nil {
		t.Fatalf("ListenControl: %v", err)
	}
	defer srv2.Close()
	ae := dialAndGetClosed(t, srvConn2.LocalAddr().(*net.UDPAddr), srvPub)
	if ae.ErrorCode != 0 || ae.ErrorMessage != "" {
		t.Fatalf("refused source: wire close = code %d reason %q; want code 0 and an empty reason", ae.ErrorCode, ae.ErrorMessage)
	}
}

// dialAndGetClosed opens a control connection, sends one request and returns the
// remote close the client observed. A refusal is expected on either the request
// itself or a follow-up stream open.
func dialAndGetClosed(t *testing.T, server *net.UDPAddr, srvPub ed25519.PublicKey) *quic.ApplicationError {
	t.Helper()
	cliConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer cliConn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, cliPriv, _ := ed25519.GenerateKey(rand.Reader)
	cli, err := DialControl(ctx, cliConn, server, srvPub, cliPriv, 30*time.Second)
	if err != nil {
		// The refused-source case may already surface here.
		return remoteClose(t, err)
	}
	defer cli.Close()
	if _, err := cli.Roundtrip(ctx, []byte("probe")); err != nil {
		return remoteClose(t, err)
	}
	// The first request may have been answered with a closed stream before the
	// connection close arrived; the next stream open must then fail.
	select {
	case <-cli.conn.Context().Done():
	case <-ctx.Done():
		t.Fatalf("connection was not closed by the server")
	}
	return remoteClose(t, context.Cause(cli.conn.Context()))
}
