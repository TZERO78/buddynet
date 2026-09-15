package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// These tests pin the pre-handshake boundary of the control plane (2026-09-15
// audit, BN-04): a source the server will not serve — outside --allow-cidr or
// past the connection caps — is refused by quic-go's per-connection hook, before
// the TLS handshake. The observable consequences, which is what is asserted:
//
//   - the client sees a bare CONNECTION_REFUSED transport error, not an
//     application close after a handshake;
//   - the client's VerifyPeerCertificate is never invoked, i.e. the server's
//     identity certificate was never sent;
//   - and the slot a refused or failed connection would have held is not held.

// probeDial dials the control ALPN with a full client identity and reports
// whether the server's certificate reached the client.
func probeDial(t *testing.T, server *net.UDPAddr, srvPub ed25519.PublicKey) (*quic.Conn, bool, error) {
	t.Helper()
	cliConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	t.Cleanup(func() { cliConn.Close() })
	tr := &quic.Transport{Conn: cliConn}
	t.Cleanup(func() { tr.Close() })
	_, cliPriv, _ := ed25519.GenerateKey(rand.Reader)
	var sawCert atomic.Bool
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qc, err := tr.Dial(ctx, server, &tls.Config{
		InsecureSkipVerify: true, //nosec G402 -- pinned below, as in DialControl
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{controlALPN},
		Certificates:       []tls.Certificate{selfSignedCert(cliPriv)},
		VerifyPeerCertificate: func(raw [][]byte, chains [][]*x509.Certificate) error {
			sawCert.Store(true)
			return pinnedPeerVerify(srvPub)(raw, chains)
		},
		SessionTicketsDisabled: true,
	}, controlQUICConf(30*time.Second, true))
	return qc, sawCert.Load(), err
}

// wantRefusedBeforeTLS asserts the exact shape of a pre-handshake refusal.
func wantRefusedBeforeTLS(t *testing.T, what string, sawCert bool, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: dial succeeded, want a refusal", what)
	}
	if sawCert {
		t.Fatalf("%s: the server sent its identity certificate before refusing — the check ran after TLS", what)
	}
	var te *quic.TransportError
	if !errors.As(err, &te) || te.ErrorCode != quic.ConnectionRefused || !te.Remote {
		t.Fatalf("%s: got %T %v, want a remote CONNECTION_REFUSED", what, err, err)
	}
}

func heldSlots(s *ControlServer) (int, int) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return s.conns, len(s.perIP)
}

func waitForSlots(t *testing.T, s *ControlServer, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if n, _ := heldSlots(s); n == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	n, entries := heldSlots(s)
	t.Fatalf("server holds %d slots (%d source entries), want %d", n, entries, want)
}

// A source outside --allow-cidr gets no handshake: no certificate, no slot, a
// bare transport refusal.
func TestDisallowedSourceIsRefusedBeforeTLS(t *testing.T) {
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	srvPub := srvPriv.Public().(ed25519.PublicKey)
	srvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srvConn.Close()
	srv, err := ListenControl(srvConn, srvPriv, 30*time.Second, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	if err != nil {
		t.Fatalf("ListenControl: %v", err)
	}
	defer srv.Close()

	qc, sawCert, err := probeDial(t, srvConn.LocalAddr().(*net.UDPAddr), srvPub)
	if qc != nil {
		defer qc.CloseWithError(0, "")
	}
	wantRefusedBeforeTLS(t, "disallowed source", sawCert, err)
	if n, entries := heldSlots(srv); n != 0 || entries != 0 {
		t.Fatalf("a refused source holds %d slots (%d entries)", n, entries)
	}
}

// The per-source cap is applied before the handshake, and a held slot comes back
// when its connection closes — so the cap bounds handshakes in flight, not just
// connections that completed one.
func TestConnectionCapIsEnforcedBeforeTLS(t *testing.T) {
	srv, srvAddr, srvPub := controlTestServer(t)
	defer srv.Close()

	clients := openConns(t, srvAddr, srvPub, maxCtrlConnsPerIP)
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()
	waitForSlots(t, srv, maxCtrlConnsPerIP)

	qc, sawCert, err := probeDial(t, srvAddr, srvPub)
	if qc != nil {
		defer qc.CloseWithError(0, "")
	}
	wantRefusedBeforeTLS(t, "connection past the per-source cap", sawCert, err)

	// Free one slot; the next dial must complete a handshake again. This is the
	// release path that runs off the connection context, not the accept loop.
	clients[0].Close()
	clients = clients[1:]
	waitForSlots(t, srv, maxCtrlConnsPerIP-1)
	qc2, sawCert2, err := probeDial(t, srvAddr, srvPub)
	if err != nil {
		t.Fatalf("dial after a slot was freed: %v", err)
	}
	defer qc2.CloseWithError(0, "")
	if !sawCert2 {
		t.Fatal("a served connection never saw the server certificate")
	}
}

// A connection that passes the gate but fails its TLS handshake (here: no client
// certificate, which the server requires) must give its slot back — the slot is
// tied to the connection's lifetime, not to the accept loop ever seeing it.
func TestHandshakeFailureReleasesSlot(t *testing.T) {
	srv, srvAddr, srvPub := controlTestServer(t)
	defer srv.Close()

	cliConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cliConn.Close()
	tr := &quic.Transport{Conn: cliConn}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qc, err := tr.Dial(ctx, srvAddr, &tls.Config{
		InsecureSkipVerify:    true, //nosec G402 -- pinned below, as in DialControl
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{controlALPN},
		VerifyPeerCertificate: pinnedPeerVerify(srvPub),
	}, controlQUICConf(30*time.Second, true))
	if err == nil {
		qc.CloseWithError(0, "")
	}
	waitForSlots(t, srv, 0)
}
