package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/tzero78/buddynet/internal/safe"
)

// This file is the optional QUIC transport for the handshake CONTROL plane (the
// REGISTER / PEER_LIST exchange), an alternative to plain UDP. Its only purpose
// is source-address validation: QUIC completes a cryptographic round-trip before
// the server does any work, so an IP-spoofed sender cannot make the server
// reflect a PEER_LIST. (The plain-UDP transport gets the same property from an
// application-layer cookie; this is the heavier, dependency-reusing option.)
//
// Crucially, a ControlClient runs on the buddy's SHARED UDP socket and its
// Close() leaves that socket open — quic-go does not close a user-supplied Conn
// (see quic.Transport.Close) — so the very same socket then hole-punches and
// carries the peer tunnel, preserving the NAT mapping the server observed.

// controlALPN is the QUIC application protocol for the control plane, distinct
// from the data-plane ALPN so the two can never be confused.
const controlALPN = "buddynet-ctrl/1"

const (
	maxControlReq  = 8192  // bound on a REGISTER read by the server
	maxControlResp = 65536 // bound on a PEER_LIST read by the client
	maxCtrlStreams = 16    // concurrent control streams a peer may open
	maxCtrlConns   = 256   // concurrent QUIC control connections the server services
)

// pinnedPeerVerify returns a TLS VerifyPeerCertificate that accepts the peer
// only if its certificate carries exactly want — the same key-pinning used by
// the data plane, with no CA or hostname.
func pinnedPeerVerify(want ed25519.PublicKey) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("peer presented no certificate")
		}
		c, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		pk, ok := c.PublicKey.(ed25519.PublicKey)
		if !ok || !pk.Equal(want) {
			return errors.New("peer identity does not match the expected key (possible MITM)")
		}
		return nil
	}
}

// clientKeyVerify returns a TLS VerifyPeerCertificate (server side) that extracts
// the client's Ed25519 identity from its certificate and defers the accept/reject
// decision to allow. It lets the handshake server pin CLIENTS to its allowlist
// during the TLS handshake — so a non-allowlisted buddy is refused before it can
// send a REGISTER (the same early rejection kernel WireGuard gives), not merely at
// the app layer afterwards. Used only in approval mode; open mode passes nil.
func clientKeyVerify(allow func(ed25519.PublicKey) error) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("client presented no certificate")
		}
		c, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		pk, ok := c.PublicKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("client certificate is not an Ed25519 identity")
		}
		return allow(pk)
	}
}

func controlQUICConf(idle time.Duration) *quic.Config {
	ka := idle / 4
	if ka < 5*time.Second {
		ka = 5 * time.Second
	}
	return &quic.Config{
		MaxIdleTimeout:       idle,
		KeepAlivePeriod:      ka,
		HandshakeIdleTimeout: 10 * time.Second,
		MaxIncomingStreams:   maxCtrlStreams,
	}
}

// ControlClient is a buddy's QUIC control connection to the handshake server.
type ControlClient struct {
	tr   *quic.Transport
	conn *quic.Conn
}

// DialControl opens a QUIC control connection to server over conn, pinning the
// server's identity key. It presents the buddy's own identity certificate so a
// server in approval mode can pin the client to its allowlist during the TLS
// handshake. On error it cleans up and leaves conn open.
func DialControl(ctx context.Context, conn *net.UDPConn, server *net.UDPAddr, serverPub ed25519.PublicKey, priv ed25519.PrivateKey, idle time.Duration) (*ControlClient, error) {
	tr := &quic.Transport{Conn: conn}
	tlsConf := &tls.Config{
		// PKI-free: identity is pinned by key in VerifyPeerCertificate below, not by
		// CA/hostname. Dropping that callback would remove all authentication.
		InsecureSkipVerify:    true, //nosec G402 -- server identity is pinned by key in VerifyPeerCertificate
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{controlALPN},
		Certificates:          []tls.Certificate{selfSignedCert(priv)}, // our identity, for server-side client pinning
		VerifyPeerCertificate: pinnedPeerVerify(serverPub),
	}
	qc, err := tr.Dial(ctx, server, tlsConf, controlQUICConf(idle))
	if err != nil {
		tr.Close()
		return nil, err
	}
	return &ControlClient{tr: tr, conn: qc}, nil
}

// Roundtrip opens a stream, sends req, half-closes the send side, and returns
// the full reply the server writes before closing its end.
func (c *ControlClient) Roundtrip(ctx context.Context, req []byte) ([]byte, error) {
	st, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer st.CancelRead(0)
	if _, err := st.Write(req); err != nil {
		return nil, err
	}
	st.Close() // half-close: signals end of request, read side stays open
	return io.ReadAll(io.LimitReader(st, maxControlResp))
}

// Close tears down the QUIC connection and transport but LEAVES the underlying
// UDP socket open, so the caller can reuse it for hole punching and the peer
// tunnel.
func (c *ControlClient) Close() error {
	c.conn.CloseWithError(0, "bye")
	return c.tr.Close()
}

// ControlRequest is one received REGISTER awaiting a reply.
type ControlRequest struct {
	Remote  net.Addr
	Payload []byte
	st      *quic.Stream
}

// Reply writes b as the response and closes the stream. A parked registration
// replies with an empty PEER_LIST so the client's Roundtrip returns and retries.
func (r *ControlRequest) Reply(b []byte) error {
	_, err := r.st.Write(b)
	r.st.Close()
	return err
}

// ControlServer is the handshake server's QUIC control listener.
type ControlServer struct {
	tr        *quic.Transport
	ln        *quic.Listener
	reqs      chan *ControlRequest
	done      chan struct{}
	closeOnce sync.Once
}

// ListenControl starts a QUIC control listener on conn, presenting the server's
// identity certificate. conn is owned by the caller; Close leaves it open.
//
// verifyClient pins CLIENTS by key during the TLS handshake (approval mode): a
// non-nil callback requires every client to present a certificate whose Ed25519
// key it accepts, so a non-allowlisted buddy is refused before sending a REGISTER.
// Pass nil in open mode — any client may connect and is gated at the app layer.
func ListenControl(conn *net.UDPConn, priv ed25519.PrivateKey, idle time.Duration, verifyClient func(ed25519.PublicKey) error) (*ControlServer, error) {
	tr := &quic.Transport{Conn: conn}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(priv)},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{controlALPN},
		ClientAuth:   tls.NoClientCert, // open mode: clients gated at the app layer
	}
	if verifyClient != nil {
		// Approval mode: demand and pin a client certificate at the TLS layer.
		tlsConf.ClientAuth = tls.RequireAnyClientCert
		tlsConf.VerifyPeerCertificate = clientKeyVerify(verifyClient)
	}
	ln, err := tr.Listen(tlsConf, controlQUICConf(idle))
	if err != nil {
		tr.Close()
		return nil, err
	}
	s := &ControlServer{tr: tr, ln: ln, reqs: make(chan *ControlRequest), done: make(chan struct{})}
	go s.acceptConns()
	return s, nil
}

func (s *ControlServer) acceptConns() {
	// Cap concurrent connections so a flood of (source-validated) QUIC dials
	// cannot grow goroutines/memory without bound. The per-stream rate limiter
	// gates work inside a connection; this bounds the number of connections.
	sem := make(chan struct{}, maxCtrlConns)
	for {
		qc, err := s.ln.Accept(context.Background())
		if err != nil {
			return // listener closed
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				s.acceptStreams(qc)
			}()
		default:
			qc.CloseWithError(0, "server at capacity") // shed load instead of queuing unboundedly
		}
	}
}

func (s *ControlServer) acceptStreams(qc *quic.Conn) {
	for {
		st, err := qc.AcceptStream(context.Background())
		if err != nil {
			return // connection closed
		}
		safe.Go("control.read", func() { s.readRequest(qc, st) })
	}
}

func (s *ControlServer) readRequest(qc *quic.Conn, st *quic.Stream) {
	payload, err := io.ReadAll(io.LimitReader(st, maxControlReq))
	if err != nil {
		st.Close()
		return
	}
	req := &ControlRequest{Remote: qc.RemoteAddr(), Payload: payload, st: st}
	select {
	case s.reqs <- req:
	case <-s.done:
		st.Close()
	}
}

// Accept returns the next control request, or an error if ctx is done or the
// server is closed.
func (s *ControlServer) Accept(ctx context.Context) (*ControlRequest, error) {
	select {
	case r := <-s.reqs:
		return r, nil
	case <-s.done:
		return nil, errors.New("control server closed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close stops the listener and transport (leaving the UDP socket open). Safe to
// call concurrently and more than once: the select/default check-then-close was a
// race (two callers could both pass the default and double-close s.done, panicking
// "close of closed channel"); a sync.Once makes the shutdown idempotent.
func (s *ControlServer) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.ln.Close()
		_ = s.tr.Close()
	})
	return nil
}
