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

// peerEd25519FromCerts extracts the peer's Ed25519 identity from the leaf
// certificate of a TLS handshake (PKI-free: the key IS the identity). Shared by
// the server- and client-key pinning verifiers below.
func peerEd25519FromCerts(rawCerts [][]byte) (ed25519.PublicKey, error) {
	if len(rawCerts) == 0 {
		return nil, errors.New("peer presented no certificate")
	}
	c, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return nil, err
	}
	pk, ok := c.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("peer certificate is not an Ed25519 identity")
	}
	return pk, nil
}

// pinnedPeerVerify returns a TLS VerifyPeerCertificate that accepts the peer only
// if its certificate carries exactly want — the same key-pinning used by the data
// plane, with no CA or hostname.
func pinnedPeerVerify(want ed25519.PublicKey) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		pk, err := peerEd25519FromCerts(rawCerts)
		if err != nil {
			return err
		}
		if !pk.Equal(want) {
			return errors.New("peer identity does not match the expected key (possible MITM)")
		}
		return nil
	}
}

// requireEd25519Client is the server-side TLS VerifyPeerCertificate for the
// control plane. It requires a client certificate carrying an Ed25519 key —
// nothing more.
//
// Deliberately NOT an allowlist gate. Refusing unknown keys here made
// code-based enrollment impossible: a client that has never been approved could
// never complete the handshake, so its sealed enrollment code could never reach
// the application layer, so the operator could never approve it. Authorization
// belongs one layer up, where an unknown key WITH a valid code becomes a pending
// enrollment and an unknown key without one is refused (see role.pairRegister).
//
// What this still buys is proof of possession: TLS 1.3 with a required client
// certificate makes the client sign the handshake transcript (CertificateVerify),
// so the key handed to the application layer is one the peer demonstrably holds
// the private half of — not merely one it claimed.
func requireEd25519Client(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	_, err := peerEd25519FromCerts(rawCerts)
	return err
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
	Remote net.Addr
	// ClientKey is the Ed25519 identity the client AUTHENTICATED with in the TLS
	// handshake (it signed the transcript with the matching private key). The
	// handshake server requires REGISTER.PubKey to equal it, so a registration can
	// never claim an identity the connection did not prove.
	ClientKey ed25519.PublicKey
	Payload   []byte
	st        *quic.Stream
	qc        *quic.Conn
}

// Reply writes b as the response and closes the stream. A parked registration
// replies with an empty PEER_LIST so the client's Roundtrip returns and retries.
func (r *ControlRequest) Reply(b []byte) error {
	_, err := r.st.Write(b)
	r.st.Close()
	return err
}

// Drop closes the whole CONNECTION without answering. Used when a request is not
// merely unauthorized but structurally abusive — e.g. a REGISTER claiming a
// public key other than the one the TLS handshake authenticated — so the peer
// does not get to retry on the same connection.
func (r *ControlRequest) Drop(reason string) {
	r.st.CancelRead(0)
	r.st.Close()
	r.qc.CloseWithError(0, reason)
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
// Every client must present an Ed25519 client certificate and prove possession of
// its private key in the TLS handshake. The authenticated key is handed to the
// application layer on each ControlRequest (ClientKey), which is what lets the
// handshake server bind REGISTER.PubKey to the key that actually authenticated —
// and decide, per key, between "allowlisted", "enrolling with a code" and
// "refused". The TLS layer itself makes no authorization decision.
func ListenControl(conn *net.UDPConn, priv ed25519.PrivateKey, idle time.Duration) (*ControlServer, error) {
	tr := &quic.Transport{Conn: conn}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(priv)},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{controlALPN},
		// RequireAnyClientCert + an Ed25519 check: authentication (who holds this
		// key), never authorization (may this key pair) — see requireEd25519Client.
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: requireEd25519Client,
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
	// The authenticated client identity is a property of the CONNECTION, so it is
	// extracted once here and carried on every request from it. ClientAuth is
	// RequireAnyClientCert and VerifyPeerCertificate insists on an Ed25519 leaf, so
	// a connection that got this far always has one; bail out defensively if not,
	// rather than serving requests with an unknown identity.
	clientKey, err := clientKeyOf(qc)
	if err != nil {
		qc.CloseWithError(0, "client identity unavailable")
		return
	}
	for {
		st, err := qc.AcceptStream(context.Background())
		if err != nil {
			return // connection closed
		}
		safe.Go("control.read", func() { s.readRequest(qc, clientKey, st) })
	}
}

// clientKeyOf returns the Ed25519 identity the peer authenticated with.
func clientKeyOf(qc *quic.Conn) (ed25519.PublicKey, error) {
	certs := qc.ConnectionState().TLS.PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("peer presented no certificate")
	}
	pk, ok := certs[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("peer certificate is not an Ed25519 identity")
	}
	return pk, nil
}

func (s *ControlServer) readRequest(qc *quic.Conn, clientKey ed25519.PublicKey, st *quic.Stream) {
	payload, err := io.ReadAll(io.LimitReader(st, maxControlReq))
	if err != nil {
		st.Close()
		return
	}
	req := &ControlRequest{Remote: qc.RemoteAddr(), ClientKey: clientKey, Payload: payload, st: st, qc: qc}
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
