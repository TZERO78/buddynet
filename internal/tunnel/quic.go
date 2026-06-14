package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// ALPN is the QUIC application protocol identifier for BuddyNet v1.
const ALPN = "buddynet/1"

// maxConcurrentStreams bounds how many streams a peer may open on us at once, so
// a busy or runaway peer cannot spawn unbounded goroutines/streams.
const maxConcurrentStreams = 256

// QUICTransport is the v1 Transport: a QUIC connection (TLS 1.3, reliable,
// ordered, multiplexed) over a single dual-stack UDP socket. Reusing the socket
// that was already used to hole-punch is what preserves the NAT mapping, so the
// transport is constructed from the punched *net.UDPConn rather than opening its
// own. Identity is the node's Ed25519 key; the peer is pinned by public key.
type QUICTransport struct {
	conn    *net.UDPConn
	tr      *quic.Transport
	tlsConf *tls.Config
	qconf   *quic.Config
	ln      *quic.Listener // created once; reused across fallback attempts
}

// NewQUIC builds a QUIC transport over an already-open (typically punched) UDP
// socket. priv is this node's identity (and TLS cert key); partnerPub is the
// peer's pinned public key — the TLS handshake is required to present exactly
// it, so a man in the middle cannot impersonate the peer. idleTimeout tears the
// session down after a stretch with no traffic at all; keepalive is derived as a
// quarter of it so an active transfer never times out.
func NewQUIC(conn *net.UDPConn, priv ed25519.PrivateKey, partnerPub ed25519.PublicKey, idleTimeout time.Duration) *QUICTransport {
	keepAlive := idleTimeout / 4
	if keepAlive < 5*time.Second {
		keepAlive = 5 * time.Second
	}
	return &QUICTransport{
		conn:    conn,
		tr:      &quic.Transport{Conn: conn},
		tlsConf: tlsConfig(priv, partnerPub),
		qconf: &quic.Config{
			MaxIdleTimeout:       idleTimeout,
			KeepAlivePeriod:      keepAlive,
			HandshakeIdleTimeout: 10 * time.Second,
			MaxIncomingStreams:   maxConcurrentStreams,
		},
	}
}

// Listen takes the QUIC server role: it accepts the next session a peer dials.
// The listener is created once and reused, so a buddy can Accept across several
// fallback attempts on the same socket (direct, then via a relay) without
// re-binding it.
func (t *QUICTransport) Listen(ctx context.Context) (Session, error) {
	if t.ln == nil {
		ln, err := t.tr.Listen(t.tlsConf, t.qconf)
		if err != nil {
			return nil, err
		}
		t.ln = ln
	}
	qc, err := t.ln.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &quicSession{conn: qc}, nil
}

// Dial takes the QUIC client role: it connects to the peer's punched endpoint.
func (t *QUICTransport) Dial(ctx context.Context, endpoint string) (Session, error) {
	addr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, err
	}
	qc, err := t.tr.Dial(ctx, addr, t.tlsConf, t.qconf)
	if err != nil {
		return nil, err
	}
	return &quicSession{conn: qc}, nil
}

// Close releases the QUIC transport and its listener (but not the underlying UDP
// socket, which the caller owns and may still need).
func (t *QUICTransport) Close() error {
	if t.ln != nil {
		t.ln.Close()
	}
	return t.tr.Close()
}

// quicSession adapts a *quic.Conn to the Session interface.
type quicSession struct {
	conn *quic.Conn
}

func (s *quicSession) OpenStream(ctx context.Context) (Stream, error) {
	st, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return quicStream{st}, nil
}

func (s *quicSession) AcceptStream(ctx context.Context) (Stream, error) {
	st, err := s.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return quicStream{st}, nil
}

func (s *quicSession) RemoteAddr() net.Addr  { return s.conn.RemoteAddr() }
func (s *quicSession) Done() <-chan struct{} { return s.conn.Context().Done() }

func (s *quicSession) Close() error {
	return s.conn.CloseWithError(0, "bye")
}

// quicStream adapts *quic.Stream to Stream. A QUIC stream's Close already
// half-closes only the send side, which is exactly CloseWrite's contract; the
// receive side keeps draining until the peer closes its end.
type quicStream struct{ st *quic.Stream }

func (q quicStream) Read(p []byte) (int, error)  { return q.st.Read(p) }
func (q quicStream) Write(p []byte) (int, error) { return q.st.Write(p) }
func (q quicStream) CloseWrite() error           { return q.st.Close() }

// Close tears the stream down in both directions.
func (q quicStream) Close() error {
	q.st.CancelRead(0)
	return q.st.Close()
}

// tlsConfig pins the partner: both sides present an Ed25519 self-signed cert and
// require the peer's cert to carry exactly the expected public key. This is NOT
// a CA/hostname PKI — there is no authority and no hostname — so the default
// chain/expiry/name checks are disabled and identity is enforced by key in
// VerifyPeerCertificate. InsecureSkipVerify therefore only turns off checks that
// are meaningless here; it does not weaken authentication.
func tlsConfig(priv ed25519.PrivateKey, partnerPub ed25519.PublicKey) *tls.Config {
	return &tls.Config{
		Certificates:       []tls.Certificate{selfSignedCert(priv)},
		ClientAuth:         tls.RequireAnyClientCert,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{ALPN},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("peer presented no certificate")
			}
			c, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			pk, ok := c.PublicKey.(ed25519.PublicKey)
			if !ok || !pk.Equal(partnerPub) {
				return errors.New("peer identity does not match the expected key (possible MITM)")
			}
			return nil
		},
	}
}

func selfSignedCert(priv ed25519.PrivateKey) tls.Certificate {
	// With InsecureSkipVerify the TLS stack never checks expiry, and we
	// authenticate by the cert's public key, not its dates; a long NotAfter just
	// avoids confusing anyone who inspects the cert.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "buddynet"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(100 * 365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		panic(err) // only fails on a broken key, which we just generated/loaded
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}
