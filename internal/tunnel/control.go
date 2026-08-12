package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/tzero78/buddynet/internal/netkey"
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
	maxControlReq  = 8192 // bound on a REGISTER read by the server
	maxControlResp = 65536
	maxCtrlStreams = 16  // concurrent control streams a peer may open
	maxCtrlConns   = 256 // concurrent QUIC control connections the server services

	// maxCtrlConnsPerIP bounds concurrent control connections from ONE source
	// address. The global cap alone is not enough: a single source can open
	// connections up to it and lock every other buddy out, and QUIC's source-address
	// validation makes those connections cheap to hold rather than impossible to
	// make. A buddy needs exactly one control connection, so this is generous by an
	// order of magnitude while still leaving 15/16 of the table for everyone else.
	maxCtrlConnsPerIP = 16

	// firstStreamTimeout bounds how long an accepted connection may sit without
	// opening its first stream. A real buddy registers immediately; a connection
	// that completes the handshake and then goes quiet is holding a slot for free.
	firstStreamTimeout = 5 * time.Second

	// controlReadTimeout bounds reading ONE request off a stream, so a peer cannot
	// pin a goroutine (and a stream slot) by dribbling bytes or never half-closing.
	controlReadTimeout = 5 * time.Second

	// rejectLogInterval throttles the "at capacity" line. Refusals happen exactly
	// when something is flooding us, so logging per refusal would let the flood
	// write the disk full — the one line per interval says it is happening, and the
	// suppressed count says how much.
	rejectLogInterval = 30 * time.Second
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

// controlQUICConf builds the control-plane QUIC config. keepalive must be true
// only on the CLIENT: a server that sends keepalives keeps every connection alive
// on its own initiative, including the ones an attacker opened and abandoned, so
// they would never age out of the connection table. With it off, a silent peer
// hits MaxIdleTimeout and the slot is reclaimed; a real buddy's own keepalive (and
// its ~1/s polling) keeps its connection healthy either way.
func controlQUICConf(idle time.Duration, keepalive bool) *quic.Config {
	cfg := &quic.Config{
		MaxIdleTimeout:       idle,
		HandshakeIdleTimeout: 10 * time.Second,
		MaxIncomingStreams:   maxCtrlStreams,
	}
	if keepalive {
		ka := idle / 4
		if ka < 5*time.Second {
			ka = 5 * time.Second
		}
		cfg.KeepAlivePeriod = ka
	}
	return cfg
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
		// No session resumption on the control plane. A resumed session does NOT
		// re-run VerifyPeerCertificate, so identity pinning would be enforced only on
		// the original handshake (gosec G123). A control connection is short-lived and
		// low-volume, so resumption buys nothing worth that caveat.
		SessionTicketsDisabled: true,
	}
	qc, err := tr.Dial(ctx, server, tlsConf, controlQUICConf(idle, true))
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

// Reply writes b as the response and closes the stream in BOTH directions. A
// parked registration replies with an empty PEER_LIST so the client's Roundtrip
// returns and retries.
//
// The receive side is cancelled too: the request has been read in full and
// answered, so anything the peer still sends on this stream is unwanted, and
// leaving the side open lets it hold flow-control credit we will never consume.
func (r *ControlRequest) Reply(b []byte) error {
	_, err := r.st.Write(b)
	r.st.CancelRead(0)
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

	// Connection accounting. connMu guards all four fields so the global and
	// per-source counters can never drift apart: they are taken together in admit
	// and given back together in the release closure, which every exit path runs.
	connMu sync.Mutex
	conns  int
	// handler is the per-connection loop, overridable ONLY by a test that needs to
	// substitute a panicking handler and prove that one crafted connection can take
	// down neither the process nor its slot. It lives on the server (not in a
	// package var) and under connMu because acceptConns reads it from its own
	// goroutine — a plain global would be a data race, and would also leak between
	// tests sharing the binary. nil means the production path.
	handler   func(*ControlServer, *quic.Conn)
	perIP     map[string]int // normalized source IP -> open connections
	rejected  int64          // refusals since the last logged line
	lastLogAt time.Time
}

// connLoop returns the per-connection handler: the test override if one is
// installed, otherwise the production loop.
func (s *ControlServer) connLoop() func(*ControlServer, *quic.Conn) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.handler != nil {
		return s.handler
	}
	return (*ControlServer).acceptStreams
}

// ipKey normalizes a source address to one connection-accounting key: IPv4 per
// exact address, IPv6 per /64, IPv4-mapped IPv6 unmapped onto the IPv4 key, port
// dropped.
//
// The rule itself lives in internal/netkey, NOT here, and every other per-source
// budget in the codebase (the handshake rate limiters, the relay's bind limiter
// and leg cap) calls the same function. Two copies of this logic is exactly how
// finding H-01 happened: this one aggregated to /64 while the relay keyed per
// exact address, so a single /64 bypassed the relay's caps entirely.
func ipKey(a net.Addr) string { return netkey.FromAddr(a) }

// admit reserves a connection slot for a source, returning the release closure.
// The closure is idempotent, so calling it on several exit paths is safe and
// missing it is the only real hazard — hence the single defer at the call site.
func (s *ControlServer) admit(remote net.Addr) (release func(), ok bool) {
	key := ipKey(remote)
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.conns >= maxCtrlConns || s.perIP[key] >= maxCtrlConnsPerIP {
		s.rejected++
		return nil, false
	}
	s.conns++
	s.perIP[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			s.connMu.Lock()
			defer s.connMu.Unlock()
			s.conns--
			if n := s.perIP[key] - 1; n <= 0 {
				delete(s.perIP, key) // keep the map bounded by live connections only
			} else {
				s.perIP[key] = n
			}
		})
	}, true
}

// noteRejection emits at most one "at capacity" line per rejectLogInterval,
// carrying the number of refusals it stands for.
func (s *ControlServer) noteRejection() {
	s.connMu.Lock()
	if time.Since(s.lastLogAt) < rejectLogInterval {
		s.connMu.Unlock()
		return
	}
	n := s.rejected
	s.rejected = 0
	s.lastLogAt = time.Now()
	s.connMu.Unlock()
	log.Printf("SECURITY: event=control-conn-refused count=%d detail=%q", n,
		"control connection limit reached (per-source or global); shedding load")
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
		// No session resumption: a resumed session skips the certificate exchange and
		// does not re-run VerifyPeerCertificate (gosec G123). The authenticated client
		// key is what the whole approval decision hangs on, so it must come from a
		// handshake this connection actually performed, not a restored ticket.
		SessionTicketsDisabled: true,
	}
	ln, err := tr.Listen(tlsConf, controlQUICConf(idle, false))
	if err != nil {
		tr.Close()
		return nil, err
	}
	s := &ControlServer{tr: tr, ln: ln, reqs: make(chan *ControlRequest), done: make(chan struct{}), perIP: map[string]int{}}
	go s.acceptConns()
	return s, nil
}

func (s *ControlServer) acceptConns() {
	// Cap concurrent connections globally AND per source, so neither a broad flood
	// of (source-validated) QUIC dials nor one host opening connection after
	// connection can grow goroutines/memory or lock other buddies out. The rate
	// limiter one layer up gates work INSIDE a connection; this bounds how many
	// connections exist at all.
	for {
		qc, err := s.ln.Accept(context.Background())
		if err != nil {
			return // listener closed
		}
		release, ok := s.admit(qc.RemoteAddr())
		if !ok {
			s.noteRejection()
			qc.CloseWithError(0, "server at capacity") // shed load instead of queuing unboundedly
			continue
		}
		go func() {
			defer release() // every exit path gives the slot back, exactly once
			// Recover a panic here too: this goroutine parses an attacker-supplied
			// certificate chain, and the project's rule is that one crafted input may
			// cost its connection, never the process. release() is deferred FIRST, so
			// it still runs while the panic unwinds and the slot cannot leak.
			safe.Do("control.conn", func() { s.connLoop()(s, qc) })
		}()
	}
}

func (s *ControlServer) acceptStreams(qc *quic.Conn) {
	// Closing here is what makes the slot accounting honest: the release closure
	// runs when this returns, so the connection must actually be gone by then —
	// including on the first-stream timeout below.
	defer qc.CloseWithError(0, "")

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
	// A real buddy registers immediately after connecting. Bound the wait for the
	// FIRST stream so a connection that completes the handshake and then goes quiet
	// releases its slot in seconds rather than at the idle timeout. Later streams
	// are the ordinary polling cadence and only need the idle timeout.
	first := true
	for {
		ctx, cancel := context.Background(), context.CancelFunc(func() {})
		if first {
			ctx, cancel = context.WithTimeout(ctx, firstStreamTimeout)
		}
		st, err := qc.AcceptStream(ctx)
		cancel()
		if err != nil {
			return // connection closed, or no first stream in time
		}
		first = false
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
	// Bound the read: a peer that dribbles bytes, or that never half-closes its
	// send side, would otherwise pin this goroutine and one of the connection's
	// stream slots indefinitely. An incomplete request is closed, not queued.
	_ = st.SetReadDeadline(time.Now().Add(controlReadTimeout))
	// Read ONE byte past the limit so going over it is detectable. A plain
	// LimitReader(st, maxControlReq) reports clean EOF at exactly the limit, so an
	// oversize request was silently TRUNCATED and its prefix served — pad valid
	// JSON with whitespace up to the limit and the server answers while the client
	// keeps sending. The documented bound has to reject, not trim.
	payload, err := io.ReadAll(io.LimitReader(st, maxControlReq+1))
	if err != nil || len(payload) > maxControlReq {
		st.CancelRead(0)
		st.Close()
		return
	}
	_ = st.SetReadDeadline(time.Time{})
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
