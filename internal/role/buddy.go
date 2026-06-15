package role

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/peer"
	"github.com/tzero78/buddynet/internal/relay"
	"github.com/tzero78/buddynet/internal/tunnel"
	"github.com/tzero78/buddynet/pkg/protocol"
)

// BuddyConfig configures an ordinary peer (--role=buddy): it finds its partner
// via the handshake server, brings up an end-to-end-encrypted tunnel along the
// fallback chain (direct, then relay, then cached), and forwards plain TCP.
type BuddyConfig struct {
	Server    string // handshake server host:port [required]
	ServerKey string // server Ed25519 public key, base64 (pinned) [required]
	Token     string // shared pairing token [required]

	PeerKey    string // pin the partner's key (strongest)
	KnownPeers string // TOFU trust store path
	Insecure   bool   // disable partner verification (testing only)
	Code       string // enrollment code for an allowlist server
	KeyPath    string // this node's identity key (created if missing; "" = ephemeral)
	PeersPath  string // offline peer cache (peers.json); "" = none

	LocalListen string // -L: expose local TCP/unix and forward to the peer
	Forward     string // -forward: dial this local service for incoming streams

	PunchDur    time.Duration
	IdleTimeout time.Duration
	Status      bool // probe whether the buddy is online, print, exit

	// Interactive enables the first-contact SAS prompt (trust-on-first-use only).
	// When false (a daemon, or no TTY) an unknown partner key is refused rather
	// than learned blindly — pin it with --peer-key instead.
	Interactive bool
	SASTimeout  time.Duration // how long to wait for SAS confirmation (default 30s)

	// Ephemeral marks an --invite/--join pairing: the Token is a short-lived,
	// one-time invite. On the first SAS-confirmed pairing a long-lived session
	// secret is derived from the channel binding and stored, and all later
	// reconnects use THAT (never the invite again). Plain --token is the legacy
	// fixed-token mode (Ephemeral=false): no session secret, token reused.
	Ephemeral     bool
	InviteTimeout time.Duration // give up first pairing after this long (default 15m)

	// QUIC selects the QUIC control transport for registration instead of plain
	// UDP. It must match the handshake server's transport. QUIC validates the
	// source address in its handshake (structural anti-reflection); UDP achieves
	// the same with the address-validation cookie. Either way the SAME socket is
	// then reused to hole-punch and run the peer tunnel.
	QUIC bool
}

// attempt is the per-connection plan: which rendezvous token to register with,
// and how to treat the partner. It separates the value sent on the wire (the
// invite token, or the derived session secret on reconnect) from how trust is
// evaluated.
type attempt struct {
	rendezvous   string            // token registered at the server this attempt
	inviteToken  string            // human token, for TOFU/session keying ("" on reconnect)
	pin          ed25519.PublicKey // reconnect: partner key that MUST match (nil otherwise)
	firstPairing bool              // ephemeral invite: derive & store a session on success
}

// Buddy runs the peer until ctx is cancelled, reconnecting whenever the tunnel
// drops.
func Buddy(ctx context.Context, cfg BuddyConfig) error {
	if cfg.PunchDur == 0 {
		cfg.PunchDur = 2 * time.Second
	}
	if cfg.IdleTimeout < 10*time.Second {
		cfg.IdleTimeout = 60 * time.Second
	}
	if cfg.SASTimeout <= 0 {
		cfg.SASTimeout = 30 * time.Second
	}
	if cfg.InviteTimeout <= 0 {
		cfg.InviteTimeout = 15 * time.Minute
	}

	serverPub, err := bcrypto.DecodePubKey(cfg.ServerKey)
	if err != nil {
		return fmt.Errorf("bad --server-key: %w", err)
	}
	priv, created, err := bcrypto.LoadOrCreateKey(cfg.KeyPath)
	if err != nil {
		return fmt.Errorf("identity key: %w", err)
	}
	if created && cfg.KeyPath != "" {
		log.Printf("WARNING: generated a NEW identity at %s — your virtual IP changed and your buddy must update its pinned --peer-key", cfg.KeyPath)
	}
	myPub := bcrypto.PubKeyB64(priv.Public().(ed25519.PublicKey))
	myVIP := bcrypto.VirtualIPString(priv.Public().(ed25519.PublicKey))
	myID := randomID()
	log.Printf("buddynet buddy — identity %s vip=%s id=%s", myPub, myVIP, myID)

	trust := &trustPolicy{insecure: cfg.Insecure, storePath: cfg.KnownPeers}
	switch {
	case cfg.PeerKey != "":
		if trust.pinned, err = bcrypto.DecodePubKey(cfg.PeerKey); err != nil {
			return fmt.Errorf("bad --peer-key: %w", err)
		}
		log.Print("buddy identity pinned via --peer-key (strict)")
	case cfg.Insecure:
		log.Print("!!! INSECURE MODE — the buddy's identity is NOT verified: no pin, no SAS.")
		log.Print("!!! Anyone who can answer with this token can impersonate your buddy (MITM).")
		log.Print("!!! Use --peer-key (or default trust-on-first-use with SAS) instead. Testing only.")
		if !cfg.Interactive {
			log.Print("!!! --insecure on an unattended/daemon node is especially dangerous — there is")
			log.Print("!!! no human to catch an impostor. Pin the buddy with --peer-key.")
		}
	case cfg.KnownPeers == "":
		return errors.New("no trust source: set --peer-key, or --known-peers <path> for trust-on-first-use, or --insecure")
	default:
		log.Printf("trust-on-first-use: buddy identity recorded in %s on first connect (pin with --peer-key)", cfg.KnownPeers)
	}

	reg, err := peer.Open(cfg.PeersPath)
	if err != nil {
		return fmt.Errorf("peer cache %s: %w", cfg.PeersPath, err)
	}

	if cfg.Status {
		return buddyProbe(ctx, cfg, serverPub, trust, myID, myPub, myVIP, priv)
	}

	inviteStart := time.Now()
	for {
		// Prefer a stored session (reconnect): use its secret as the rendezvous
		// token and pin the partner key it recorded. Otherwise pair with the
		// invite/legacy token; an ephemeral invite stores a session on success.
		att, aerr := nextAttempt(cfg)
		if aerr != nil {
			return aerr
		}
		// A one-time invite is only valid for a limited window of first pairing.
		if cfg.Ephemeral && att.firstPairing && time.Since(inviteStart) > cfg.InviteTimeout {
			return fmt.Errorf("invite token expired after %s without pairing — run --invite again for a fresh one", cfg.InviteTimeout)
		}

		if err := buddyRun(ctx, cfg, att, serverPub, trust, reg, myID, myPub, myVIP, priv); err != nil && ctx.Err() == nil {
			// An unconfirmed SAS (mismatch or timeout) is a deliberate "do not
			// trust" — retrying would just re-prompt forever, so stop instead of
			// reconnecting.
			if errors.Is(err, ErrSASRejected) || errors.Is(err, ErrSASTimeout) {
				return fmt.Errorf("aborted: %w", err)
			}
			log.Printf("tunnel error: %v", err)
		}
		if ctx.Err() != nil {
			return nil
		}
		log.Print("reconnecting in 3s...")
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(3 * time.Second):
		}
	}
}

// nextAttempt decides how to connect this round: reconnect via a stored session
// secret (pinning the recorded partner key), or pair with the invite/legacy
// token. A stored session always takes precedence, so once an ephemeral invite
// has paired once, the invite token is never used again.
func nextAttempt(cfg BuddyConfig) (attempt, error) {
	if pin, secret, ok, err := loadSession(cfg.KnownPeers); err != nil {
		return attempt{}, fmt.Errorf("session store %s: %w", cfg.KnownPeers, err)
	} else if ok {
		return attempt{rendezvous: secret, pin: pin}, nil
	}
	if cfg.Token != "" {
		return attempt{rendezvous: cfg.Token, inviteToken: cfg.Token, firstPairing: cfg.Ephemeral}, nil
	}
	return attempt{}, errors.New("no saved session and no token — use --invite or --join (or --token for the legacy fixed-token mode)")
}

// buddyRun does one full attempt: register, walk the fallback chain to a
// session, then forward until the tunnel drops.
func buddyRun(ctx context.Context, cfg BuddyConfig, att attempt, serverPub ed25519.PublicKey, trust *trustPolicy, reg *peer.Registry, myID, myPub, myVIP string, priv ed25519.PrivateKey) error {
	// One dual-stack UDP socket does everything (register, punch, relay-bind,
	// QUIC); reusing it preserves the NAT mapping the server observed.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		return fmt.Errorf("open udp socket: %w", err)
	}
	defer conn.Close()

	// needSAS is set when the partner key is unknown (trust-on-first-use) and must
	// be verified by the human via the SAS once the tunnel is up.
	var needSAS bool

	serverAddrs, serr := resolveAll(cfg.Server)
	var partner protocol.Peer
	if serr == nil {
		partner, err = buddyRegister(conn, serverAddrs, cfg, att.rendezvous, myID, myPub, myVIP, priv, serverPub, 30*time.Second)
		if err != nil {
			return err
		}
	} else {
		log.Printf("handshake server %q unreachable (%v) — falling back to cached peers", cfg.Server, serr)
	}

	// Identity checks on the partner the server vouched for.
	if partner.PubKey != "" {
		partnerPub, derr := bcrypto.DecodePubKey(partner.PubKey)
		if derr != nil {
			return fmt.Errorf("partner key: %w", derr)
		}
		if partner.PubKey == myPub {
			return errors.New("partner has the SAME identity as us — both peers use the same --key; give each its own identity")
		}
		if att.pin != nil {
			if !partnerPub.Equal(att.pin) {
				return errors.New("partner key does not match the stored session pin — refusing (someone else answered on the session secret?)")
			}
		} else if needSAS, err = trust.decide(att.inviteToken, partnerPub); err != nil {
			return err
		}
		// The virtual IP is a pure function of the key; reject a roster that
		// claims an inconsistent one (defends against a buggy/hostile server).
		if want := bcrypto.VirtualIPString(partnerPub); partner.VirtualIP != "" && partner.VirtualIP != want {
			return fmt.Errorf("partner virtual IP %s does not match its key (want %s)", partner.VirtualIP, want)
		}
		_ = reg.Upsert(partner) // cache for offline fallback next time
		log.Printf("buddy ONLINE: partner %s vip=%s verified (%d candidate(s))", partner.ID, partner.VirtualIP, len(partner.Candidates))
	}

	// Assemble the fallback chain. A cached entry is only used when the server
	// gave us nothing live (it was unreachable).
	var cached *protocol.Peer
	if partner.PubKey == "" {
		// Server down: try every fresh-enough cached peer in turn.
		for _, c := range reg.List() {
			if peer.Fresh(c, 24*time.Hour) {
				cp := c
				cached = &cp
				partner = c // adopt identity/vip from cache for the QUIC pin
				break
			}
		}
		if cached == nil {
			return errors.New("handshake server unreachable and no fresh cached peer to try")
		}
		partnerPub, derr := bcrypto.DecodePubKey(partner.PubKey)
		if derr != nil {
			return derr
		}
		if att.pin != nil {
			if !partnerPub.Equal(att.pin) {
				return errors.New("cached partner key does not match the stored session pin — refusing")
			}
		} else if needSAS, err = trust.decide(att.inviteToken, partnerPub); err != nil {
			return err
		}
		log.Printf("trying cached partner %s vip=%s (server offline)", partner.ID, partner.VirtualIP)
	}

	partnerPub, err := bcrypto.DecodePubKey(partner.PubKey)
	if err != nil {
		return err
	}
	chain := relay.Chain(partner, nil, partner.Relay, cached)
	if len(chain) == 0 {
		return errors.New("no path to the partner (no candidates, no relay)")
	}

	// One QUIC transport over the socket; deterministic role: lower key listens.
	tr := tunnel.NewQUIC(conn, priv, partnerPub, cfg.IdleTimeout)
	defer tr.Close()
	listening := myPub < partner.PubKey
	session := sessionToken(att.rendezvous, myPub, partner.PubKey)

	sess, used, err := dialChain(ctx, tr, conn, myID, chain, listening, session, cfg.PunchDur)
	if err != nil {
		return err
	}
	log.Printf("✓ ONLINE: encrypted tunnel up via %s — buddy at %s", used.Desc, sess.RemoteAddr())

	// First contact (trust-on-first-use): verify the partner identity with a SAS
	// over the now-established, channel-bound session BEFORE trusting/persisting
	// it. Only reached when not pinned and not --insecure.
	if needSAS {
		if !cfg.Interactive {
			return fmt.Errorf("first contact with an unknown buddy key (%s) but no way to verify it: running non-interactively. Pin it with --peer-key, or run once interactively to confirm the SAS", partner.PubKey)
		}
		ekm, eerr := sess.ExportKeyingMaterial(sasLabel, nil, 32)
		if eerr != nil {
			return fmt.Errorf("SAS channel binding: %w", eerr)
		}
		myEdPub := priv.Public().(ed25519.PublicKey)
		sas := ComputeSAS(myEdPub, partnerPub, ekm)
		if err := PromptSAS(sas, cfg.SASTimeout); err != nil {
			logSASFailure(err, sess, used, partner, att.inviteToken)
			return err // Buddy stops the reconnect loop, key NOT stored
		}
		if err := trust.confirm(att.inviteToken, partnerPub); err != nil {
			return err
		}
	}

	// Ephemeral invite/join: now that the partner is verified, derive a long-lived
	// rendezvous secret from the channel binding and store it. From here on
	// reconnects use that secret — the one-time invite token is retired.
	if att.firstPairing {
		secret, derr := deriveSessionSecret(sess, priv.Public().(ed25519.PublicKey), partnerPub)
		if derr != nil {
			return fmt.Errorf("derive session secret: %w", derr)
		}
		if err := saveSession(cfg.KnownPeers, att.inviteToken, partner.PubKey, secret); err != nil {
			return fmt.Errorf("persist session: %w", err)
		}
		log.Printf("session established — invite token retired; reconnects now use the stored session secret in %s", cfg.KnownPeers)
	}

	return forward(ctx, sess, cfg.LocalListen, cfg.Forward)
}

// dialChain walks the fallback chain and returns the first session it can
// establish, plus which path worked. For each path it primes the path on the
// socket (punch for Direct, relay-bind for Relayed), then takes its
// deterministic QUIC role (listen or dial).
func dialChain(ctx context.Context, tr *tunnel.QUICTransport, conn *net.UDPConn, myID string, chain []relay.Path, listening bool, session string, punchDur time.Duration) (tunnel.Session, relay.Path, error) {
	var lastErr error
	for _, p := range chain {
		endpoint, err := primePath(conn, myID, p, session, punchDur)
		if err != nil {
			log.Printf("path %q: %v", p.Desc, err)
			lastErr = err
			continue
		}
		attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		var sess tunnel.Session
		if listening {
			log.Printf("path %q: listening for buddy (server role)", p.Desc)
			sess, err = tr.Listen(attemptCtx)
		} else {
			log.Printf("path %q: dialing buddy at %s (client role)", p.Desc, endpoint)
			sess, err = tr.Dial(attemptCtx, endpoint)
		}
		cancel()
		if err != nil {
			log.Printf("path %q: QUIC failed: %v", p.Desc, err)
			lastErr = err
			continue
		}
		return sess, p, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no usable path")
	}
	return nil, relay.Path{}, fmt.Errorf("all fallback paths failed: %w", lastErr)
}

// primePath makes a path usable and returns the endpoint to dial. Direct
// punches a hole to the partner; Relayed binds this node's leg on the relay and
// uses the relay address as the endpoint.
func primePath(conn *net.UDPConn, myID string, p relay.Path, session string, punchDur time.Duration) (string, error) {
	switch p.Kind {
	case relay.Direct:
		remote, err := tunnel.Punch(conn, myID, p.Candidates, punchDur)
		if err != nil {
			return "", fmt.Errorf("direct punch: %w", err)
		}
		return remote.String(), nil
	case relay.Relayed:
		relayAddr, err := net.ResolveUDPAddr("udp", p.RelayEndpoint)
		if err != nil {
			return "", fmt.Errorf("resolve relay %q: %w", p.RelayEndpoint, err)
		}
		if err := relay.BindLeg(conn, relayAddr, session, 5*time.Second); err != nil {
			return "", fmt.Errorf("relay bind: %w", err)
		}
		return relayAddr.String(), nil
	default:
		return "", errors.New("unknown path kind")
	}
}

// Probe exit codes for --status, returned through ProbeError so a script can
// distinguish the outcomes by exit code (not just by parsing stdout). The
// contract matches BuddyPeer's:
//
//	0  online and directly reachable          (nil error)
//	1  local error (socket / DNS)             (any non-ProbeError)
//	3  online but not directly reachable      (a relay would be used)
//	4  offline (no buddy registered)
//	5  registered but identity not trusted    (possible hijack)
const (
	ProbeUnreachable = 3
	ProbeOffline     = 4
	ProbeUntrusted   = 5
)

// ProbeError carries a --status outcome as a process exit code. main maps it to
// os.Exit; the human-readable line is printed to stdout by buddyProbe.
type ProbeError struct {
	Code int
	Msg  string
}

func (e *ProbeError) Error() string { return e.Msg }

// logSASFailure records everything known about a failed first-contact SAS, so an
// operator can later tell whether there was an attack (journalctl --namespace=
// buddynet | grep "SAS REJECTED"). An explicit mismatch is a positive attack
// signal; a timeout is only logged as caution (the user may have stepped away).
// The remote endpoint is the peer's real IP ONLY on a direct path; over a relay
// it is the relay's address, so it is annotated accordingly and must not be
// mistaken for the attacker.
func logSASFailure(reason error, sess tunnel.Session, used relay.Path, partner protocol.Peer, token string) {
	headline := "SAS REJECTED — possible MITM / token-theft attack"
	if errors.Is(reason, ErrSASTimeout) {
		headline = "SAS NOT CONFIRMED (timed out) — aborting, treat with caution"
	}
	remoteNote := "direct path: this is the peer's real address"
	if used.Kind == relay.Relayed {
		remoteNote = "RELAYED path: this is the RELAY's address, NOT the peer — do not ban it"
	}
	log.Printf("%s\n"+
		"  remote endpoint : %s   [%s]\n"+
		"  virtual IP claim: %s\n"+
		"  partner pubkey  : %s\n"+
		"  token hash      : %s\n"+
		"  timestamp       : %s\n"+
		"  -> key NOT trusted. Run --invite to generate a fresh token for your buddy.",
		headline, sess.RemoteAddr(), remoteNote, partner.VirtualIP, partner.PubKey,
		tokenKey(token), time.Now().UTC().Format(time.RFC3339))
}

// buddyProbe answers "is my buddy online and reachable?" without forwarding. It
// returns nil when online and directly reachable, a *ProbeError carrying a
// distinct exit code for the offline/unreachable/untrusted cases, or a plain
// error for a local failure (which main maps to exit 1).
func buddyProbe(ctx context.Context, cfg BuddyConfig, serverPub ed25519.PublicKey, trust *trustPolicy, myID, myPub, myVIP string, priv ed25519.PrivateKey) error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		return err
	}
	defer conn.Close()
	serverAddrs, err := resolveAll(cfg.Server)
	if err != nil {
		return err
	}
	log.Print("status: checking whether the buddy is online...")
	partner, err := buddyRegister(conn, serverAddrs, cfg, cfg.Token, myID, myPub, myVIP, priv, serverPub, 10*time.Second)
	if err != nil {
		fmt.Println("buddy is OFFLINE (no peer registered with this token)")
		return &ProbeError{Code: ProbeOffline, Msg: "offline"}
	}
	partnerPub, derr := bcrypto.DecodePubKey(partner.PubKey)
	if derr != nil {
		fmt.Println("a peer registered under this token but its key is malformed")
		return &ProbeError{Code: ProbeUntrusted, Msg: "untrusted"}
	}
	// A probe never learns a key; a CHANGED known key is a hijack signal, while a
	// brand-new key (needSAS) just means first contact not yet confirmed.
	if _, terr := trust.decide(cfg.Token, partnerPub); terr != nil {
		fmt.Println("a peer registered under this token but its identity is NOT trusted (possible hijack)")
		return &ProbeError{Code: ProbeUntrusted, Msg: "untrusted"}
	}
	if _, err := tunnel.Punch(conn, myID, partner.Candidates, cfg.PunchDur); err != nil {
		fmt.Println("buddy is ONLINE but NOT directly reachable (a relay would be used)")
		return &ProbeError{Code: ProbeUnreachable, Msg: "not directly reachable"}
	}
	fmt.Printf("buddy is ONLINE and REACHABLE — direct path available (vip=%s)\n", partner.VirtualIP)
	return nil
}

// buddyRegister sends REGISTER to every server address ~1/s until a signed
// PEER_LIST arrives and verifies against the pinned server key, then returns the
// (single, in 2-peer mode) partner.
func buddyRegister(conn *net.UDPConn, serverAddrs []*net.UDPAddr, cfg BuddyConfig, rendezvous, myID, myPub, myVIP string, priv ed25519.PrivateKey, serverPub ed25519.PublicKey, timeout time.Duration) (protocol.Peer, error) {
	if cfg.QUIC {
		return buddyRegisterQUIC(conn, serverAddrs, cfg, rendezvous, myID, myPub, myVIP, priv, serverPub, timeout)
	}
	ts := time.Now().Unix()
	m := protocol.Message{
		Type:      protocol.TypeRegister,
		Ver:       protocol.Version,
		Token:     rendezvous,
		Role:      protocol.RoleBuddy,
		ID:        myID,
		PubKey:    myPub,
		VirtualIP: myVIP,
		Ts:        ts,
	}
	m.RegSig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, protocol.RegistrationPayload(rendezvous, myID, myPub, ts)))
	if cfg.Code != "" {
		if enc, err := bcrypto.SealCode(cfg.Code, serverPub); err == nil {
			m.CodeEnc = enc
		}
	}
	reg, _ := json.Marshal(m)

	deadline := time.Now().Add(timeout)
	next := time.Now()
	var lastLog time.Time
	buf := make([]byte, 1500)
	for time.Now().Before(deadline) {
		if !time.Now().Before(next) {
			for _, a := range serverAddrs {
				conn.WriteToUDP(reg, a)
			}
			next = time.Now().Add(time.Second)
			if time.Since(lastLog) >= 5*time.Second {
				log.Print("waiting for buddy to come online (no peer with this token yet)...")
				lastLog = time.Now()
			}
		}
		conn.SetReadDeadline(next)
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		var r protocol.Message
		if json.Unmarshal(buf[:n], &r) != nil {
			continue
		}
		// Address-validation challenge: adopt the cookie and re-register at once
		// (proving return-routability) instead of waiting for the next tick.
		if r.Type == protocol.TypeCookie {
			if r.Cookie != "" && r.Cookie != m.Cookie {
				m.Cookie = r.Cookie
				reg, _ = json.Marshal(m)
				next = time.Now()
			}
			continue
		}
		if r.Type != protocol.TypePeerList {
			continue
		}
		if r.Ver != protocol.Version {
			return protocol.Peer{}, fmt.Errorf("incompatible protocol: server speaks v%d, we speak v%d — update buddynet", r.Ver, protocol.Version)
		}
		peers := canonicalPeers(r.Peers)
		sig, err := base64.StdEncoding.DecodeString(r.Sig)
		if err != nil || !ed25519.Verify(serverPub, protocol.PeerListPayload(rendezvous, r.Ts, peers), sig) {
			return protocol.Peer{}, errors.New("server signature did not verify (wrong --server-key, or MITM)")
		}
		if d := time.Since(time.Unix(r.Ts, 0)); d > 60*time.Second || d < -60*time.Second {
			continue // stale roster (replay/skew) — wait for a fresh one
		}
		if len(peers) == 0 {
			continue
		}
		conn.SetReadDeadline(time.Time{})
		return peers[0], nil
	}
	return protocol.Peer{}, errors.New("timed out waiting for partner to register with the same token")
}

// buddyRegisterQUIC registers over the QUIC control transport: it dials the
// server on the shared socket, then polls (a stream per attempt) until a signed
// PEER_LIST names the partner. QUIC validates the source address, so no cookie
// is needed. Closing the control client leaves the socket open, so the caller
// then hole-punches and runs the peer tunnel on the very same mapping.
func buddyRegisterQUIC(conn *net.UDPConn, serverAddrs []*net.UDPAddr, cfg BuddyConfig, rendezvous, myID, myPub, myVIP string, priv ed25519.PrivateKey, serverPub ed25519.PublicKey, timeout time.Duration) (protocol.Peer, error) {
	ts := time.Now().Unix()
	m := protocol.Message{
		Type:      protocol.TypeRegister,
		Ver:       protocol.Version,
		Token:     rendezvous,
		Role:      protocol.RoleBuddy,
		ID:        myID,
		PubKey:    myPub,
		VirtualIP: myVIP,
		Ts:        ts,
	}
	m.RegSig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, protocol.RegistrationPayload(rendezvous, myID, myPub, ts)))
	if cfg.Code != "" {
		if enc, err := bcrypto.SealCode(cfg.Code, serverPub); err == nil {
			m.CodeEnc = enc
		}
	}
	reg, _ := json.Marshal(m)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var cli *tunnel.ControlClient
	var derr error
	for _, a := range serverAddrs {
		dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
		cli, derr = tunnel.DialControl(dctx, conn, a, serverPub, controlIdleTimeout)
		dcancel()
		if derr == nil {
			break
		}
	}
	if cli == nil {
		return protocol.Peer{}, fmt.Errorf("QUIC control dial failed (is the server on --quic? wrong --server-key?): %w", derr)
	}
	defer cli.Close() // leaves the UDP socket open for hole punching

	var lastLog time.Time
	for ctx.Err() == nil {
		rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
		resp, err := cli.Roundtrip(rctx, reg)
		rcancel()
		if err == nil {
			var r protocol.Message
			if json.Unmarshal(resp, &r) == nil && r.Type == protocol.TypePeerList {
				if r.Ver != protocol.Version {
					return protocol.Peer{}, fmt.Errorf("incompatible protocol: server speaks v%d, we speak v%d — update buddynet", r.Ver, protocol.Version)
				}
				peers := canonicalPeers(r.Peers)
				sig, derr := base64.StdEncoding.DecodeString(r.Sig)
				if derr != nil || !ed25519.Verify(serverPub, protocol.PeerListPayload(rendezvous, r.Ts, peers), sig) {
					return protocol.Peer{}, errors.New("server signature did not verify (wrong --server-key, or MITM)")
				}
				if d := time.Since(time.Unix(r.Ts, 0)); d <= 60*time.Second && d >= -60*time.Second && len(peers) > 0 {
					return peers[0], nil
				}
			}
		}
		if time.Since(lastLog) >= 5*time.Second {
			log.Print("waiting for buddy to come online (no peer with this token yet)...")
			lastLog = time.Now()
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
	return protocol.Peer{}, errors.New("timed out waiting for partner to register with the same token")
}

// canonicalPeers returns the roster in the same ID-sorted order the server
// signed, with each peer's candidates Addr-sorted, so the verifier reconstructs
// identical signed bytes.
func canonicalPeers(in []protocol.Peer) []protocol.Peer {
	out := append([]protocol.Peer(nil), in...)
	for i := range out {
		cs := append([]protocol.Candidate(nil), out[i].Candidates...)
		sort.Slice(cs, func(a, b int) bool { return cs[a].Addr < cs[b].Addr })
		out[i].Candidates = cs
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out
}

// sessionToken derives the relay session id deterministically from the pairing
// token and both identities, so the two buddies compute the SAME value with no
// extra signaling and a relay can pair their legs by it. The relay treats it as
// opaque; the token binds it to this specific pair.
func sessionToken(token, pubA, pubB string) string {
	lo, hi := pubA, pubB
	if hi < lo {
		lo, hi = hi, lo
	}
	sum := sha256.Sum256([]byte(token + "\x00" + lo + "\x00" + hi))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func randomID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand unavailable: %v", err)) // unrecoverable; never happens for crypto/rand
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// resolveAll returns all UDP addresses (v4 and v6) for host:port, so we register
// over both stacks and the server learns both candidates.
func resolveAll(hostport string) ([]*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	p, err := net.LookupPort("udp", port)
	if err != nil {
		return nil, err
	}
	var out []*net.UDPAddr
	for _, ip := range ips {
		out = append(out, &net.UDPAddr{IP: ip, Port: p})
	}
	if len(out) == 0 {
		return nil, errors.New("no addresses resolved")
	}
	return out, nil
}
