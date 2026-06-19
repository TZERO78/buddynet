package role

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	buddydns "github.com/tzero78/buddynet/internal/dns"
	"github.com/tzero78/buddynet/internal/peer"
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

	// ReauthInterval, if > 0, tears the tunnel down and re-pairs after this long
	// even while it is healthy, so a server-side revocation or token rotation
	// takes effect within the interval (a direct P2P tunnel is otherwise outside
	// the server's reach — it cannot be cancelled centrally). 0 (default) keeps a
	// single session up indefinitely, which is what long transfers want.
	ReauthInterval time.Duration

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

	// Name is this node's self-asserted .buddy hostname (e.g. "alice" → alice.buddy).
	// It is sent in REGISTER and relayed by the handshake server to the partner,
	// who TOFU-pins it. Empty means no name — the node is still reachable via its
	// fingerprint alias in the DNS table.
	Name string

	// DNS, when true, starts a stub resolver on 127.0.0.153:53 that answers
	// A queries for <name>.buddy and <fp8>.buddy from the live peer registry.
	// Requires CAP_NET_BIND_SERVICE or root; fails gracefully with a WARNING
	// if the bind is not permitted.
	DNS bool

	// Lazy defers tunnel establishment until the first -L connection arrives.
	// The -L listener binds immediately (so connect() never returns ECONNREFUSED),
	// but the QUIC tunnel is only dialled when a client actually connects.
	// Requires LocalListen to be set.
	Lazy bool
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
	if cfg.ReauthInterval == 0 {
		log.Print("NOTE: --reauth-interval is 0 (off): once a DIRECT tunnel is up the handshake server " +
			"is no longer in the path, so a server-side revocation or token rotation will NOT tear it down. " +
			"Set --reauth-interval (e.g. 1h) if revocation must take effect on long-lived sessions.")
	}

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

	// Start the .buddy stub resolver once per process lifetime, not per reconnect.
	// It runs until ctx is cancelled; bind failures are logged as WARNING and the
	// tunnel continues without DNS.
	if cfg.DNS {
		myVIPAddr := bcrypto.VirtualIP(priv.Public().(ed25519.PublicKey))
		go func() {
			if err := buddydns.Run(ctx, reg, cfg.Name, myVIPAddr); err != nil {
				log.Printf("WARNING: MagicDNS server error: %v", err)
			}
		}()
		buddydns.RegisterSystem(ctx)
	}

	if cfg.Status {
		return buddyProbe(ctx, cfg, serverPub, trust, myID, myPub, myVIP, priv)
	}

	// --lazy: bind the -L listener immediately so clients never see ECONNREFUSED,
	// but defer the QUIC tunnel until the first connection actually arrives.
	var lt *lazyTunnel
	var lazyCount atomic.Int64
	if cfg.Lazy && cfg.LocalListen != "" {
		ln, lerr := listenLocal(cfg.LocalListen)
		if lerr != nil {
			return fmt.Errorf("lazy -L %s: %w", cfg.LocalListen, lerr)
		}
		go func() { <-ctx.Done(); ln.Close() }()
		log.Printf("lazy -L: listening on %s (tunnel starts on first connection)", cfg.LocalListen)
		lt = newLazyTunnel()
		go lazyForward(ctx, ln, lt, &lazyCount)
	}

	inviteStart := time.Now()
	backoff := reconnectBase
	for {
		// In lazy mode, sleep until a local connection needs a tunnel.
		if lt != nil {
			select {
			case <-lt.wake:
			case <-ctx.Done():
				return nil
			}
		}

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

		runStart := time.Now()
		if err := buddyRun(ctx, cfg, att, serverPub, trust, reg, myID, myPub, myVIP, priv, lt); err != nil && ctx.Err() == nil {
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
		// A run that lasted longer than the cap means a real tunnel was up; reset
		// the backoff so a single long-lived session always reconnects promptly.
		// A run that failed fast (server/network flapping) grows the delay, with
		// jitter, so many buddies don't reconnect in lockstep (thundering herd).
		if time.Since(runStart) > reconnectMax {
			backoff = reconnectBase
		}
		wait := jitter(backoff)
		log.Printf("reconnecting in %s...", wait.Round(100*time.Millisecond))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		if backoff *= 2; backoff > reconnectMax {
			backoff = reconnectMax
		}
	}
}

// Reconnect backoff bounds: start at reconnectBase, double up to reconnectMax,
// each wait jittered to spread reconnects across many buddies.
const (
	reconnectBase = 3 * time.Second
	reconnectMax  = 60 * time.Second
)

// jitter returns a duration in [d/2, d]: full-ish jitter so synchronized clients
// (e.g. after a shared server outage) do not retry in lockstep. It draws from
// crypto/rand — overkill for load spreading, but it keeps the whole binary free
// of math/rand so there is no weak-RNG to misuse elsewhere.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return d // CSPRNG failure (never happens) — fall back to the full delay
	}
	return d/2 + time.Duration(binary.BigEndian.Uint64(b[:])%(uint64(d/2)+1))
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
