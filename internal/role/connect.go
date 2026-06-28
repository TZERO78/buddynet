package role

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/peer"
	"github.com/tzero78/buddynet/internal/relay"
	"github.com/tzero78/buddynet/internal/tunnel"
	"github.com/tzero78/buddynet/pkg/protocol"
)

// buddyRun does one full attempt: register, walk the fallback chain to a
// session, then forward until the tunnel drops. lt is non-nil in --lazy mode.
func buddyRun(ctx context.Context, cfg BuddyConfig, att attempt, nd *node, lt *lazyTunnel) (retErr error) {
	trust, reg := nd.trust, nd.reg
	myID, myPub, priv := nd.id, nd.pub, nd.priv
	// In lazy mode: if we return an error before setSession is reached,
	// unblock any waiting -L connections with the error and reset to SLEEPING.
	if lt != nil {
		defer func() {
			if retErr != nil {
				lt.setFailed(retErr)
				lt.markIdle()
			}
		}()
	}

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
		partner, err = buddyRegister(conn, serverAddrs, cfg, nd, att.rendezvous, 30*time.Second)
		if err != nil {
			return err
		}
	} else {
		log.Printf("CONNECT: action=server-unreachable server=%q detail=%q", cfg.Server, serr.Error())
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
		// claims an inconsistent one (defends against a buggy/hostile server, or a
		// squat that forged a virtual IP). Log the security event HERE, at the
		// detection point, rather than letting it surface as a generic tunnel error.
		if want := bcrypto.VirtualIPString(partnerPub); partner.VirtualIP != "" && partner.VirtualIP != want {
			log.Printf("SECURITY: event=vip-mismatch key=%s detail=%q",
				keyTag(partner.PubKey),
				fmt.Sprintf("roster claims vip %s but the key derives %s (hostile/buggy server, or a squat with a forged vip)", partner.VirtualIP, want))
			return fmt.Errorf("partner virtual IP %s does not match its key (want %s)", partner.VirtualIP, want)
		}
		_ = reg.Upsert(partner) // cache for offline fallback next time
		// Partner found and identity-verified — NOT "online" yet (the tunnel is not
		// up until dialChain succeeds below; that emits CONNECTED).
		log.Printf("CONNECT: action=partner-verified id=%s key=%s vip=%s cands=%d", partner.ID, keyTag(partner.PubKey), partner.VirtualIP, len(partner.Candidates))
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
		log.Printf("CONNECT: action=cached id=%s vip=%s detail=\"server offline\"", partner.ID, partner.VirtualIP)
	}

	partnerPub, err := bcrypto.DecodePubKey(partner.PubKey)
	if err != nil {
		return err
	}
	chain := relay.Chain(partner, nil, partner.Relay, cached)
	if len(chain) == 0 {
		return errors.New("no path to the partner (no candidates, no relay)")
	}
	// Deterministic relay session id: both buddies derive the same value, so a
	// relay can splice their two legs by it. Used by both the QUIC and WG paths.
	session := sessionToken(att.rendezvous, myPub, partner.PubKey)

	// WireGuard data plane (Phase 3, opt-in): hand the socket to kernel WG instead
	// of running QUIC, over the same fallback chain (direct, then relay). Fails
	// closed (no silent fallback to another plane).
	if cfg.WireGuard {
		return runWG(ctx, cfg, nd, conn, att, partner, partnerPub, needSAS, chain, session)
	}

	// One QUIC transport over the socket; deterministic role: lower key listens.
	tr := tunnel.NewQUIC(conn, priv, partnerPub, cfg.IdleTimeout)
	defer tr.Close()
	listening := myPub < partner.PubKey

	sess, used, err := dialChain(ctx, tr, conn, myID, chain, listening, session, cfg.PunchDur)
	if err != nil {
		return err
	}
	log.Printf("CONNECTED: role=buddy partner=%s key=%s vip=%s via=%q remote=%s",
		partner.ID, keyTag(partner.PubKey), partner.VirtualIP, used.Desc, sess.RemoteAddr())

	// First contact (trust-on-first-use): verify the partner identity with a SAS
	// over the now-established, channel-bound session BEFORE trusting/persisting
	// it. Only reached when not pinned and not --lab.
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
			logSASFailure(err, sess.RemoteAddr().String(), used, partner, att.inviteToken)
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
		log.Printf("CONNECT: action=session-stored store=%s detail=\"invite token retired; reconnects use the stored session secret\"", cfg.KnownPeers)
	}

	// Optional forced re-auth: after ReauthInterval, close the session so the
	// outer loop re-registers (re-running the allowlist/trust checks). This is
	// the only way a revocation can reach an established direct tunnel, which the
	// server is not in the path of. Off by default so long transfers are not
	// interrupted.
	var reauthFired atomic.Bool
	if cfg.ReauthInterval > 0 {
		t := time.AfterFunc(cfg.ReauthInterval, func() {
			log.Printf("CONNECT: action=reauth interval=%s detail=\"tearing down the tunnel to re-check authorization\"", cfg.ReauthInterval)
			reauthFired.Store(true)
			sess.Close()
		})
		defer t.Stop()
	}

	connectedAt := time.Now()
	var streams int64
	var ferr error

	if lt != nil {
		// Lazy path: signal waiting -L connections that the tunnel is ready, then
		// run the --forward side (if set) until the session ends. lazyForward()
		// already handles the -L side in its own goroutine.
		lt.setSession(sess)
		if cfg.Forward != "" {
			var fwdCount atomic.Int64
			serveStreams(ctx, sess, cfg.Forward, &fwdCount)
			streams = fwdCount.Load()
		} else {
			<-sess.Done()
		}
		lt.markIdle()
	} else {
		// Non-lazy path: -L and -forward as before, plus --vip-listen, which binds
		// THIS partner's virtual IP on lo and routes name.buddy:port to its tunnel.
		streams, ferr = forward(ctx, sess, cfg.LocalListen, cfg.Forward, bcrypto.VirtualIP(partnerPub), cfg.VIPListen)
	}

	reason := "peer-closed-or-idle"
	switch {
	case ctx.Err() != nil:
		reason = "shutdown"
	case reauthFired.Load():
		reason = "reauth"
	}
	log.Printf("DISCONNECTED: role=buddy partner=%s key=%s reason=%s duration=%s streams=%d",
		partner.ID, keyTag(partner.PubKey), reason, time.Since(connectedAt).Round(time.Second), streams)
	return ferr
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
			log.Printf("CONNECT: action=path-failed path=%q detail=%q", p.Desc, err.Error())
			lastErr = err
			continue
		}
		attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		var sess tunnel.Session
		if listening {
			log.Printf("CONNECT: action=path-try path=%q role=server", p.Desc)
			sess, err = tr.Listen(attemptCtx)
		} else {
			log.Printf("CONNECT: action=path-try path=%q role=client endpoint=%s", p.Desc, endpoint)
			sess, err = tr.Dial(attemptCtx, endpoint)
		}
		cancel()
		if err != nil {
			log.Printf("CONNECT: action=path-failed path=%q detail=%q", p.Desc, fmt.Sprintf("QUIC failed: %v", err))
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
// primeOne readies a single fallback path on conn and returns the peer endpoint to
// use: a hole-punch for Direct, a relay-leg bind for Relayed. Shared by the QUIC
// dial loop (primePath) and the WireGuard path walk (primeWGPath).
func primeOne(conn *net.UDPConn, myID string, p relay.Path, session string, punchDur time.Duration) (*net.UDPAddr, error) {
	switch p.Kind {
	case relay.Direct:
		remote, err := tunnel.Punch(conn, myID, p.Candidates, punchDur)
		if err != nil {
			return nil, fmt.Errorf("direct punch: %w", err)
		}
		return remote, nil
	case relay.Relayed:
		relayAddr, err := net.ResolveUDPAddr("udp", p.RelayEndpoint)
		if err != nil {
			return nil, fmt.Errorf("resolve relay %q: %w", p.RelayEndpoint, err)
		}
		if err := relay.BindLeg(conn, relayAddr, session, 5*time.Second); err != nil {
			return nil, fmt.Errorf("relay bind: %w", err)
		}
		return relayAddr, nil
	default:
		return nil, errors.New("unknown path kind")
	}
}

// primePath primes one path for the QUIC dial loop, returning the endpoint as a
// string for tunnel dialing.
func primePath(conn *net.UDPConn, myID string, p relay.Path, session string, punchDur time.Duration) (string, error) {
	addr, err := primeOne(conn, myID, p, session, punchDur)
	if err != nil {
		return "", err
	}
	return addr.String(), nil
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
