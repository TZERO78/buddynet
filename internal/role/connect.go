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
	//
	// Port 0 (the default) takes an ephemeral port, which is what a buddy behind
	// NAT wants. --listen-port pins it instead, so a port forward can be aimed at
	// this socket and the buddy becomes dialable at a stable address — the
	// prerequisite for direct mode's listening side.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: cfg.ListenPort})
	if err != nil {
		if cfg.ListenPort != 0 {
			return fmt.Errorf("open udp socket on --listen-port %d: %w", cfg.ListenPort, err)
		}
		return fmt.Errorf("open udp socket: %w", err)
	}
	defer conn.Close()

	// needSAS is set when the partner key is unknown (trust-on-first-use) and must
	// be verified by the human via the SAS once the tunnel is up.
	var needSAS bool

	// One throwaway key pair per attempt, minted BEFORE registering because its
	// public half travels with the REGISTER: the server signs it into the relay
	// ticket, which is what makes that ticket useless to anyone else.
	cred, err := newRelayCred()
	if err != nil {
		return err
	}

	// Where does the partner come from? Direct mode configures it locally;
	// otherwise the handshake server introduces it. Everything below this point
	// — pinning, QUIC, forwarding — is identical for both.
	var partner protocol.Peer
	var cached *protocol.Peer
	if cfg.Direct {
		// No REGISTER, no roster, no ticket: the partner is exactly what the
		// operator pinned, and its virtual IP is derived from that key rather
		// than claimed by anyone. See internal/role/direct.go.
		var derr error
		if partner, derr = directPartner(cfg); derr != nil {
			return derr
		}
		// Same guard the server path applies to a roster entry: pinning our own
		// key would otherwise have this node dial itself and fail obscurely.
		if partner.PubKey == myPub {
			return errors.New("--peer-key is this node's OWN identity — pass your BUDDY's public key (see: buddynet identity)")
		}
		log.Printf("CONNECT: action=direct key=%s vip=%s endpoint=%q detail=%q",
			keyTag(partner.PubKey), partner.VirtualIP, cfg.PeerEndpoint,
			"direct mode: no handshake server; partner pinned by key")
	} else {
		serverAddrs, serr := resolveAll(cfg.Server)
		if serr == nil {
			var rt *protocol.RelayTicket
			partner, rt, err = buddyRegister(conn, serverAddrs, cfg, nd, att.rendezvous, 30*time.Second, cred)
			if err != nil {
				return err
			}
			// A missing or unusable ticket costs the relay fallback, never the pairing:
			// the server may simply have no relay configured, which is a supported and
			// fully functional deployment.
			if aerr := cred.adopt(rt); aerr != nil && rt != nil {
				log.Printf("NOTE: the server issued a relay ticket this buddy cannot use (%v) — the relay fallback is unavailable for this attempt", aerr)
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
				if perr := enforcePins(att, partnerPub, "partner key"); perr != nil {
					return perr
				}
			} else if needSAS, err = trust.decide(att.inviteToken, partnerPub); err != nil {
				return err
			}
			if err := checkPartnerVIP(partner, partnerPub); err != nil {
				return err
			}
			// NOTE: deliberately NOT persisted here. The roster has been checked for
			// consistency, but nothing has yet PROVEN that the key on it belongs to the
			// buddy we mean — that happens when the tunnel comes up (the partner has to
			// hold the private key to complete the QUIC/WG handshake) and, on first
			// contact, when the human confirms the SAS. Writing peers.json here would
			// cache an unverified key and TOFU-pin an unverified .buddy name, both
			// straight from a server-supplied roster. See rememberPeer below.
			// Partner found and identity-verified — NOT "online" yet (the tunnel is not
			// up until dialChain succeeds below; that emits CONNECTED).
			log.Printf("CONNECT: action=partner-verified id=%s key=%s vip=%s cands=%d", partner.ID, keyTag(partner.PubKey), partner.VirtualIP, len(partner.Candidates))
		}

		// Assemble the fallback chain. A cached entry is only used when the server
		// gave us nothing live (it was unreachable).
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
				if perr := enforcePins(att, partnerPub, "cached partner key"); perr != nil {
					return perr
				}
			} else if needSAS, err = trust.decide(att.inviteToken, partnerPub); err != nil {
				return err
			}
			log.Printf("CONNECT: action=cached id=%s vip=%s detail=\"server offline\"", partner.ID, partner.VirtualIP)
		}
	}

	partnerPub, err := bcrypto.DecodePubKey(partner.PubKey)
	if err != nil {
		return err
	}
	chain := relay.Chain(partner, nil, partner.Relay, cached)
	if cfg.Direct {
		chain = relay.DirectChain(cfg.PeerEndpoint, cfg.PeerRelay)
	}
	if len(chain) == 0 {
		return errors.New("no path to the partner (no candidates, no relay)")
	}
	// The relay session id. With a ticket it is the one the SERVER named, so two
	// legs can only meet if the server put them together; without one it is the
	// value both buddies derive from the pairing token, which is what a
	// network-mode relay has always spliced on. Used by both the QUIC and WG paths.
	session := cred.session(sessionToken(att.rendezvous, myPub, partner.PubKey))

	// WireGuard data plane (Phase 3, opt-in): hand the socket to kernel WG instead
	// of running QUIC, over the same fallback chain (direct, then relay). Fails
	// closed (no silent fallback to another plane).
	if cfg.WireGuard {
		return runWG(ctx, cfg, nd, conn, att, partner, partnerPub, needSAS, chain, session, cred)
	}

	// One QUIC transport over the socket; deterministic role: lower key listens.
	tr := tunnel.NewQUIC(conn, priv, partnerPub, cfg.IdleTimeout)
	defer tr.Close()
	listening := myPub < partner.PubKey
	if cfg.Direct {
		// In direct mode reachability is not symmetric — one side may only be
		// able to dial — so the role follows the configuration first and falls
		// back to the same key comparison when both ends could do either.
		listening = directListening(cfg, myPub, partner.PubKey)
	}

	var sess tunnel.Session
	var used relay.Path
	if cfg.Direct && listening {
		// No server means no shared starting gun, so the listening side arms every
		// path at once instead of walking them in turn. See listenAllPaths.
		sess, used, err = listenAllPaths(ctx, tr, conn, myID, chain, session, cfg.PunchDur, cred)
	} else {
		sess, used, err = dialChain(ctx, tr, conn, myID, chain, listening, session, cfg.PunchDur, cred)
	}
	if err != nil {
		return err
	}
	log.Printf("CONNECTED: role=buddy partner=%s key=%s vip=%s via=%q remote=%s",
		partner.ID, keyTag(partner.PubKey), partner.VirtualIP, used.Desc, sess.RemoteAddr())

	// First contact (trust-on-first-use): verify the partner identity with a SAS
	// over the now-established, channel-bound session BEFORE trusting/persisting
	// it. Only reached when not pinned and not --lab.
	// showOnly is the joining side of a key-bound invite: the partner key was
	// pinned from the invite blob, so there is nothing to verify here — but the
	// INVITER still has to verify us, and the code it types has to come from
	// somewhere. Display it (once, on the first pairing) so the human can read it
	// out. This never blocks and never trusts anything.
	showOnly := !needSAS && cfg.SASShow && att.firstPairing
	if needSAS || showOnly {
		if needSAS && !cfg.Interactive {
			return fmt.Errorf("first contact with an unknown buddy key (%s) but no way to verify it: running non-interactively. Pin it with --peer-key, or run once interactively to confirm the SAS", partner.PubKey)
		}
		ekm, eerr := sess.ExportKeyingMaterial(sasLabel, nil, 32)
		if eerr != nil {
			return fmt.Errorf("SAS channel binding: %w", eerr)
		}
		myEdPub := priv.Public().(ed25519.PublicKey)
		sas := ComputeSAS(myEdPub, partnerPub, ekm)
		if showOnly {
			showSAS(sas)
		} else {
			if err := promptSAS(sas, cfg.Inviting, cfg.SASTimeout); err != nil {
				logSASFailure(err, sess.RemoteAddr().String(), used, partner, att.inviteToken)
				return err // Buddy stops the reconnect loop, key NOT stored
			}
			if err := trust.confirm(att.inviteToken, partnerPub); err != nil {
				return err
			}
		}
	}

	// Identity is now CONFIRMED: the session is up (which required the partner to
	// hold the private key for partnerPub) and, on first contact, the human matched
	// the SAS. Only now does the peer earn a place in the on-disk cache and in the
	// .buddy name table. A failed SAS returns above, so nothing is written.
	rememberPeer(reg, partner)

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

// rememberPeer writes a peer into the offline cache (peers.json) and the .buddy
// name table. Call it ONLY after the partner's identity has been confirmed:
//
//   - the data plane came up, which the partner could only do by holding the
//     private key for the public key we pinned or were vouched, and
//   - on first contact, the human confirmed the SAS over that same channel-bound
//     session (a rejected SAS aborts before this point).
//
// An already-pinned or already-known peer is refreshed the same way, so a new
// endpoint or a new LastSeen from an authenticated connection is kept. A cache
// write is best-effort: losing it costs the offline fallback next time, never the
// live tunnel, so a failure is logged rather than returned.
func rememberPeer(reg *peer.Registry, p protocol.Peer) {
	if p.PubKey == "" {
		return
	}
	if err := reg.Upsert(p); err != nil {
		log.Printf("NOTE: could not update the peer cache (%v) — the tunnel is unaffected, but the offline fallback may be stale", err)
	}
}

// checkPartnerVIP enforces "identity IS address" on the roster the server handed
// us: the virtual IP is a pure function of the public key, so a roster claiming
// an inconsistent one is refused before any data plane comes up. This is the
// buddy-side half of the defense — the server derives the VIP itself and drops a
// registration that claims a different one, so in a healthy deployment this never
// fires. It exists for the case the server itself is hostile or buggy, which is
// exactly the case where the server-side check is worth nothing.
//
// An absent VirtualIP is not a mismatch: it carries no claim, and everything that
// matters (the WG peer address, the route) is derived from the key regardless.
//
// The SECURITY event is logged here, at the detection point, rather than being
// left to surface as a generic tunnel error somewhere up the stack.
func checkPartnerVIP(partner protocol.Peer, partnerPub ed25519.PublicKey) error {
	want := bcrypto.VirtualIPString(partnerPub)
	if partner.VirtualIP == "" || partner.VirtualIP == want {
		return nil
	}
	log.Printf("SECURITY: event=vip-mismatch key=%s detail=%q",
		keyTag(partner.PubKey),
		fmt.Sprintf("roster claims vip %s but the key derives %s (hostile/buggy server, or a squat with a forged vip)", partner.VirtualIP, want))
	return fmt.Errorf("partner virtual IP %s does not match its key (want %s)", partner.VirtualIP, want)
}

// dialChain walks the fallback chain and returns the first session it can
// establish, plus which path worked. For each path it primes the path on the
// socket (punch for Direct, relay-bind for Relayed), then takes its
// deterministic QUIC role (listen or dial).
// listenAllPaths is the listening side of DIRECT MODE, where nothing
// synchronises the two ends.
//
// Walking the chain in step is fine when a handshake server introduced the pair:
// both sides start from the same PEER_LIST at the same moment. In direct mode
// they start whenever their processes happened to start, and each path attempt
// takes ~10s — so the two can settle permanently out of phase, one listening on
// the direct path exactly while the other is bound to the relay, and back again.
// Measured, not theorised: the relay logged `session-paired` for both legs while
// each end was already off trying the other path.
//
// The fix uses a property the sequential walk throws away: every path arrives on
// the SAME UDP socket. So prime them all — punch, bind the relay legs — and then
// listen ONCE. Whoever dials gets through, on whichever path they picked, and the
// phase problem cannot exist. The path is reported afterwards from the address
// the session actually came in on.
func listenAllPaths(ctx context.Context, tr *tunnel.QUICTransport, conn *net.UDPConn, myID string, chain []relay.Path, session string, punchDur time.Duration, cred *relayCred) (tunnel.Session, relay.Path, error) {
	primed := make(map[string]relay.Path, len(chain))
	var lastErr error
	for _, p := range chain {
		endpoint, err := primeOne(conn, myID, p, session, punchDur, cred)
		if err != nil {
			log.Printf("CONNECT: action=path-failed path=%q detail=%q", p.Desc, err.Error())
			lastErr = err
			continue
		}
		if endpoint != nil {
			primed[endpoint.String()] = p
		}
		log.Printf("CONNECT: action=path-armed path=%q role=server", p.Desc)
	}
	// The direct path has no endpoint to prime on this side (nothing to punch
	// towards), so an empty primed map is normal and still worth listening on.
	if len(primed) == 0 && lastErr != nil && len(chain) > 1 {
		return nil, relay.Path{}, lastErr
	}
	attemptCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	sess, err := tr.Listen(attemptCtx)
	if err != nil {
		return nil, relay.Path{}, fmt.Errorf("%s: %w", noPathAdvice(chain), err)
	}
	// Attribute the session to the path it arrived on: a relayed session comes
	// from the relay's address, anything else came in directly.
	used := chain[0]
	if p, ok := primed[sess.RemoteAddr().String()]; ok {
		used = p
	}
	return sess, used, nil
}

func dialChain(ctx context.Context, tr *tunnel.QUICTransport, conn *net.UDPConn, myID string, chain []relay.Path, listening bool, session string, punchDur time.Duration, cred *relayCred) (tunnel.Session, relay.Path, error) {
	var lastErr error
	for _, p := range chain {
		endpoint, err := primePath(conn, myID, p, session, punchDur, cred)
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
	return nil, relay.Path{}, fmt.Errorf("%s: %w", noPathAdvice(chain), lastErr)
}

// noPathAdvice turns "it did not work" into something an operator can act on.
// When the chain held no relay at all, the failure is not a mystery: the direct
// connection did not come up and there was nothing to fall back to. Saying so is
// the difference between an operator who knows they need to open a port or run a
// relay, and one who concludes BuddyNet is broken.
//
// It never claims a relay would have helped — with symmetric NAT on both ends it
// is the likely remedy, but the buddy cannot know that from here.
func noPathAdvice(chain []relay.Path) string {
	for _, p := range chain {
		if p.Kind == relay.Relayed {
			return "all fallback paths failed"
		}
	}
	return "no path to the partner: the direct connection failed and no relay is configured " +
		"(the handshake server advertises one with --relay-endpoint; see docs/OPERATIONS.md)"
}

// primePath makes a path usable and returns the endpoint to dial. Direct
// punches a hole to the partner; Relayed binds this node's leg on the relay and
// uses the relay address as the endpoint.
// primeOne readies a single fallback path on conn and returns the peer endpoint to
// use: a hole-punch for Direct, a relay-leg bind for Relayed. Shared by the QUIC
// dial loop (primePath) and the WireGuard path walk (primeWGPath).
func primeOne(conn *net.UDPConn, myID string, p relay.Path, session string, punchDur time.Duration, cred *relayCred) (*net.UDPAddr, error) {
	switch p.Kind {
	case relay.Direct:
		remote, err := tunnel.Punch(conn, myID, p.Candidates, punchDur)
		if err != nil {
			return nil, fmt.Errorf("direct punch: %w", err)
		}
		return remote, nil
	case relay.Configured:
		// Direct mode. The listening side has no endpoint to prepare — it just
		// waits — so an empty endpoint is a valid no-op, not a failure.
		if p.Endpoint == "" {
			return nil, nil
		}
		// Resolved fresh on EVERY attempt: this is how a dynamic-DNS record that
		// moved gets picked up, and it is the only thing DNS does here. The name
		// carries no authority — the endpoint it yields still has to prove the
		// pinned key in the TLS handshake.
		addr, err := net.ResolveUDPAddr("udp", p.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("resolve peer endpoint %q: %w", p.Endpoint, err)
		}
		return addr, nil
	case relay.Relayed:
		relayAddr, err := net.ResolveUDPAddr("udp", p.RelayEndpoint)
		if err != nil {
			return nil, fmt.Errorf("resolve relay %q: %w", p.RelayEndpoint, err)
		}
		if err := relay.BindLeg(conn, relayAddr, session, 5*time.Second, cred.bindCred()); err != nil {
			return nil, fmt.Errorf("relay bind: %w", err)
		}
		return relayAddr, nil
	default:
		return nil, errors.New("unknown path kind")
	}
}

// primePath primes one path for the QUIC dial loop, returning the endpoint as a
// string for tunnel dialing.
func primePath(conn *net.UDPConn, myID string, p relay.Path, session string, punchDur time.Duration, cred *relayCred) (string, error) {
	addr, err := primeOne(conn, myID, p, session, punchDur, cred)
	if err != nil {
		return "", err
	}
	if addr == nil {
		return "", nil // nothing to dial (direct mode, listening side)
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
