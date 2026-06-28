package role

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/relay"
	"github.com/tzero78/buddynet/internal/wg"
	"github.com/tzero78/buddynet/pkg/protocol"
)

// wgIfName is this buddy's WireGuard interface: one interface per buddy (bnet0,
// bnet1, …), so N buddies never share one device/listen-port (which would break
// the per-peer hole-punch handoff). Single-peer is bnet0; the supervisor assigns a
// stable index per buddy in MultiPeer mode.
func wgIfName(ifIndex int) string { return fmt.Sprintf("bnet%d", ifIndex) }

// This is the buddy-side glue for the WireGuard data path (Phase 3 step 4c):
// the EKM-free SAS binding run over the punched UDP socket, and the socket→WG
// handoff. connect.go calls these on the WG path; the QUIC path is unchanged.

// bindFramePrefix tags a SAS-binding datagram so it is not confused with punch
// (BNPNCH1), relay control (BNRELAY1), or WireGuard packets (first byte 0x01-0x04).
const bindFramePrefix = "BNBIND1"

// runBindingOverConn performs the ephemeral-DH SAS binding (binding.go) over the
// already-punched UDP path to remote, framing each message with bindFramePrefix
// and retransmitting the last message on timeout (UDP is lossy). committer must be
// opposite on the two ends — reuse the transport role (lower public key commits).
// It returns the 32-byte session binding to feed ComputeSAS in place of TLS EKM.
func runBindingOverConn(conn *net.UDPConn, remote *net.UDPAddr, committer bool, total time.Duration) ([]byte, error) {
	var lastSent []byte
	send := func(b []byte) error {
		lastSent = append([]byte(bindFramePrefix), b...)
		_, err := conn.WriteToUDP(lastSent, remote)
		return err
	}
	deadline := time.Now().Add(total)
	recv := func() ([]byte, error) {
		buf := make([]byte, 1500)
		for time.Now().Before(deadline) {
			_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil { // timeout (or transient) → retransmit our last message
				if lastSent != nil {
					_, _ = conn.WriteToUDP(lastSent, remote)
				}
				continue
			}
			if !udpAddrEqual(src, remote) {
				continue
			}
			if n < len(bindFramePrefix) || string(buf[:len(bindFramePrefix)]) != bindFramePrefix {
				continue
			}
			return append([]byte(nil), buf[len(bindFramePrefix):n]...), nil
		}
		return nil, errors.New("binding: timed out waiting for peer")
	}
	defer conn.SetReadDeadline(time.Time{})
	return runBinding(committer, send, recv)
}

// bringUpWGDirect hands the freshly punched UDP socket to kernel WireGuard: it
// reads the local port, derives the device config from the pinned identities, then
// CLOSES the Go socket and brings up ifName with the partner as the sole peer on
// that same port (so the NAT mapping survives — see lab/test-wg-handoff.sh).
// Returns the teardown func. On a host without NET_ADMIN/module the error wraps
// wg.ErrUnsupported (callers chose this path via wg.Available, so that is unexpected).
func bringUpWGDirect(conn *net.UDPConn, ifName string, myPriv ed25519.PrivateKey, partnerPub ed25519.PublicKey, remote netip.AddrPort) (func() error, error) {
	la, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, errors.New("wgpath: socket has no UDP local address")
	}
	cfg, err := wg.ConfigForPeer(ifName, la.Port, myPriv, partnerPub, remote)
	if err != nil {
		return nil, err
	}
	if err := conn.Close(); err != nil {
		return nil, fmt.Errorf("wgpath: close punch socket before handoff: %w", err)
	}
	return wg.Up(cfg)
}

func udpAddrEqual(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.IP.Equal(b.IP)
}

// primeWGPath walks the fallback chain and returns the first endpoint it can make
// usable, plus which path worked, mirroring primePath on the QUIC side. For Direct
// it hole-punches and returns the punched peer address; for Relayed it binds this
// node's leg on the relay and returns the relay address. In both cases the returned
// address is what the WG data plane uses as its peer endpoint (over a relay the
// relay forwards the encrypted WG packets to the partner's leg, exactly as it does
// QUIC — it is never a WG peer and holds no key). conn keeps the NAT mapping the
// bind/punch opened, so the socket handoff to kernel WG reuses it.
func primeWGPath(conn *net.UDPConn, myID string, chain []relay.Path, session string, punchDur time.Duration) (*net.UDPAddr, relay.Path, error) {
	var lastErr error
	for _, p := range chain {
		addr, err := primeOne(conn, myID, p, session, punchDur)
		if err != nil {
			log.Printf("CONNECT: action=path-failed path=%q detail=%q", p.Desc, err.Error())
			lastErr = err
			continue
		}
		return addr, p, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no usable path")
	}
	return nil, relay.Path{}, fmt.Errorf("all fallback paths failed: %w", lastErr)
}

// runWG brings up the kernel WireGuard data plane (Phase 3 steps 4c/4d). It walks
// the same fallback chain as the QUIC path — direct hole-punch first, then a relay
// — and over the chosen endpoint does the EKM-free SAS binding (TOFU), derives the
// static-DH reconnect secret, hands the socket to kernel WG (bnet0), and keeps the
// tunnel up until ctx.Done; the partner is then reachable natively at its VIP over
// bnet0 (no -L/-forward). It fails closed: if WG is unavailable, no path works, or
// the SAS is rejected, it returns an error rather than silently using another plane.
// MultiPeer-over-bnet0 is a later step.
func runWG(ctx context.Context, cfg BuddyConfig, nd *node, conn *net.UDPConn, att attempt, partner protocol.Peer, partnerPub ed25519.PublicKey, needSAS bool, chain []relay.Path, session string) error {
	if !wg.Available() {
		return errors.New("--wireguard set but kernel WireGuard is unavailable here (need Linux + NET_ADMIN + the wireguard module)")
	}
	remote, used, err := primeWGPath(conn, nd.id, chain, session, cfg.PunchDur)
	if err != nil {
		return fmt.Errorf("--wireguard: %w", err)
	}

	// First contact (TOFU): verify the partner with a SAS bound to a fresh
	// ephemeral-DH exchange over the punched socket (no TLS EKM on the WG path).
	if needSAS {
		if !cfg.Interactive {
			return fmt.Errorf("first contact with an unknown buddy key (%s) but running non-interactively — pin it with --peer-key", partner.PubKey)
		}
		committer := nd.pub < partner.PubKey // deterministic, opposite on the two ends
		sid, berr := runBindingOverConn(conn, remote, committer, 15*time.Second)
		if berr != nil {
			return fmt.Errorf("SAS channel binding: %w", berr)
		}
		sas := ComputeSAS(nd.priv.Public().(ed25519.PublicKey), partnerPub, sid)
		if perr := PromptSAS(sas, cfg.SASTimeout); perr != nil {
			logSASFailure(perr, remote.String(), relay.Path{}, partner, att.inviteToken)
			return perr // key NOT trusted; stop (do not fall back to another plane)
		}
		if cerr := nd.trust.confirm(att.inviteToken, partnerPub); cerr != nil {
			return cerr
		}
	}

	// Reconnect secret (EKM-free): static-DH of the two identities (deterministic,
	// only the two key-holders can compute it).
	var secret string
	if att.firstPairing {
		s, derr := bcrypto.PairSecret(nd.priv, partnerPub)
		if derr != nil {
			return fmt.Errorf("derive session secret: %w", derr)
		}
		secret = base64.RawURLEncoding.EncodeToString(s)
	}

	remoteAP := remote.AddrPort()
	if remoteAP.Addr().Is4In6() {
		remoteAP = netip.AddrPortFrom(remoteAP.Addr().Unmap(), remoteAP.Port())
	}
	down, err := bringUpWGDirect(conn, wgIfName(att.ifIndex), nd.priv, partnerPub, remoteAP)
	if err != nil {
		return fmt.Errorf("--wireguard: bring up data plane: %w", err)
	}
	defer func() { _ = down() }()

	log.Printf("CONNECTED: role=buddy partner=%s key=%s vip=%s via=%q remote=%s",
		partner.ID, keyTag(partner.PubKey), partner.VirtualIP, used.Desc+" (WireGuard)", remoteAP)

	if att.firstPairing {
		if serr := saveSession(cfg.KnownPeers, att.inviteToken, partner.PubKey, secret); serr != nil {
			return fmt.Errorf("persist session: %w", serr)
		}
		log.Printf("CONNECT: action=session-stored store=%s detail=\"invite token retired; reconnects use the stored session secret\"", cfg.KnownPeers)
	}

	// Optional forced re-auth (revocation reach), mirroring the QUIC path: tear the
	// tunnel down after the interval so the outer loop re-pairs and re-checks authz.
	waitCtx := ctx
	if cfg.ReauthInterval > 0 {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, cfg.ReauthInterval)
		defer cancel()
	}
	connectedAt := time.Now()
	<-waitCtx.Done()
	reason := "shutdown"
	if cfg.ReauthInterval > 0 && ctx.Err() == nil {
		reason = "reauth"
	}
	log.Printf("DISCONNECTED: role=buddy partner=%s key=%s reason=%s duration=%s streams=0",
		partner.ID, keyTag(partner.PubKey), reason, time.Since(connectedAt).Round(time.Second))
	return nil
}
