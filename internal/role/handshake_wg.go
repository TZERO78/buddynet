package role

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/ratelimit"
	"github.com/tzero78/buddynet/internal/safe"
	"github.com/tzero78/buddynet/internal/wg"
)

// hsWGIface is the server's WireGuard control-plane interface.
const hsWGIface = "bnet-hs0"

// hsWGControlPort is the UDP port REGISTER/PEER_LIST use INSIDE the tunnel (on the
// server's VIP). It must differ from the WireGuard underlay listen port — the
// kernel WG socket already holds that port, so a userspace bind on the same port
// fails with EADDRINUSE. It lives only on the private overlay, so it cannot clash
// with anything on the public interface. Server and buddy agree on it by constant.
const hsWGControlPort = 51821

// serveControlWG runs the handshake control plane over kernel WireGuard. The
// server brings up one interface whose WG peers ARE the --authorized allowlist
// (each buddy's X25519 key derived from its allowlisted Ed25519 identity). Kernel
// WireGuard admits only configured peers, so the allowlist becomes the network
// admission control: an unauthorized buddy never completes a WG handshake and its
// REGISTER never arrives. REGISTER/PEER_LIST then ride INSIDE the tunnel, reaching
// the server at its VIP — encrypted, authenticated and source-validated by WG
// itself (no signatures-on-the-wire, no sealed token, no cookie needed).
//
// Because the datagram's inner source is only the buddy's VIP, the punchable
// candidate is recovered from the kernel via wg.PeerEndpoint (the peer's learned
// underlay endpoint). The pairing core (pairRegister/signedPeerList) is reused
// unchanged.
func serveControlWG(ctx context.Context, priv ed25519.PrivateKey, authz *authorizer, cfg HandshakeConfig, reg *hsRegistry, rl *ratelimit.Limiter) error {
	if authz == nil {
		return errors.New("--wireguard handshake requires --authorized: kernel WireGuard admits only known peers, so the allowlist is the WG peer set. Approve buddies with `buddynet allowclient <key>`")
	}
	peers, err := authorizedWGPeers(authz)
	if err != nil {
		return err
	}
	if len(peers) == 0 {
		return errors.New("--wireguard handshake: the allowlist is empty — approve at least one buddy first: `buddynet allowclient <key>`")
	}

	port := listenPortOf(cfg.Listen)
	pub := priv.Public().(ed25519.PublicKey)
	myVIP := bcrypto.VirtualIP(pub)

	down, err := wg.Up(wg.Config{
		IfName:     hsWGIface,
		PrivateKey: bcrypto.X25519FromEd25519Private(priv),
		ListenPort: port,
		Address:    netip.PrefixFrom(myVIP, 16), // /16 so replies to any buddy VIP route out this iface
		Peer:       peers[0],
	})
	if err != nil {
		return fmt.Errorf("--wireguard handshake: bring up %s (need Linux + NET_ADMIN + the wireguard module): %w", hsWGIface, err)
	}
	defer down()
	for _, p := range peers[1:] {
		if err := wg.AddPeer(hsWGIface, p); err != nil {
			return fmt.Errorf("--wireguard handshake: add WG peer: %w", err)
		}
	}
	log.Printf("HANDSHAKE: action=listening iface=%s vip=%s peers=%d transport=wireguard", hsWGIface, myVIP, len(peers))

	// Serve REGISTER inside the tunnel, on the server VIP at the inner control port
	// (distinct from the WG underlay port). The kernel routes replies back through
	// the tunnel to the buddy.
	lconn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(myVIP, hsWGControlPort)))
	if err != nil {
		return fmt.Errorf("--wireguard handshake: listen on %s:%d: %w", myVIP, hsWGControlPort, err)
	}
	defer lconn.Close()
	go func() { <-ctx.Done(); lconn.Close() }()

	buf := make([]byte, 1500)
	for {
		n, innerSrc, err := lconn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				log.Print("shutting down")
				return nil
			}
			log.Printf("read: %v", err)
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		safe.Do("handshake.register.wg", func() {
			handleRegisterWG(lconn, reg, priv, authz, cfg.RelayEndpoint, rl, innerSrc, raw)
		})
	}
}

// handleRegisterWG pairs one REGISTER that arrived inside the WireGuard tunnel.
// The buddy is already WG-authenticated (it is an allowlisted peer), so there is no
// cookie; the punchable candidate is the peer's underlay endpoint from the kernel,
// not the inner VIP source. Replies (even when parked/empty) go to the inner source
// so a polling buddy makes progress.
func handleRegisterWG(conn *net.UDPConn, reg *hsRegistry, priv ed25519.PrivateKey, authz *authorizer, relayEndpoint string, rl *ratelimit.Limiter, innerSrc *net.UDPAddr, raw []byte) {
	// Bound per-source work even though WG already gated admission (each buddy has a
	// distinct VIP, so the inner source is a fine rate-limit key).
	if rl != nil && !rl.Allow(innerSrc.IP.String()) {
		hsStats.rateLimited.Add(1)
		return
	}
	m, ok := parseRegister(raw)
	if !ok {
		hsStats.dropped.Add(1)
		return
	}
	if !resolveToken(&m, priv) {
		hsStats.dropped.Add(1)
		return
	}
	edpub, err := bcrypto.DecodePubKey(m.PubKey)
	if err != nil {
		hsStats.dropped.Add(1)
		return
	}
	wgpub, err := bcrypto.X25519FromEd25519Public(edpub)
	if err != nil {
		hsStats.dropped.Add(1)
		return
	}
	// The buddy's real, punchable endpoint — learned by the kernel from its WG
	// handshake. Without it there is no usable candidate yet; drop and let the
	// buddy retry (its next REGISTER arrives once the endpoint is established).
	ep, ok, err := wg.PeerEndpoint(hsWGIface, wgpub)
	if err != nil || !ok {
		hsDebugf("wg handshake: no endpoint yet for %s", keyTag(m.PubKey))
		return
	}
	realSrc := net.UDPAddrFromAddrPort(ep)

	peers, ok := pairRegister(reg, authz, relayEndpoint, realSrc, m)
	if !ok {
		return
	}
	if b, err := json.Marshal(signedPeerList(priv, m.Token, peers)); err == nil {
		conn.WriteToUDP(b, innerSrc)
	}
}

// authorizedWGPeers turns the allowlist into the server's WG peer set: one peer per
// approved buddy, keyed by the X25519 derived from its Ed25519 identity, allowed
// only its own key-derived VIP /32 (cryptokey routing — a peer can never claim
// another's VIP). No endpoint is set: the server does not initiate; the kernel
// learns each buddy's endpoint when it connects in.
func authorizedWGPeers(authz *authorizer) ([]wg.Peer, error) {
	keys := authz.authorizedKeys()
	peers := make([]wg.Peer, 0, len(keys))
	for _, b64 := range keys {
		edpub, err := bcrypto.DecodePubKey(b64)
		if err != nil {
			log.Printf("WARNING: --wireguard handshake: skipping un-decodable allowlist key %s: %v", keyTag(b64), err)
			continue
		}
		x, err := bcrypto.X25519FromEd25519Public(edpub)
		if err != nil {
			log.Printf("WARNING: --wireguard handshake: skipping allowlist key %s (X25519 derive failed): %v", keyTag(b64), err)
			continue
		}
		peers = append(peers, wg.Peer{
			PublicKey:  x,
			AllowedIPs: []netip.Prefix{netip.PrefixFrom(bcrypto.VirtualIP(edpub), 32)},
		})
	}
	return peers, nil
}

// listenPortOf extracts the UDP port from a listen address ("[::]:51820"),
// defaulting to 51820 when it cannot be parsed.
func listenPortOf(listen string) int {
	_, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return 51820
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return 51820
	}
	return p
}
