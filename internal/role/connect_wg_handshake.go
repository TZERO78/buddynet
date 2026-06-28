package role

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/wg"
	"github.com/tzero78/buddynet/pkg/protocol"
)

// registerOverWG runs matchmaking over an ephemeral WireGuard tunnel to the
// handshake server (the WG-only control plane), then returns the underlay port to
// reuse for the data plane plus the paired partner.
//
// Endpoint discovery (why the port is reused): inside the tunnel the server sees
// only this buddy's VIP, so it records the buddy's PUNCHABLE address from the
// kernel WG peer endpoint (wg.PeerEndpoint) — which is the NAT mapping of THIS
// interface's listen port. The data plane then binds that same port, so the mapping
// the server observed stays valid for the direct punch (same principle as the
// punch→WG handoff in lab/test-wg-handoff.sh). The ephemeral handshake interface is
// torn down before returning, freeing the port for the data socket.
func registerOverWG(ctx context.Context, cfg BuddyConfig, nd *node, att attempt, timeout time.Duration) (port int, partner protocol.Peer, err error) {
	if !wg.Available() {
		return 0, protocol.Peer{}, errors.New("--wireguard set but kernel WireGuard is unavailable here (need Linux + NET_ADMIN + the wireguard module)")
	}
	serverAddrs, err := resolveAll(cfg.Server)
	if err != nil || len(serverAddrs) == 0 {
		return 0, protocol.Peer{}, fmt.Errorf("resolve server %q: %w", cfg.Server, err)
	}
	serverUnderlay := serverAddrs[0].AddrPort()
	if serverUnderlay.Addr().Is4In6() {
		serverUnderlay = netip.AddrPortFrom(serverUnderlay.Addr().Unmap(), serverUnderlay.Port())
	}
	serverX, err := bcrypto.X25519FromEd25519Public(nd.serverPub)
	if err != nil {
		return 0, protocol.Peer{}, fmt.Errorf("derive server X25519 key: %w", err)
	}
	serverVIP := bcrypto.VirtualIP(nd.serverPub)

	// Pick the underlay port to reuse for the data plane.
	probe, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		return 0, protocol.Peer{}, fmt.Errorf("pick handshake port: %w", err)
	}
	port = probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()

	myPub := nd.priv.Public().(ed25519.PublicKey)
	ifName := fmt.Sprintf("bnet-hs%d", att.ifIndex) // unique per concurrent buddy; ephemeral
	down, err := wg.Up(wg.Config{
		IfName:     ifName,
		PrivateKey: bcrypto.X25519FromEd25519Private(nd.priv),
		ListenPort: port,
		Address:    netip.PrefixFrom(bcrypto.VirtualIP(myPub), 32),
		Peer: wg.Peer{
			PublicKey:  serverX,
			Endpoint:   serverUnderlay,
			AllowedIPs: []netip.Prefix{netip.PrefixFrom(serverVIP, 32)},
			Keepalive:  25,
		},
		Routes: []netip.Prefix{netip.PrefixFrom(serverVIP, 32)},
	})
	if err != nil {
		return 0, protocol.Peer{}, fmt.Errorf("bring up ephemeral WG handshake interface %s: %w", ifName, err)
	}
	defer down() // ephemeral: drop it once we have the roster, freeing the port

	partner, err = buddyRegisterWG(ctx, cfg, nd, serverVIP, att.rendezvous, timeout)
	if err != nil {
		return 0, protocol.Peer{}, err
	}
	return port, partner, nil
}

// buddyRegisterWG sends REGISTER inside the WireGuard tunnel to the server's VIP
// and polls for a signed PEER_LIST. It mirrors buddyRegister but needs no
// address-validation cookie (WireGuard validated the source in its handshake); the
// roster signature is still verified against the pinned server key.
func buddyRegisterWG(ctx context.Context, cfg BuddyConfig, nd *node, serverVIP netip.Addr, rendezvous string, timeout time.Duration) (protocol.Peer, error) {
	sock, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		return protocol.Peer{}, fmt.Errorf("open control socket: %w", err)
	}
	defer sock.Close()
	dst := net.UDPAddrFromAddrPort(netip.AddrPortFrom(serverVIP, wgControlPort(cfg.WGControlPort)))

	myID, myPub, myVIP, priv, serverPub := nd.id, nd.pub, nd.vip, nd.priv, nd.serverPub
	var codeEnc string
	if cfg.Code != "" {
		if enc, e := bcrypto.SealCode(cfg.Code, serverPub); e == nil {
			codeEnc = enc
		}
	}
	// makeReg builds a FRESH, freshly-signed REGISTER each send. A parked buddy
	// re-polls until its partner arrives; in approval mode a fixed signature would
	// be rejected as a replay on every re-poll (the replay cache cannot tell a
	// legitimate re-registration from a captured one), so it would never receive the
	// roster after the partner joins. Signing fresh each time keeps every poll valid.
	makeReg := func() []byte {
		ts := time.Now().Unix()
		m := protocol.Message{
			Type: protocol.TypeRegister, Ver: protocol.Version, Role: protocol.RoleBuddy,
			ID: myID, PubKey: myPub, VirtualIP: myVIP, Name: cfg.Name, Ts: ts, CodeEnc: codeEnc,
		}
		setToken(&m, rendezvous, serverPub)
		m.RegSig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, protocol.RegistrationPayload(rendezvous, myID, myPub, ts)))
		reg, _ := json.Marshal(m)
		return reg
	}

	deadline := time.Now().Add(timeout)
	next := time.Now()
	var lastLog time.Time
	var skewNoted bool
	buf := make([]byte, 1500)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return protocol.Peer{}, ctx.Err()
		}
		if !time.Now().Before(next) {
			sock.WriteToUDP(makeReg(), dst)
			next = time.Now().Add(time.Second)
			if time.Since(lastLog) >= 5*time.Second {
				log.Print("RECONNECT: action=waiting detail=\"no peer with this token yet\"")
				lastLog = time.Now()
			}
		}
		sock.SetReadDeadline(next)
		n, _, rerr := sock.ReadFromUDP(buf)
		if rerr != nil {
			continue
		}
		var r protocol.Message
		if json.Unmarshal(buf[:n], &r) != nil || r.Type != protocol.TypePeerList {
			continue
		}
		if r.Ver != protocol.Version {
			return protocol.Peer{}, fmt.Errorf("incompatible protocol: server speaks v%d, we speak v%d — update buddynet", r.Ver, protocol.Version)
		}
		peers := canonicalPeers(r.Peers)
		sig, derr := base64.StdEncoding.DecodeString(r.Sig)
		if derr != nil || !ed25519.Verify(serverPub, protocol.PeerListPayload(rendezvous, r.Ts, peers), sig) {
			return protocol.Peer{}, errors.New("server signature did not verify (wrong --server-key, or MITM)")
		}
		if d := time.Since(time.Unix(r.Ts, 0)); d > 60*time.Second || d < -60*time.Second {
			noteSkew(d, &skewNoted)
			continue
		}
		if len(peers) == 0 {
			continue
		}
		return peers[0], nil
	}
	return protocol.Peer{}, errors.New("timed out waiting for partner to register with the same token (WireGuard handshake)")
}
