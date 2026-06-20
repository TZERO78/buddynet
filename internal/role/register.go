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
	"sort"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/tunnel"
	"github.com/tzero78/buddynet/pkg/protocol"
)

// buddyRegister sends REGISTER to every server address ~1/s until a signed
// PEER_LIST arrives and verifies against the pinned server key, then returns the
// (single, in 2-peer mode) partner.
func buddyRegister(conn *net.UDPConn, serverAddrs []*net.UDPAddr, cfg BuddyConfig, nd *node, rendezvous string, timeout time.Duration) (protocol.Peer, error) {
	if cfg.QUIC {
		return buddyRegisterQUIC(conn, serverAddrs, cfg, nd, rendezvous, timeout)
	}
	myID, myPub, myVIP, priv, serverPub := nd.id, nd.pub, nd.vip, nd.priv, nd.serverPub
	ts := time.Now().Unix()
	m := protocol.Message{
		Type:      protocol.TypeRegister,
		Ver:       protocol.Version,
		Role:      protocol.RoleBuddy,
		ID:        myID,
		PubKey:    myPub,
		VirtualIP: myVIP,
		Name:      cfg.Name,
		Ts:        ts,
	}
	setToken(&m, rendezvous, serverPub)
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
	var skewNoted bool
	buf := make([]byte, 1500)
	for time.Now().Before(deadline) {
		if !time.Now().Before(next) {
			for _, a := range serverAddrs {
				conn.WriteToUDP(reg, a)
			}
			next = time.Now().Add(time.Second)
			if time.Since(lastLog) >= 5*time.Second {
				log.Print("RECONNECT: action=waiting detail=\"no peer with this token yet\"")
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
			noteSkew(d, &skewNoted) // signed but stale: almost always a clock-skew problem
			continue                // wait for a fresh one
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
func buddyRegisterQUIC(conn *net.UDPConn, serverAddrs []*net.UDPAddr, cfg BuddyConfig, nd *node, rendezvous string, timeout time.Duration) (protocol.Peer, error) {
	myID, myPub, myVIP, priv, serverPub := nd.id, nd.pub, nd.vip, nd.priv, nd.serverPub
	ts := time.Now().Unix()
	m := protocol.Message{
		Type:      protocol.TypeRegister,
		Ver:       protocol.Version,
		Role:      protocol.RoleBuddy,
		ID:        myID,
		PubKey:    myPub,
		VirtualIP: myVIP,
		Name:      cfg.Name,
		Ts:        ts,
	}
	setToken(&m, rendezvous, serverPub)
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
	var skewNoted bool
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
				} else if d > 60*time.Second || d < -60*time.Second {
					noteSkew(d, &skewNoted)
				}
			}
		}
		if time.Since(lastLog) >= 5*time.Second {
			log.Print("RECONNECT: action=waiting detail=\"no peer with this token yet\"")
			lastLog = time.Now()
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
	return protocol.Peer{}, errors.New("timed out waiting for partner to register with the same token")
}

// noteSkew logs a one-time diagnostic when the server's signature verified but
// its PEER_LIST timestamp is outside the ±60s freshness window: the signature
// proves it is not forged, so a large delta is a CLOCK problem (this node or the
// server is not time-synced), not an attack. Without this the buddy would just
// loop silently and "never pair" with no hint why. noted is flipped so the line
// appears at most once per registration attempt.
func noteSkew(d time.Duration, noted *bool) {
	if *noted {
		return
	}
	*noted = true
	log.Printf("NOTE: server roster is signed but %s out of date — check the clock on this host and the server (NTP/time-sync); pairing needs them within ~60s", d.Round(time.Second))
}

// setToken puts the pairing rendezvous on a REGISTER, sealed to the server's
// pinned identity key so it never travels in cleartext on the plain-UDP control
// plane (an on-path observer sees only ciphertext). It falls back to the
// plaintext field only if sealing is somehow unavailable; the signature is always
// over the raw rendezvous, which the server recovers by unsealing.
func setToken(m *protocol.Message, rendezvous string, serverPub ed25519.PublicKey) {
	if enc, err := bcrypto.SealCode(rendezvous, serverPub); err == nil {
		m.TokenEnc = enc
		return
	}
	m.Token = rendezvous
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
