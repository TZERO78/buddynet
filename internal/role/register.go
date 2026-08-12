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

// buddyRegister registers over the QUIC control transport — the only one there
// is since v8: it dials the server on the shared socket, then polls (a stream per
// attempt) until a signed PEER_LIST names the partner. QUIC validates the source
// address in its handshake, so no application-layer cookie is needed, and the
// REGISTER travels inside TLS 1.3 rather than in the clear. Closing the control
// client leaves the socket open, so the caller then hole-punches and runs the peer
// tunnel on the very same mapping.
func buddyRegister(conn *net.UDPConn, serverAddrs []*net.UDPAddr, cfg BuddyConfig, nd *node, rendezvous string, timeout time.Duration) (protocol.Peer, error) {
	priv, serverPub := nd.priv, nd.serverPub

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var cli *tunnel.ControlClient
	var derr error
	for _, a := range serverAddrs {
		dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
		cli, derr = tunnel.DialControl(dctx, conn, a, serverPub, priv, controlIdleTimeout)
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
		// One freshly signed registration per poll (see buddyRegister): the QUIC
		// transport reuses a single connection, but each stream must carry its own
		// nonce or the server sees the second poll as a replay. No cookie here —
		// QUIC's own handshake validated the source address.
		reg, berr := buildRegister(cfg, nd, rendezvous)
		if berr != nil {
			return protocol.Peer{}, berr
		}
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

// buildRegister marshals ONE registration attempt: a fresh nonce, a current
// timestamp and a signature over both, plus the sealed token and (if enrolling)
// the sealed enrollment code.
//
// Every caller must call this per ATTEMPT, never once per session: the server
// rejects a repeated (PubKey,Nonce) as a replay, which is exactly what a
// re-marshalled cached registration would look like.
func buildRegister(cfg BuddyConfig, nd *node, rendezvous string) ([]byte, error) {
	nonce, err := protocol.NewNonce()
	if err != nil {
		return nil, fmt.Errorf("registration nonce: %w", err)
	}
	m := protocol.Message{
		Type:      protocol.TypeRegister,
		Ver:       protocol.Version,
		Role:      protocol.RoleBuddy,
		Token:     rendezvous, // signed in plaintext; replaced by TokenEnc on the wire below
		ID:        nd.id,
		PubKey:    nd.pub,
		VirtualIP: nd.vip,
		Name:      cfg.Name,
		Ts:        time.Now().Unix(),
		Nonce:     nonce,
	}
	if cfg.Code != "" {
		// Sealed BEFORE signing: CodeEnc is covered by the signature, so a captured
		// enrollment code cannot be re-bound to a different public key.
		//
		// A sealing failure is an ERROR, not a silently code-less registration: the
		// operator passed --code because they are waiting to approve this client, and
		// dropping the field would leave them watching a `pending` line that never
		// appears, with nothing anywhere saying why.
		enc, serr := bcrypto.SealCode(cfg.Code, nd.serverPub)
		if serr != nil {
			return nil, fmt.Errorf("seal the enrollment code to the server key: %w", serr)
		}
		m.CodeEnc = enc
	}
	m.RegSig = base64.StdEncoding.EncodeToString(ed25519.Sign(nd.priv, protocol.RegistrationPayload(m)))
	if err := setToken(&m, rendezvous, nd.serverPub); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

// setToken puts the pairing rendezvous on a REGISTER, sealed to the server's
// pinned identity key. The signature is always over the RAW rendezvous, which the
// server recovers by unsealing.
//
// A sealing failure is now an ERROR rather than a silent fall back to the
// cleartext field: that fallback would have put the pairing token on the wire in
// the clear precisely when something was already wrong, and since v8 there is no
// cleartext field to fall back to anyway.
func setToken(m *protocol.Message, rendezvous string, serverPub ed25519.PublicKey) error {
	enc, err := bcrypto.SealCode(rendezvous, serverPub)
	if err != nil {
		return fmt.Errorf("seal the pairing token to the server key: %w", err)
	}
	m.TokenEnc = enc
	m.Token = "" // only the sealed form is serialised; the signature covers the plaintext
	return nil
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
