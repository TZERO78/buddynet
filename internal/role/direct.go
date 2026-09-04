package role

import (
	"errors"
	"fmt"
	"net"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/pkg/protocol"
)

// Direct mode: two buddies that reach each other at addresses their operators
// configured, with no handshake server anywhere.
//
// What carries the security here is exactly what carries it in server mode — the
// partner's pinned Ed25519 key, checked in the TLS handshake by
// tunnel.pinnedPeerVerify. What FALLS AWAY is everything the server contributed
// to *finding* the partner: no REGISTER, no signed roster, no observed
// candidates, no relay ticket. So:
//
//   - --peer-key is mandatory. In server mode an unknown key can still be
//     established over a rendezvous token and a human-checked SAS; here there is
//     no rendezvous channel to run that over, so an unpinned partner is not a
//     weaker mode, it is no authentication at all.
//   - The configured address is route-finding only, never identity. A hijacked
//     DNS record or a spoofed route reaches a host that cannot produce the pinned
//     key, and the handshake fails. That costs availability, not secrecy.
//   - Nothing learned this way is taken on the partner's word: the virtual IP is
//     DERIVED from the pinned key (identity is address), not accepted from a peer.

// errDirectNoKey is returned when direct mode is configured without a pin. It is
// a hard error and never a warning: see the reasoning above.
var errDirectNoKey = errors.New("--direct requires --peer-key: with no handshake server there is no rendezvous channel for a SAS, so the pinned key is the only thing authenticating the partner")

// directPartner builds the partner descriptor from local configuration alone.
//
// Every field is derived from the pinned key rather than asserted by anyone:
// the virtual IP comes from crypto.VirtualIP, so a peer cannot claim a different
// address than its identity implies — the invariant the signed roster enforces in
// server mode holds here by construction, because there is no roster to lie on.
func directPartner(cfg BuddyConfig) (protocol.Peer, error) {
	if cfg.PeerKey == "" {
		return protocol.Peer{}, errDirectNoKey
	}
	pub, err := bcrypto.DecodePubKey(cfg.PeerKey)
	if err != nil {
		return protocol.Peer{}, fmt.Errorf("bad --peer-key: %w", err)
	}
	return protocol.Peer{
		ID:        keyTag(cfg.PeerKey),
		PubKey:    bcrypto.PubKeyB64(pub),
		VirtualIP: bcrypto.VirtualIPString(pub),
	}, nil
}

// directListening decides which side runs the QUIC listener, since there is no
// server to arrange a simultaneous connect.
//
// A buddy can be dialled if it was given a fixed port to listen on, and can dial
// if it was told where the partner is. When only one of those is true the roles
// are forced. When BOTH sides are reachable the tie is broken exactly the way
// server mode breaks it — lower public key listens — so the two ends agree
// without exchanging a single packet first.
func directListening(cfg BuddyConfig, myPub, peerPub string) bool {
	canDial := cfg.PeerEndpoint != ""
	canListen := cfg.ListenPort != 0
	switch {
	case canDial && canListen:
		return myPub < peerPub
	case canListen:
		return true
	default:
		// No fixed port: this side can only reach out.
		return false
	}
}

// errDirectNoPath reports the one configuration direct mode cannot work with:
// a buddy that can neither be dialled nor dial.
var errDirectNoPath = errors.New("--direct needs either --peer-endpoint (to dial your buddy) or --listen-port (to be dialled by them); with neither there is no way for the two to meet")

// validateDirect checks a direct-mode configuration before any socket is opened,
// so a misconfiguration is a startup error rather than a reconnect loop that
// never succeeds.
func validateDirect(cfg BuddyConfig) error {
	// --peer-relay is checked in BOTH modes: since the relay endpoint comes from
	// local trust (relaytrust.go), the flag is the one way to name a relay on a
	// host other than the server's, and a malformed value should fail at startup
	// rather than on the first fallback.
	if err := validateHostPort("--peer-relay", cfg.PeerRelay); err != nil {
		return err
	}
	if !cfg.Direct {
		return nil
	}
	if cfg.PeerKey == "" {
		return errDirectNoKey
	}
	if cfg.PeerEndpoint == "" && cfg.ListenPort == 0 {
		return errDirectNoPath
	}
	return validateHostPort("--peer-endpoint", cfg.PeerEndpoint)
}

// validateHostPort fails on a malformed address at startup rather than at every
// reconnect. The name is NOT resolved — a dynamic-DNS record may legitimately
// not exist at startup, and resolution happens per attempt. Empty is fine (the
// flag is optional).
func validateHostPort(what, addr string) error {
	for _, a := range []struct{ what, addr string }{{what, addr}} {
		if a.addr == "" {
			continue
		}
		host, port, err := net.SplitHostPort(a.addr)
		if err != nil {
			return fmt.Errorf("%s %q: want host:port: %w", a.what, a.addr, err)
		}
		if host == "" {
			return fmt.Errorf("%s %q: missing host", a.what, a.addr)
		}
		if _, err := net.LookupPort("udp", port); err != nil {
			return fmt.Errorf("%s %q: bad port %q", a.what, a.addr, port)
		}
	}
	return nil
}
