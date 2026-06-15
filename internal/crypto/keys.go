// Package crypto holds BuddyNet's identity and addressing primitives: the
// long-term Ed25519 keypair every node carries, and the deterministic virtual
// IP derived from a public key. There is no key server and no DHCP — a node's
// address is a pure function of its identity, so two nodes that know each
// other's public key already agree on each other's virtual IP.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// VirtualSubnet is the BuddyNet overlay range. Addresses are assigned
// deterministically from a node's public key, never by a server.
const VirtualSubnet = "10.66.0.0/24"

// VirtualIP derives a node's overlay address from its public key:
//
//	10.66.0.X   where X = SHA-256(pubkey)[0]
//
// It is deterministic (same key always yields the same IP) and needs no
// coordination. The host octet is clamped to the usable 1..254 range so we
// never hand out the network (.0) or broadcast (.255) address; this folds two
// of the 256 hash values onto .1/.254, an acceptable, rare extra collision in a
// /24 that is already collision-prone by design (256 hosts, birthday bound
// ~20). Operators who outgrow a /24 widen the host part in v2.
func VirtualIP(pub ed25519.PublicKey) netip.Addr {
	sum := sha256.Sum256(pub)
	host := sum[0]
	switch host {
	case 0:
		host = 1
	case 255:
		host = 254
	}
	return netip.AddrFrom4([4]byte{10, 66, 0, host})
}

// VirtualIPString is VirtualIP rendered as a string, the form carried on the
// wire and stored in peers.json.
func VirtualIPString(pub ed25519.PublicKey) string {
	return VirtualIP(pub).String()
}

// PubKeyB64 is the canonical base64 (std encoding) of a public key, the form
// used everywhere on the wire and on disk.
func PubKeyB64(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// DecodePubKey parses a base64 Ed25519 public key, rejecting anything that is
// not exactly a 32-byte key.
func DecodePubKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d-byte key, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// LoadOrCreateKey returns a long-term Ed25519 private key and whether it was
// freshly generated (true) versus loaded from disk (false). With an empty path
// it generates an ephemeral key (created=true). Otherwise it loads the base64
// 32-byte seed from path, creating and persisting one (0600) on first run — or
// after the key was lost, which the caller can surface via created.
//
// The same key is the node's identity, the subject of its self-signed TLS cert,
// and the seed of its virtual IP, so losing it changes the node's address and
// requires re-pinning by its buddies.
func LoadOrCreateKey(path string) (priv ed25519.PrivateKey, created bool, err error) {
	if path == "" {
		_, priv, err = ed25519.GenerateKey(rand.Reader)
		return priv, true, err
	}
	data, rerr := os.ReadFile(path)
	switch {
	case rerr == nil:
		// Tolerate a trailing newline/whitespace so a key written with `echo` or an
		// editor still loads (StdEncoding would otherwise reject the newline and the
		// node could silently regenerate a fresh identity, changing its address).
		seed, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if derr != nil {
			return nil, false, fmt.Errorf("decode key %s: %w", path, derr)
		}
		if len(seed) != ed25519.SeedSize {
			return nil, false, fmt.Errorf("key %s: bad seed length %d (want %d)", path, len(seed), ed25519.SeedSize)
		}
		return ed25519.NewKeyFromSeed(seed), false, nil
	case os.IsNotExist(rerr):
		_, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, false, err
		}
		seed := base64.StdEncoding.EncodeToString(priv.Seed())
		if werr := os.WriteFile(path, []byte(seed), 0o600); werr != nil {
			return nil, false, werr
		}
		return priv, true, nil
	default:
		return nil, false, rerr
	}
}
