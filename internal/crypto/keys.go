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
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"strings"
	"syscall"
)

// VirtualSubnet is the BuddyNet overlay range. Addresses are assigned
// deterministically from a node's public key, never by a server.
const VirtualSubnet = "10.66.0.0/16"

// VirtualIP derives a node's overlay address from its public key:
//
//	10.66.X.Y   where X = SHA-256(pubkey)[0], Y = SHA-256(pubkey)[1]
//
// It is deterministic (same key always yields the same IP) and needs no
// coordination. Two of the 65536 host values are reserved — the all-zeros
// network address (10.66.0.0) and the all-ones broadcast (10.66.255.255) — and
// folded onto 10.66.0.1 / 10.66.255.254 respectively, a rare extra collision.
// Drawing 16 bits instead of 8 widens the space from 254 to ~65534 usable
// addresses, lifting the birthday bound from ~20 to ~300 nodes at 1% collision
// probability — enough headroom for multi-buddy deployments. Operators who
// outgrow a /16 widen the host part further in a later protocol version.
func VirtualIP(pub ed25519.PublicKey) netip.Addr {
	sum := sha256.Sum256(pub)
	hi, lo := sum[0], sum[1]
	switch {
	case hi == 0 && lo == 0:
		lo = 1
	case hi == 255 && lo == 255:
		lo = 254
	}
	return netip.AddrFrom4([4]byte{10, 66, hi, lo})
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

// ErrKeyMissing is returned by LoadKey when the key file does not exist. It is a
// distinct error because the two reasons it happens need opposite reactions: on a
// genuine first run the operator should create one, while on an existing node it
// means the key was LOST (an unmounted volume, a typo in --key), and inventing a
// replacement would silently change the node's identity.
var ErrKeyMissing = errors.New("identity key file does not exist")

// LoadKey loads a long-term Ed25519 private key from path and NEVER creates one:
// a missing file returns ErrKeyMissing. This is what the server roles use.
//
// Creating an identity by accident is the failure this guards against. The key is
// simultaneously the node's identity, the subject of its self-signed TLS cert and
// the seed of its virtual IP, and buddies PIN it — so a handshake server that
// quietly comes up with a fresh one is not a server with a rotated key, it is a
// different server to everyone, and every buddy refuses it as a possible MITM
// until the pins are redone by hand.
//
// With an empty path it still generates an ephemeral in-memory key (created=true),
// which is the documented "no --key given" behaviour and touches no disk.
func LoadKey(path string) (priv ed25519.PrivateKey, created bool, err error) {
	return loadKey(path, false)
}

// CreateKey creates a new identity at path and returns it. It refuses if the file
// already exists (O_EXCL), so it can never overwrite an identity that buddies have
// pinned — running it twice is safe and the second run is an error, not a silent
// re-key.
//
// This is the ONLY way a server identity comes into being. It is deliberately a
// separate function with a name nobody puts in a start-up path: anything that runs
// on every boot must not be able to mint an identity.
func CreateKey(path string) (priv ed25519.PrivateKey, err error) {
	if path == "" {
		_, priv, err = ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
	// NOT loadKey: this must FAIL on an existing file rather than load it. Loading
	// silently would let `init` report "created a new identity" for a node that
	// already had one — the opposite of what the command promises.
	return createKeyFile(path)
}

// createKeyFile generates an identity and writes it to path, refusing if anything
// is already there. O_CREATE|O_EXCL|O_NOFOLLOW: create a fresh REAL file or fail —
// never write THROUGH a symlink, never clobber a file that appeared in the
// meantime. (Unchanged from the hardened original; see the 2026-07-04 audit.)
func createKeyFile(path string) (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	seed := base64.StdEncoding.EncodeToString(priv.Seed())
	cf, cerr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if cerr != nil {
		return nil, fmt.Errorf("create key %s: %w", path, cerr)
	}
	if _, werr := cf.WriteString(seed); werr != nil {
		cf.Close()
		return nil, werr
	}
	if cerr := cf.Close(); cerr != nil {
		return nil, cerr
	}
	return priv, nil
}

// LoadOrCreateKey loads the key at path, creating one when it is missing. This is
// the BUDDY behaviour: a buddy is set up by a person on their own machine and
// should stay a single command, and a buddy that loses its key only has to be
// re-pinned by its one partner — it does not lock a whole network out the way a
// lost server identity does.
//
// Server roles must use LoadKey instead. See ErrKeyMissing.
func LoadOrCreateKey(path string) (priv ed25519.PrivateKey, created bool, err error) {
	return loadKey(path, true)
}

// loadKey is the shared implementation. create decides what happens when the file
// is missing; everything else — the O_NOFOLLOW/TOCTOU handling, the permission
// tightening, the O_EXCL creation — is identical for both callers and deliberately
// untouched (hardened in the 2026-07-04 crypto audit).
func loadKey(path string, create bool) (priv ed25519.PrivateKey, created bool, err error) {
	if path == "" {
		_, priv, err = ed25519.GenerateKey(rand.Reader)
		return priv, true, err
	}
	// A key file must be a REAL file, never a symlink. os.ReadFile/Stat/Chmod and
	// os.WriteFile all FOLLOW symlinks, so honoring a symlinked path would read,
	// chmod, or clobber the LINK TARGET (e.g. a key path pointing at /etc/shadow —
	// as root that would chmod the target to 0600).
	//
	// We open the file ONCE with O_NOFOLLOW and do every subsequent check (perms)
	// and fix (chmod) on the returned descriptor — never re-deriving from the path.
	// That closes the TOCTOU an Lstat-then-ReadFile / Stat-then-Chmod pair leaves
	// open: a path swapped to a symlink between the check and the use can no longer
	// redirect us to another file. O_NOFOLLOW makes the open itself fail (ELOOP) if
	// the final component is a link; a missing path (ENOENT) falls through to
	// creation. Fail-closed throughout.
	f, oerr := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	switch {
	case oerr == nil:
		defer f.Close()
		info, serr := f.Stat()
		if serr != nil {
			return nil, false, serr
		}
		if info.Mode().Perm()&0o077 != 0 {
			// The identity key is also the TLS cert key and the seed of the virtual
			// IP — it must not be group/other-accessible. Tighten it in place (on the
			// fd, not the path) rather than run with an exposed key; if even that
			// fails, refuse instead of continuing with a readable private key
			// (fail-closed, like SSH).
			log.Printf("WARNING: key file %s had permissions %v (group/other access); tightening to 0600", path, info.Mode().Perm())
			if cerr := f.Chmod(0o600); cerr != nil {
				return nil, false, fmt.Errorf("key %s has permissions %v (must be 0600) and could not be tightened: %w", path, info.Mode().Perm(), cerr)
			}
		}
		data, rerr := io.ReadAll(f)
		if rerr != nil {
			return nil, false, fmt.Errorf("read key %s: %w", path, rerr)
		}
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
	case errors.Is(oerr, syscall.ELOOP):
		return nil, false, fmt.Errorf("key %s is a symlink; refusing (a key file must be a real file, not a link to one)", path)
	case errors.Is(oerr, os.ErrNotExist):
		if !create {
			return nil, false, fmt.Errorf("%w: %s", ErrKeyMissing, path)
		}
		priv, cerr := createKeyFile(path)
		if cerr != nil {
			return nil, false, cerr
		}
		return priv, true, nil
	default:
		return nil, false, oerr
	}
}
