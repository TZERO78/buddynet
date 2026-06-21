package role

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/curve25519"
)

// This is the EKM-free SAS channel binding for the WireGuard data plane. On QUIC
// the SAS was bound to the TLS session via RFC 5705 ExportKeyingMaterial; kernel
// WireGuard exposes no such value, so we run a small ephemeral Diffie-Hellman
// exchange with a hash commitment (the construction RFC 6189 / ZRTP uses) to
// produce a fresh per-connection binding the SAS hashes over.
//
// Why it detects a man in the middle: the committing side sends H(its ephemeral
// public key) BEFORE it sees the peer's ephemeral key, and the other side reveals
// its ephemeral key before seeing the committed one — so neither end can grind
// the resulting value, leaving an active attacker a single guess at the short
// SAS. A passive observer cannot compute the binding (it mixes in the DH shared
// secret); an active MITM terminates two distinct exchanges and therefore derives
// two different bindings, so the two humans read out different SAS codes and
// catch it.

const bindLabel = "buddynet-bind-v1"

// runBinding performs the ephemeral-DH + commitment exchange and returns a
// 32-byte session binding to feed ComputeSAS (in place of TLS keying material).
// committer must be deterministic and opposite on the two ends (the transport
// already picks roles by "lower public key listens" — reuse that). send/recv
// exchange one opaque message each; the caller supplies the transport (the
// punched/relayed datagram path in production, an in-memory pair in tests).
func runBinding(committer bool, send func([]byte) error, recv func() ([]byte, error)) ([]byte, error) {
	var ePriv [32]byte
	if _, err := rand.Read(ePriv[:]); err != nil {
		return nil, err
	}
	ePub, err := curve25519.X25519(ePriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	var peerPub []byte
	if committer {
		commit := sha256.Sum256(ePub)
		if err := send(commit[:]); err != nil {
			return nil, err
		}
		if peerPub, err = recv(); err != nil {
			return nil, err
		}
		if len(peerPub) != 32 {
			return nil, errors.New("binding: bad peer ephemeral key")
		}
		if err := send(ePub); err != nil {
			return nil, err
		}
	} else {
		commit, err := recv()
		if err != nil {
			return nil, err
		}
		if len(commit) != sha256.Size {
			return nil, errors.New("binding: bad commitment")
		}
		if err := send(ePub); err != nil {
			return nil, err
		}
		if peerPub, err = recv(); err != nil {
			return nil, err
		}
		if len(peerPub) != 32 {
			return nil, errors.New("binding: bad peer ephemeral key")
		}
		if got := sha256.Sum256(peerPub); !bytes.Equal(got[:], commit) {
			return nil, errors.New("binding: commitment mismatch (possible MITM)")
		}
	}

	shared, err := curve25519.X25519(ePriv[:], peerPub)
	if err != nil {
		return nil, err
	}
	lo, hi := ePub, peerPub
	if bytes.Compare(lo, hi) > 0 {
		lo, hi = hi, lo
	}
	h := sha256.New()
	h.Write([]byte(bindLabel))
	h.Write(lo)
	h.Write(hi)
	h.Write(shared)
	return h.Sum(nil), nil
}
