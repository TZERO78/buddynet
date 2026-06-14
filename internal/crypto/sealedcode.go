package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/nacl/box"
)

// Enrollment codes are encrypted to the handshake server with a NaCl sealed box
// (anonymous sender). The recipient X25519 key is DERIVED from the server's
// existing Ed25519 identity — the one buddies already pin via --server-key — so
// no second key needs distributing. A network eavesdropper cannot read the code
// and therefore cannot pre-claim it.

// SealCode encrypts code to the X25519 key derived from the server's Ed25519
// public key. Output (base64): ephemeralPub(32) || nonce(24) || ciphertext.
func SealCode(code string, serverEdPub ed25519.PublicKey) (string, error) {
	recipient, err := ed25519PublicToX25519(serverEdPub)
	if err != nil {
		return "", err
	}
	epub, epriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	ct := box.Seal(nil, []byte(code), &nonce, &recipient, epriv)
	out := make([]byte, 0, 32+24+len(ct))
	out = append(out, epub[:]...)
	out = append(out, nonce[:]...)
	out = append(out, ct...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// OpenCode decrypts a SealCode blob using the server's Ed25519 private key.
func OpenCode(enc string, serverEdPriv ed25519.PrivateKey) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(raw) < 32+24+box.Overhead {
		return "", errors.New("malformed sealed code")
	}
	var epub, nonce [32]byte
	copy(epub[:], raw[:32])
	copy(nonce[:], raw[32:56])
	priv := ed25519PrivateToX25519(serverEdPriv)
	var n [24]byte
	copy(n[:], nonce[:24])
	msg, ok := box.Open(nil, raw[56:], &n, &epub, &priv)
	if !ok {
		return "", errors.New("sealed code does not decrypt (wrong server key?)")
	}
	return string(msg), nil
}

// ed25519PublicToX25519 maps an Ed25519 public key to the equivalent X25519
// (Montgomery) public key.
func ed25519PublicToX25519(pub ed25519.PublicKey) ([32]byte, error) {
	var out [32]byte
	p, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return out, err
	}
	copy(out[:], p.BytesMontgomery())
	return out, nil
}

// ed25519PrivateToX25519 maps an Ed25519 private key to the matching X25519
// private scalar (clamped SHA-512 of the seed, per the Ed25519 construction).
func ed25519PrivateToX25519(priv ed25519.PrivateKey) [32]byte {
	h := sha512.Sum512(priv.Seed())
	var s [32]byte
	copy(s[:], h[:32])
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
	return s
}
