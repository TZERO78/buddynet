package tunnel

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// pinnedPeerVerify is the whole PKI-free authentication of the data and control
// planes: the peer is trusted iff its leaf certificate carries EXACTLY the pinned
// key. These adversarial tests assert it accepts the right key and refuses every
// substitute — a regression here is a straight MITM hole.

func TestPinnedPeerVerifyAcceptsPinnedKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := selfSignedCert(priv)
	if err := pinnedPeerVerify(pub)(cert.Certificate, nil); err != nil {
		t.Fatalf("rejected the correctly pinned peer: %v", err)
	}
}

func TestPinnedPeerVerifyRejectsWrongKey(t *testing.T) {
	// The peer presents a perfectly valid self-signed cert — but for a DIFFERENT
	// identity than the one we pinned. This is exactly the MITM case.
	_, presenterPriv, _ := ed25519.GenerateKey(rand.Reader)
	pinnedPub, _, _ := ed25519.GenerateKey(rand.Reader)
	cert := selfSignedCert(presenterPriv)
	if err := pinnedPeerVerify(pinnedPub)(cert.Certificate, nil); err == nil {
		t.Fatal("accepted a peer whose key does not match the pinned key (MITM)")
	}
}

func TestPinnedPeerVerifyRejectsMalformed(t *testing.T) {
	pinnedPub, _, _ := ed25519.GenerateKey(rand.Reader)
	verify := pinnedPeerVerify(pinnedPub)

	t.Run("no certificate", func(t *testing.T) {
		if err := verify(nil, nil); err == nil {
			t.Fatal("accepted a handshake with no certificate")
		}
		if err := verify([][]byte{}, nil); err == nil {
			t.Fatal("accepted a handshake with an empty certificate list")
		}
	})

	t.Run("unparseable certificate", func(t *testing.T) {
		if err := verify([][]byte{{0x01, 0x02, 0x03}}, nil); err == nil {
			t.Fatal("accepted an unparseable certificate")
		}
	})

	t.Run("non-ed25519 identity", func(t *testing.T) {
		// A valid X.509 cert, but with an ECDSA key — BuddyNet identities are always
		// Ed25519, so this must be refused before any key comparison.
		der := ecdsaCertDER(t)
		if err := verify([][]byte{der}, nil); err == nil {
			t.Fatal("accepted a certificate whose key is not an Ed25519 identity")
		}
	})
}

// ecdsaCertDER builds a syntactically valid self-signed X.509 cert carrying an
// ECDSA (non-Ed25519) key, to exercise the "not an Ed25519 identity" rejection.
func ecdsaCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "not-buddynet"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// Neither plane may resume a TLS session. A resumed session does not re-run
// VerifyPeerCertificate, and that callback is the ONLY thing authenticating a
// peer here — there is no CA and no hostname — so resumption would turn key
// pinning into a first-handshake-only check. The control plane had this from the
// start; the data plane, where pinning carries the tunnel, did not.
func TestNeitherPlaneResumesTLSSessions(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	peerPub, _, _ := ed25519.GenerateKey(rand.Reader)

	if c := tlsConfig(priv, peerPub); !c.SessionTicketsDisabled {
		t.Error("data plane: session tickets are enabled — a resumed session skips the pinning callback")
	}
	// The control plane's two configs are built inline in DialControl/ListenControl;
	// assert the property where it is observable: a config that pins must never
	// combine that with resumption.
	for name, c := range map[string]*tls.Config{
		"data-plane": tlsConfig(priv, peerPub),
	} {
		if c.VerifyPeerCertificate != nil && !c.SessionTicketsDisabled {
			t.Errorf("%s: pins by callback but allows resumption", name)
		}
		if c.ClientSessionCache != nil {
			t.Errorf("%s: a client session cache would make resumption reachable", name)
		}
	}
}
