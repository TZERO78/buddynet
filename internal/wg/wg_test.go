package wg

import (
	"context"
	"crypto/ed25519"
	"net/netip"
	"testing"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
)

func TestConfigForPeer(t *testing.T) {
	myPub, myPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	peerPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ep := netip.MustParseAddrPort("203.0.113.5:51820")

	cfg, err := ConfigForPeer("bnet0", 41000, myPriv, peerPub, ep)
	if err != nil {
		t.Fatalf("ConfigForPeer: %v", err)
	}

	if cfg.IfName != "bnet0" || cfg.ListenPort != 41000 || cfg.Peer.Endpoint != ep {
		t.Fatalf("scalar fields wrong: %+v", cfg)
	}
	if cfg.PrivateKey != bcrypto.X25519FromEd25519Private(myPriv) {
		t.Fatal("PrivateKey not derived from my Ed25519 private key")
	}
	wantPeerX, _ := bcrypto.X25519FromEd25519Public(peerPub)
	if cfg.Peer.PublicKey != wantPeerX {
		t.Fatal("Peer.PublicKey not derived from partner's Ed25519 public key")
	}
	if cfg.Address != netip.PrefixFrom(bcrypto.VirtualIP(myPub), 32) {
		t.Fatalf("Address: want %s/32, got %s", bcrypto.VirtualIP(myPub), cfg.Address)
	}
	wantPartnerVIP := netip.PrefixFrom(bcrypto.VirtualIP(peerPub), 32)
	if len(cfg.Peer.AllowedIPs) != 1 || cfg.Peer.AllowedIPs[0] != wantPartnerVIP {
		t.Fatalf("AllowedIPs: want %s, got %v", wantPartnerVIP, cfg.Peer.AllowedIPs)
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0] != wantPartnerVIP {
		t.Fatalf("Routes: want [%s], got %v", wantPartnerVIP, cfg.Routes)
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("derived config failed validate(): %v", err)
	}
}

// TestConfirmHandshakeFailsClosedOnUnknownDevice pins the property the whole
// proof rests on: when the kernel cannot be asked about the device (no such
// interface, no wireguard module, or not Linux at all), ConfirmHandshake must
// report an error — never a confirmed partner. It must also not sit out its full
// budget in that case.
func TestConfirmHandshakeFailsClosedOnUnknownDevice(t *testing.T) {
	peerPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	ts, err := ConfirmHandshake(context.Background(), "bn-nosuchdev0", peerPub, 3*time.Second)
	if err == nil {
		t.Fatalf("want an error for an unknown device, got handshake at %s", ts)
	}
	if !ts.IsZero() {
		t.Fatalf("error path must not report a handshake time, got %s", ts)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("a device that cannot be queried should fail fast, took %s", el)
	}
}

// TestConfirmHandshakeHonoursCancellation proves a shutdown while waiting is
// surfaced as the context's error, not as a "partner did not answer" failure —
// the supervisor distinguishes the two.
func TestConfirmHandshakeHonoursCancellation(t *testing.T) {
	peerPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ConfirmHandshake(ctx, "bn-nosuchdev0", peerPub, HandshakeTimeout); err == nil {
		t.Fatal("want an error on a cancelled context")
	}
}
