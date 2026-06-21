package wg

import (
	"crypto/ed25519"
	"net/netip"
	"testing"

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
	if cfg.Address != netip.PrefixFrom(bcrypto.VirtualIP(myPub), 16) {
		t.Fatalf("Address: want %s/16, got %s", bcrypto.VirtualIP(myPub), cfg.Address)
	}
	if len(cfg.Peer.AllowedIPs) != 1 || cfg.Peer.AllowedIPs[0] != netip.PrefixFrom(bcrypto.VirtualIP(peerPub), 32) {
		t.Fatalf("AllowedIPs: want %s/32, got %v", bcrypto.VirtualIP(peerPub), cfg.Peer.AllowedIPs)
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("derived config failed validate(): %v", err)
	}
}
