// Command wg-spike is the P3.1 step-3 lab harness for internal/wg: it brings up a
// kernel WireGuard interface with exactly one peer, exercising the REAL identity
// derivation (Ed25519 seed → X25519 keys → virtual IP), and verifies the netlink
// encoding against a live kernel. Two instances peered to each other (typically
// in two network namespaces, see lab/test-wg.sh) form a working tunnel over
// which the overlay VIPs become pingable.
//
// It is NOT part of the shipped binary — purely a lab tool. Needs NET_ADMIN +
// the wireguard kernel module.
//
// Usage:
//
//	wg-spike pubkey --seed <b64>
//	    print the Ed25519 public key (b64) and virtual IP for a 32-byte seed.
//
//	wg-spike up --seed <b64> --peer-pub <b64> --ifname <name> \
//	    --listen-port <p> --peer-endpoint <ip:port> [--keepalive <s>]
//	    bring the interface up and block until SIGINT/SIGTERM, then tear down.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/wg"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "pubkey":
		cmdPubkey(os.Args[2:])
	case "up":
		cmdUp(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	log.Fatalf("usage:\n  wg-spike pubkey --seed <b64>\n  wg-spike up --seed <b64> --peer-pub <b64> --ifname <name> --listen-port <p> --peer-endpoint <ip:port> [--keepalive <s>]")
}

func mustSeed(b64 string) ed25519.PrivateKey {
	seed, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(seed) != ed25519.SeedSize {
		log.Fatalf("--seed must be base64 of %d bytes: %v", ed25519.SeedSize, err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func cmdPubkey(args []string) {
	fs := flag.NewFlagSet("pubkey", flag.ExitOnError)
	seed := fs.String("seed", "", "base64 32-byte Ed25519 seed")
	_ = fs.Parse(args)
	priv := mustSeed(*seed)
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Printf("%s %s\n", base64.StdEncoding.EncodeToString(pub), crypto.VirtualIP(pub))
}

func cmdUp(args []string) {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	seed := fs.String("seed", "", "base64 32-byte Ed25519 seed (this node's identity)")
	peerPubB64 := fs.String("peer-pub", "", "base64 Ed25519 public key of the peer")
	ifname := fs.String("ifname", "bn-wg0", "interface name")
	listenPort := fs.Int("listen-port", 51820, "UDP listen port")
	peerEndpoint := fs.String("peer-endpoint", "", "peer underlay endpoint ip:port")
	keepalive := fs.Int("keepalive", 0, "persistent keepalive seconds (0=off)")
	_ = fs.Parse(args)

	priv := mustSeed(*seed)
	pub := priv.Public().(ed25519.PublicKey)

	peerPub, err := base64.StdEncoding.DecodeString(*peerPubB64)
	if err != nil || len(peerPub) != ed25519.PublicKeySize {
		log.Fatalf("--peer-pub must be base64 of %d bytes: %v", ed25519.PublicKeySize, err)
	}
	peerEd := ed25519.PublicKey(peerPub)

	endpoint, err := netip.ParseAddrPort(*peerEndpoint)
	if err != nil {
		log.Fatalf("--peer-endpoint: %v", err)
	}

	peerX, err := crypto.X25519FromEd25519Public(peerEd)
	if err != nil {
		log.Fatalf("derive peer X25519: %v", err)
	}

	selfVIP := crypto.VirtualIP(pub)
	peerVIP := crypto.VirtualIP(peerEd)

	cfg := wg.Config{
		IfName:     *ifname,
		PrivateKey: crypto.X25519FromEd25519Private(priv),
		ListenPort: *listenPort,
		Address:    netip.PrefixFrom(selfVIP, 16), // connected route over the overlay
		Peer: wg.Peer{
			PublicKey:  peerX,
			Endpoint:   endpoint,
			AllowedIPs: []netip.Prefix{netip.PrefixFrom(peerVIP, 32)},
			Keepalive:  uint16(*keepalive),
		},
	}

	down, err := wg.Up(cfg)
	if err != nil {
		log.Fatalf("wg.Up: %v", err)
	}
	fmt.Printf("READY ifname=%s self-vip=%s peer-vip=%s listen=%d peer-endpoint=%s\n",
		*ifname, selfVIP, peerVIP, *listenPort, endpoint)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	if err := down(); err != nil {
		log.Fatalf("teardown: %v", err)
	}
	fmt.Println("DOWN")
}
