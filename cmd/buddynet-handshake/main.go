// Command buddynet-handshake is a single-purpose matchmaking server: it runs ONLY
// the BuddyNet handshake (rendezvous) control plane and nothing else. It exists so
// a PUBLIC coordinator (e.g. handshake.buddynet.io) can be operated with the
// smallest possible footprint and the strongest possible "sees nothing, stores
// nothing" guarantees:
//
//   - It cannot relay, forward, or otherwise touch tunnel data — that code is not
//     wired here at all (no --role switch, no relay endpoint). The only thing on
//     the wire is REGISTER → signed PEER_LIST matchmaking.
//   - It is STATELESS by construction: the registry is in-memory and bounded
//     (entries expire); nothing is written to disk. Run it with a read-only root
//     filesystem and no state directory.
//   - Its one secret — the Ed25519 identity that signs PEER_LISTs and that buddies
//     pin — is supplied at runtime via --key pointing at an injected credential
//     (systemd LoadCredential / a tmpfs mount / a secret store), so the public box
//     itself persists nothing sensitive. Keep the durable copy in your hardened
//     store and inject it; back it up (losing it forces every buddy to re-pin).
//   - It runs OPEN (no client allowlist): a public server cannot approve everyone,
//     and pairing is already gated by the shared one-time token plus SAS/peer-key
//     pinning on the buddies. Abuse is bounded by the built-in UDP source-address
//     cookie, global + per-source rate limits, and the bounded registry caps.
//
// For a private or combined coordinator (handshake + relay on your own VPS), use
// the full `buddynet --role=handshake[,relay]` binary instead; this one is the
// deliberately minimal public-service variant.
package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/role"
	"github.com/tzero78/buddynet/pkg/protocol"
)

// version is stamped at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	listen := flag.String("listen", envOr("BUDDYNET_LISTEN", protocol.DefaultHandshakeAddr),
		"UDP address to listen on")
	keyPath := flag.String("key", os.Getenv("BUDDYNET_KEY_PATH"),
		"path to the Ed25519 identity key (buddies pin this; created if missing, but for a public server inject it read-only and back it up). Empty = EPHEMERAL (regenerates on restart — buddies would have to re-pin; not for production).")
	ttl := flag.Duration("ttl", 0, "liveness window for a registration (0 = default 10s)")
	allowCIDR := flag.String("allow-cidr", "",
		"comma-separated CIDRs allowed to reach the server; other sources are dropped before any crypto (empty = open to all, the norm for a public server)")
	debug := flag.Bool("debug", false, "verbose, security-sensitive logging (avoid on a public server — leaks pairing metadata)")

	flag.Usage = usage
	flag.Parse()

	// `identity` subcommand: print this server's public key (the value buddies pin
	// with --server-key, and that you bake into a pre-pinned client) and exit.
	if flag.Arg(0) == "identity" {
		if *keyPath == "" {
			fmt.Fprintln(os.Stderr, "error: set --key <path> to read the persistent identity")
			os.Exit(1)
		}
		priv, _, err := bcrypto.LoadOrCreateKey(*keyPath)
		if err != nil {
			log.Fatalf("identity key: %v", err)
		}
		fmt.Println(bcrypto.PubKeyB64(priv.Public().(ed25519.PublicKey)))
		return
	}

	allowed, err := parseCIDRs(*allowCIDR)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	// Surface the pinned identity up front so the operator can distribute/pre-pin
	// it, and warn loudly if the key is ephemeral (public servers must be stable).
	if *keyPath != "" {
		if priv, created, err := bcrypto.LoadOrCreateKey(*keyPath); err == nil {
			pub := bcrypto.PubKeyB64(priv.Public().(ed25519.PublicKey))
			log.Printf("handshake identity (buddies pin this --server-key): %s", pub)
			if created {
				log.Printf("WARNING: generated a NEW identity at %s — every buddy must (re-)pin it", *keyPath)
			}
		}
	} else {
		log.Print("WARNING: no --key: identity is EPHEMERAL and changes on restart (buddies would have to re-pin). Inject a persistent key for a public server.")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("buddynet-handshake %s starting (handshake-only, stateless; listen=%s)", version, *listen)

	// NOTE: RelayEndpoint and Authorized are intentionally NOT wired — this binary
	// never relays and runs open. Use the full binary for those.
	if err := role.Handshake(ctx, role.HandshakeConfig{
		Listen:     *listen,
		KeyPath:    *keyPath,
		TTL:        *ttl,
		Debug:      *debug,
		AllowCIDRs: allowed,
	}); err != nil {
		log.Fatalf("handshake: %v", err)
	}
}

// parseCIDRs splits a comma-separated --allow-cidr value into validated prefixes;
// a bare IP is accepted as a host route. Empty yields nil (open to all).
func parseCIDRs(s string) ([]netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if p, err := netip.ParsePrefix(part); err == nil {
			out = append(out, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("invalid --allow-cidr entry %q (want a CIDR like 10.0.0.0/8 or an IP)", part)
		}
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func usage() {
	fmt.Fprintf(os.Stderr, `buddynet-handshake %s — single-purpose PUBLIC matchmaking server.

Runs ONLY the handshake control plane: no relay, no data path, no client
allowlist, nothing written to disk. Its identity key is the value buddies pin.

Usage:
  buddynet-handshake --key /run/credentials/id.key            # run the server
  buddynet-handshake --key /path/id.key identity              # print the pinned key

Recommended (stateless, key injected read-only):
  buddynet-handshake --key "$CREDENTIALS_DIRECTORY/id.key"

Flags:
`, version)
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, "\nFor a private/combined coordinator use: buddynet --role=handshake[,relay]\n")
}
