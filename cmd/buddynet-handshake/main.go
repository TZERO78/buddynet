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
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/role"
	"github.com/tzero78/buddynet/pkg/protocol"
)

// version is stamped at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

// cliFlags is every flag this binary defines. Registered in one place so the
// flag-drift test can enumerate them from the same source main() uses — see the
// same split in cmd/buddynet: the shipped systemd unit for THIS binary passed
// --quic-handshake for a full release after v8 removed it, and the service
// exited 2 on every start (finding A-05).
type cliFlags struct {
	listen    *string
	keyPath   *string
	ttl       *time.Duration
	allowCIDR *string
	debug     *bool
}

// registerFlags defines every flag on fs and returns the parsed destinations.
func registerFlags(fs *flag.FlagSet) *cliFlags {
	return &cliFlags{
		listen: fs.String("listen", envOr("BUDDYNET_LISTEN", protocol.DefaultHandshakeAddr),
			"UDP address to listen on"),
		keyPath: fs.String("key", os.Getenv("BUDDYNET_KEY_PATH"),
			"path to the Ed25519 identity key (buddies pin this; created if missing, but for a public server inject it read-only and back it up). Empty = EPHEMERAL (regenerates on restart — buddies would have to re-pin; not for production)."),
		ttl: fs.Duration("ttl", 0, "liveness window for a registration (0 = default 10s)"),
		allowCIDR: fs.String("allow-cidr", "",
			"comma-separated CIDRs allowed to reach the server; other sources are refused before they occupy a connection slot -- after the TLS handshake QUIC already ran, not before it (empty = open to all, the norm for a public server)"),
		debug: fs.Bool("debug", false, "verbose, security-sensitive logging (avoid on a public server — leaks pairing metadata)"),
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	f := registerFlags(flag.CommandLine)

	flag.Usage = usage
	flag.Parse()

	// `identity` subcommand: print this server's public key (the value buddies pin
	// with --server-key, and that you bake into a pre-pinned client) and exit.
	// READ-ONLY — creating an identity is `init`, on purpose: a public matchmaker
	// that mints a fresh key after a lost volume is a different server to everyone
	// who pinned the old one.
	if flag.Arg(0) == "identity" {
		if *f.keyPath == "" {
			fmt.Fprintln(os.Stderr, "error: set --key <path> to read the persistent identity")
			os.Exit(1)
		}
		priv, _, err := bcrypto.LoadKey(*f.keyPath)
		if errors.Is(err, bcrypto.ErrKeyMissing) {
			fmt.Fprintf(os.Stderr, "error: %v\n\n"+
				"  Create it once (this is the only command that does):\n"+
				"      buddynet-handshake --key %s init\n\n"+
				"  If this host has run before, the key is LOST rather than absent — check the\n"+
				"  volume or credential holding it before creating a new identity.\n", err, *f.keyPath)
			os.Exit(1)
		}
		if err != nil {
			log.Fatalf("identity key: %v", err)
		}
		fmt.Println(bcrypto.PubKeyB64(priv.Public().(ed25519.PublicKey)))
		return
	}

	// `init` subcommand: create the identity, once. Refuses to replace one.
	if flag.Arg(0) == "init" {
		if *f.keyPath == "" {
			fmt.Fprintln(os.Stderr, "error: set --key <path> — `init` creates a persistent identity, so it needs somewhere to put it")
			os.Exit(1)
		}
		priv, err := bcrypto.CreateKey(*f.keyPath)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				fmt.Fprintf(os.Stderr, "error: %s already holds an identity — refusing to replace it.\n"+
					"  Print the existing one with: buddynet-handshake --key %s identity\n", *f.keyPath, *f.keyPath)
				os.Exit(1)
			}
			log.Fatalf("create identity: %v", err)
		}
		fmt.Println(bcrypto.PubKeyB64(priv.Public().(ed25519.PublicKey)))
		fmt.Fprintf(os.Stderr, "\ncreated a new identity at %s\n"+
			"  Buddies pin this key as --server-key. Back the file up: losing it makes\n"+
			"  this a DIFFERENT server to every buddy, and they all have to re-pin.\n", *f.keyPath)
		return
	}

	allowed, err := parseCIDRs(*f.allowCIDR)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	// Surface the pinned identity up front so the operator can distribute/pre-pin
	// it, and warn loudly if the key is ephemeral (public servers must be stable).
	if *f.keyPath != "" {
		priv, _, kerr := bcrypto.LoadKey(*f.keyPath)
		if errors.Is(kerr, bcrypto.ErrKeyMissing) {
			fmt.Fprintf(os.Stderr, "error: %v\n\n"+
				"  If this is the FIRST start on this host, create the identity once:\n"+
				"      buddynet-handshake --key %s init\n\n"+
				"  If this host HAS run before, the key is missing rather than absent — check\n"+
				"  that the volume or credential holding it is mounted. Starting with a new\n"+
				"  identity would lock out every buddy that pinned the old one, and this is a\n"+
				"  PUBLIC matchmaker: its whole job is to be the one key everybody pinned.\n",
				kerr, *f.keyPath)
			os.Exit(1)
		}
		if kerr == nil {
			log.Printf("handshake identity (buddies pin this --server-key): %s",
				bcrypto.PubKeyB64(priv.Public().(ed25519.PublicKey)))
		}
	} else {
		log.Print("WARNING: no --key: identity is EPHEMERAL and changes on restart (buddies would have to re-pin). Inject a persistent key for a public server.")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("buddynet-handshake %s starting (handshake-only, stateless; listen=%s)", version, *f.listen)

	// NOTE: RelayEndpoint and Authorized are intentionally NOT wired — this binary
	// never relays and runs open. Use the full binary for those.
	if err := role.Handshake(ctx, role.HandshakeConfig{
		Listen:     *f.listen,
		KeyPath:    *f.keyPath,
		TTL:        *f.ttl,
		Debug:      *f.debug,
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
