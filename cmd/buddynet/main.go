// Command buddynet is the single BuddyNet binary. One executable, three roles,
// chosen explicitly with --role (never auto-detected):
//
//	buddynet --role=buddy      # ordinary peer; NAT is fine
//	buddynet --role=relay      # public IP; blindly forwards encrypted sessions
//	buddynet --role=handshake  # bootstrap/matchmaking server on a VPS
//
// Every binary carries all three roles; a buddy contains the relay and
// handshake code as dormant fallback. BuddyPeer — two buddies and one handshake
// server — is just the two-peer case of BuddyNet:
//
//	buddynet --role=buddy --invite            # mint a token, wait for the buddy
//	buddynet --role=buddy --join=TOKEN ...     # join with that token
//
// Security: each node has an Ed25519 identity that is also its TLS cert key and
// the seed of its deterministic virtual IP. The handshake server signs every
// PEER_LIST; buddies pin the server key and then pin each other, so a man in the
// middle on the control path cannot impersonate a peer. The relay only ever sees
// encrypted QUIC packets.
package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/role"
	"github.com/tzero78/buddynet/internal/secret"
	"github.com/tzero78/buddynet/pkg/protocol"
)

const appName = "buddynet"

// version is overridable at build time:
//
//	go build -ldflags="-X main.version=1.2.3" ./cmd/buddynet
var version = "0.1.0"

func main() {
	log.SetFlags(log.Ltime)

	roleFlag := flag.String("role", "", "node role: buddy | relay | handshake (required; never auto-detected)")
	keyPath := flag.String("key", "", "path to this node's Ed25519 identity key (created if missing; empty = ephemeral)")
	listen := flag.String("listen", "", "UDP address to listen on (handshake default [::]:51820, relay default [::]:51821)")
	relayListenFlag := flag.String("relay-listen", "", "relay: UDP address for the relay when combined with another role on one node (default [::]:51821)")
	ttl := flag.Duration("ttl", 0, "liveness/idle window for server-side state (handshake 10s, relay 60s default)")
	authorized := flag.String("authorized", "", "handshake: client allowlist file (approval mode); also used by the approve/list/revoke/allowclient subcommands")
	relayEndpoint := flag.String("relay-endpoint", "", "handshake: advertise this relay host:port to paired buddies as a fallback (set when the VPS also runs --role=relay)")
	debug := flag.Bool("debug", false, "handshake: verbose logging of parked/dropped packets (not for production)")

	server := flag.String("server", "", "buddy: handshake server host:port [required]")
	serverKey := flag.String("server-key", "", "buddy: handshake server Ed25519 public key, base64 (pin it) [required]")
	token := flag.String("token", "", "buddy: shared pairing token agreed with your buddy")
	peerKey := flag.String("peer-key", "", "buddy: pin the buddy's Ed25519 public key, base64 (strongest)")
	knownPeers := flag.String("known-peers", role.DefaultKnownPeersPath(), "buddy: trust-on-first-use store (SSH-style; learns the buddy key on first connect)")
	insecure := flag.Bool("insecure", false, "buddy: do NOT verify the buddy's identity (unsafe; testing only)")
	code := flag.String("code", "", "buddy: enrollment code for an allowlist handshake server")
	peersPath := flag.String("peers", role.DefaultPeersPath(), "buddy: offline peer cache (peers.json) used when the handshake server is unreachable")
	localListen := flag.String("L", "", "buddy: local address to expose (TCP host:port or unix:/path); connections are forwarded to the peer")
	forward := flag.String("forward", "", "buddy: local service to forward incoming peer streams to (TCP host:port or unix:/path)")
	punchDur := flag.Duration("punch", 2*time.Second, "buddy: how long to hole-punch before bringing up QUIC")
	idleTimeout := flag.Duration("idle-timeout", 60*time.Second, "buddy: tear down the tunnel after this long with no traffic at all")
	status := flag.Bool("status", false, "buddy: probe whether the buddy is online and reachable, then exit")
	invite := flag.Bool("invite", false, "buddy: mint a fresh pairing token, print it, and wait for your buddy to join")
	join := flag.String("join", "", "buddy: join using the pairing token your buddy gave you (alias for --token)")

	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = usage
	flag.Parse()

	switch {
	case *showVersion || flag.Arg(0) == "version":
		fmt.Printf("%s %s\n", appName, version)
		return
	case flag.Arg(0) == "help":
		usage()
		return
	case flag.Arg(0) == "gen-token":
		genToken()
		return
	case flag.Arg(0) == "identity":
		printIdentity(*keyPath)
		return
	}
	// Handshake allowlist admin subcommands operate on --authorized and exit.
	if cmd := flag.Arg(0); cmd == "approve" || cmd == "allowclient" || cmd == "list" || cmd == "revoke" {
		os.Exit(runAuthCmd(*authorized, cmd, flag.Args()[1:]))
	}

	// Env fallbacks (handy for systemd; keeps the secret token out of argv/ps).
	*roleFlag = orEnv(*roleFlag, "BUDDYNET_ROLE")
	*server = orEnv(*server, "BUDDYNET_SERVER")
	*serverKey = orEnv(*serverKey, "BUDDYNET_SERVER_KEY")
	*token = orEnv(*token, "BUDDYNET_TOKEN")
	*peerKey = orEnv(*peerKey, "BUDDYNET_PEER_KEY")
	*knownPeers = orEnv(*knownPeers, "BUDDYNET_KNOWN_PEERS")
	*code = orEnv(*code, "BUDDYNET_CODE")

	// A node may run several roles at once, comma-separated (e.g. on a VPS:
	// --role=handshake,relay). Each runs concurrently on its own port.
	roles, rerr := parseRoles(*roleFlag)
	if rerr != nil {
		fmt.Fprintln(os.Stderr, "error:", rerr)
		usage()
		os.Exit(2)
	}
	hasBuddy, hasServer := false, false
	for _, r := range roles {
		if r == protocol.RoleBuddy {
			hasBuddy = true
		} else {
			hasServer = true
		}
	}
	// Server roles want timestamped UTC logs; a lone buddy keeps short local times.
	if hasServer {
		log.SetFlags(log.LstdFlags | log.LUTC)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if hasBuddy {
		if *join != "" {
			*token = *join
		}
		if *invite {
			*token = mintInviteToken()
		}
	}
	bArgs := buddyArgs{
		server: *server, serverKey: *serverKey, token: *token, peerKey: *peerKey,
		knownPeers: *knownPeers, insecure: *insecure, code: *code, keyPath: *keyPath,
		peersPath: *peersPath, localListen: *localListen, forward: *forward,
		punchDur: *punchDur, idleTimeout: *idleTimeout, status: *status,
	}

	// --status is a one-shot probe that only makes sense for a lone buddy.
	if *status {
		if len(roles) != 1 || !hasBuddy {
			fmt.Fprintln(os.Stderr, "error: --status is only valid with --role=buddy alone")
			os.Exit(2)
		}
		runBuddy(ctx, bArgs) // exits with the probe's status code
		return
	}

	// Fail fast on an incomplete buddy config before any role starts.
	if hasBuddy {
		bArgs.validate()
	}

	// Run every selected role concurrently; the first hard failure cancels the
	// rest and is reported.
	var wg sync.WaitGroup
	var once sync.Once
	var runErr error
	fail := func(label string, err error) {
		if err != nil {
			once.Do(func() { runErr = fmt.Errorf("%s: %w", label, err); stop() })
		}
	}
	for _, r := range roles {
		wg.Add(1)
		go func(r protocol.Role) {
			defer wg.Done()
			switch r {
			case protocol.RoleHandshake:
				fail("handshake", role.Handshake(ctx, role.HandshakeConfig{
					Listen: orDefault(*listen, "[::]:51820"), KeyPath: *keyPath,
					Authorized: *authorized, TTL: *ttl, Debug: *debug, RelayEndpoint: *relayEndpoint,
				}))
			case protocol.RoleRelay:
				fail("relay", role.Relay(ctx, role.RelayConfig{
					Listen: relayListen(*relayListenFlag, *listen, roles), TTL: *ttl,
				}))
			case protocol.RoleBuddy:
				fail("buddy", role.Buddy(ctx, bArgs.config()))
			}
		}(r)
	}
	wg.Wait()
	if runErr != nil {
		log.Fatalf("%v", runErr)
	}
}

// parseRoles splits a comma-separated --role into a deduplicated, validated set,
// preserving order. An empty value or any unknown role is an error.
func parseRoles(s string) ([]protocol.Role, error) {
	if strings.TrimSpace(s) == "" {
		return nil, fmt.Errorf("--role is required (buddy | relay | handshake; comma-separate to combine)")
	}
	seen := map[protocol.Role]bool{}
	var out []protocol.Role
	for _, part := range strings.Split(s, ",") {
		r := protocol.Role(strings.TrimSpace(part))
		switch r {
		case protocol.RoleBuddy, protocol.RoleRelay, protocol.RoleHandshake:
			if !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		case "":
			continue
		default:
			return nil, fmt.Errorf("unknown --role %q (want buddy | relay | handshake)", string(r))
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--role is required (buddy | relay | handshake)")
	}
	return out, nil
}

// relayListen resolves the relay's listen address. It prefers --relay-listen;
// failing that it uses --listen only when relay is the sole role (so a lone
// `--role=relay --listen ...` still works), and otherwise the default — which
// keeps the relay off the handshake's port when both run on one node.
func relayListen(relayFlag, listen string, roles []protocol.Role) string {
	if relayFlag != "" {
		return relayFlag
	}
	if listen != "" && len(roles) == 1 {
		return listen
	}
	return "[::]:51821"
}

func orDefault(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

type buddyArgs struct {
	server, serverKey, token, peerKey, knownPeers, code, keyPath, peersPath string
	localListen, forward                                                    string
	insecure, status                                                        bool
	punchDur, idleTimeout                                                   time.Duration
}

// config maps the parsed flags onto the role package's BuddyConfig.
func (a buddyArgs) config() role.BuddyConfig {
	return role.BuddyConfig{
		Server: a.server, ServerKey: a.serverKey, Token: a.token,
		PeerKey: a.peerKey, KnownPeers: a.knownPeers, Insecure: a.insecure,
		Code: a.code, KeyPath: a.keyPath, PeersPath: a.peersPath,
		LocalListen: a.localListen, Forward: a.forward,
		PunchDur: a.punchDur, IdleTimeout: a.idleTimeout, Status: a.status,
	}
}

// validate rejects an incomplete buddy configuration (exits 2). Run before any
// role starts so the error is immediate, whether buddy runs alone or alongside
// another role.
func (a buddyArgs) validate() {
	if a.server == "" || a.serverKey == "" || a.token == "" {
		fmt.Fprintln(os.Stderr, "error: --role=buddy needs --server, --server-key and --token (or --invite/--join for the token)")
		if a.token == "" {
			fmt.Fprintf(os.Stderr, "no token yet? mint one (both buddies use the same value):\n  %s gen-token\n", appName)
		}
		os.Exit(2)
	}
	if !a.status && a.localListen == "" && a.forward == "" {
		fmt.Fprintln(os.Stderr, "error: set at least one of -L or -forward (otherwise the tunnel carries nothing)")
		os.Exit(2)
	}
}

// runBuddy runs the one-shot --status probe and exits with its result code.
func runBuddy(ctx context.Context, a buddyArgs) {
	a.validate()
	if err := role.Buddy(ctx, a.config()); err != nil {
		os.Exit(1) // probe maps "offline / unreachable / untrusted" to non-zero
	}
}

// mintInviteToken mints a fresh pairing token, shows it (reveal-and-hide on a
// terminal, plain when piped), and returns it so the inviting buddy keeps
// running and waits for the partner to join.
func mintInviteToken() string {
	tok, err := secret.NewToken()
	if err != nil {
		log.Fatalf("could not mint token: %v", err)
	}
	if secret.Interactive() {
		fmt.Fprint(os.Stderr, "Invite token (give the SAME value to your buddy as --join). It's a bearer secret:\n")
		secret.RevealUntilKey(tok)
		fmt.Fprintln(os.Stderr, "Token hidden — now waiting for your buddy to join...")
	} else {
		fmt.Println(tok)
	}
	return tok
}

func genToken() {
	tok, err := secret.NewToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: could not read random bytes: %v\n", err)
		os.Exit(1)
	}
	if !secret.Interactive() {
		fmt.Println(tok)
		return
	}
	fmt.Fprint(os.Stderr, `New pairing token (384-bit). Both buddies use the SAME value as --token (or
--join). It's a bearer secret — keep it off the command line (prefer a 0600
file or BUDDYNET_TOKEN) and pin each other with --peer-key.
`)
	secret.RevealUntilKey(tok)
	fmt.Fprintln(os.Stderr, "Token hidden — copy it to your buddy before you lose it.")
}

// printIdentity prints the base64 public key for --key (to pin in buddies).
func printIdentity(keyPath string) {
	if keyPath == "" {
		fmt.Fprintln(os.Stderr, "error: set --key <path> to read the persistent identity")
		os.Exit(2)
	}
	priv, _, err := bcrypto.LoadOrCreateKey(keyPath)
	if err != nil {
		log.Fatalf("identity key: %v", err)
	}
	fmt.Println(bcrypto.PubKeyB64(priv.Public().(ed25519.PublicKey)))
}

func runAuthCmd(path, cmd string, args []string) int {
	if path == "" {
		fmt.Fprintln(os.Stderr, "error: --authorized <file> is required for "+cmd)
		return 2
	}
	var err error
	switch cmd {
	case "approve":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "usage: --authorized <file> approve <client-pubkey> [label]")
			return 2
		}
		label := ""
		if len(args) > 1 {
			label = joinArgs(args[1:])
		}
		err = role.ApproveKey(path, args[0], label)
	case "allowclient":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "usage: --authorized <file> allowclient <enrollment-code>")
			return 2
		}
		err = role.AllowClient(path, args[0])
	case "list":
		err = role.ListKeys(path)
	case "revoke":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "usage: --authorized <file> revoke <client-pubkey>")
			return 2
		}
		err = role.RevokeKey(path, args[0])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func joinArgs(a []string) string {
	out := ""
	for i, s := range a {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}

func orEnv(v, key string) string {
	if v != "" {
		return v
	}
	return os.Getenv(key)
}

func usage() {
	w := flag.CommandLine.Output()
	fmt.Fprintf(w, `%s %s — one binary, three roles (BuddyNet)

USAGE
  %s --role=handshake [--listen [::]:51820] [--key PATH] [--authorized FILE]
  %s --role=relay     [--listen [::]:51821]
  %s --role=buddy --server H:P --server-key KEY --token TOK (-L addr | -forward addr)
  %s --role=handshake,relay ...       # combine roles on one node (own ports)

  %s --role=buddy --invite ...        # mint a token and wait (BuddyPeer)
  %s --role=buddy --join=TOKEN ...     # join with that token
  %s --role=buddy ... --status         # is my buddy online and reachable?
  %s gen-token                         # mint a strong shared token
  %s --role=handshake --key PATH identity   # print the server public key to pin
  %s version

FLAGS
`, appName, version, appName, appName, appName, appName, appName, appName, appName, appName, appName, appName)
	flag.PrintDefaults()
	fmt.Fprintf(w, `
EXAMPLE (BuddyPeer: rsync backup between two sites)
  # On the VPS (public IP): the bootstrap server.
  %s --role=handshake --key /var/lib/%s/id.key
  %s --role=handshake --key /var/lib/%s/id.key identity   # prints KEY to pin

  # Inviter (machine being backed up TO; runs rsync daemon on :873):
  %s --role=buddy --server vps:51820 --server-key KEY --invite \
      -forward 127.0.0.1:873

  # Joiner (machine doing the backup):
  %s --role=buddy --server vps:51820 --server-key KEY --join=TOKEN \
      -L 127.0.0.1:9000 &
  rsync -a /data/ rsync://localhost:9000/backup/

SECURITY: pin your buddy with --peer-key (each buddy prints its identity at
startup). Without it, trust-on-first-use records the buddy key in --known-peers
and refuses later changes. See docs/ARCHITECTURE.md and docs/PROTOCOL.md.
`, appName, appName, appName, appName, appName, appName)
}
