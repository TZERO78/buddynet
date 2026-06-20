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
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
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
	listen := flag.String("listen", "", fmt.Sprintf("UDP address to listen on (handshake default %s, relay default %s)", protocol.DefaultHandshakeAddr, protocol.DefaultRelayAddr))
	relayListenFlag := flag.String("relay-listen", "", fmt.Sprintf("relay: UDP address for the relay when combined with another role on one node (default %s)", protocol.DefaultRelayAddr))
	allowCIDR := flag.String("allow-cidr", "", "relay/handshake: comma-separated CIDRs allowed to reach the server role(s); other sources are dropped before any crypto (empty = open to all)")
	ttl := flag.Duration("ttl", 0, "liveness/idle window for server-side state (handshake 10s, relay 60s default)")
	authorized := flag.String("authorized", "", "handshake: client allowlist file (approval mode); also used by the approve/list/revoke/allowclient subcommands")
	relayEndpoint := flag.String("relay-endpoint", "", "handshake: advertise this relay host:port to paired buddies as a fallback (set when the VPS also runs --role=relay)")
	debug := flag.Bool("debug", false, "handshake: verbose logging of parked/dropped packets (not for production)")
	quicHandshake := flag.Bool("quic-handshake", false, "use QUIC (not plain UDP) for the handshake control plane; set the SAME on the server and every buddy")

	server := flag.String("server", "", "buddy: handshake server host:port [required]")
	serverKey := flag.String("server-key", "", "buddy: handshake server Ed25519 public key, base64 (pin it) [required]")
	token := flag.String("token", "", "buddy: legacy fixed pairing token, reused on every reconnect (--invite/--join instead use a one-time token + a stored session secret)")
	peerKey := flag.String("peer-key", "", "buddy: pin the buddy's Ed25519 public key, base64 (strongest)")
	knownPeers := flag.String("known-peers", role.DefaultKnownPeersPath(), "buddy: trust-on-first-use store (SSH-style; learns the buddy key on first connect)")
	insecure := flag.Bool("insecure", false, "buddy: do NOT verify the buddy's identity (unsafe; testing only)")
	code := flag.String("code", "", "buddy: enrollment code for an allowlist handshake server")
	peersPath := flag.String("peers", role.DefaultPeersPath(), "buddy: offline peer cache (peers.json) used when the handshake server is unreachable")
	peersFile := flag.String("peers-file", "", "buddy: BuddyParty manifest, one line '<peer-key-b64> [bootstrap-token]' per buddy; maintains a tunnel to every listed buddy at once (Model A, each pinned). Use --vip-listen to route to them. Mutually exclusive with --invite/--join/--token/--lazy")
	localListen := flag.String("L", "", "buddy: local address to expose (TCP host:port or unix:/path); connections are forwarded to the peer")
	vipListen := flag.String("vip-listen", "", "buddy: port for per-buddy virtual-IP routing; binds each connected buddy's VIP (10.66.X.Y) on lo and forwards <name>.buddy:port to that buddy's tunnel. Scales to many buddies (unlike -L); needs NET_ADMIN/root, degrades gracefully if missing")
	forward := flag.String("forward", "", "buddy: local service to forward incoming peer streams to (TCP host:port or unix:/path)")
	punchDur := flag.Duration("punch", 2*time.Second, "buddy: how long to hole-punch before bringing up QUIC")
	idleTimeout := flag.Duration("idle-timeout", 60*time.Second, "buddy: tear down the tunnel after this long with no traffic at all")
	reauthInterval := flag.Duration("reauth-interval", 0, "buddy: periodically rebuild the tunnel so a revocation/token rotation takes effect within this long (0 = off; a direct tunnel cannot be cancelled centrally). May interrupt long transfers.")
	noInteractive := flag.Bool("no-interactive", false, "buddy: never prompt for first-contact SAS confirmation; refuse to learn a NEW buddy key (pin it with --peer-key instead). For daemons/Unraid.")
	sasTimeout := flag.Duration("sas-timeout", 30*time.Second, "buddy: how long to wait for SAS y/N confirmation before treating it as a mismatch (abort)")
	inviteTimeout := flag.Duration("invite-timeout", 15*time.Minute, "buddy: give up the first pairing (--invite/--join) after this long; the invite token is one-time")
	status := flag.Bool("status", false, "buddy: probe whether the buddy is online and reachable, then exit (codes: 0 reachable, 3 unreachable, 4 offline, 5 untrusted, 1 local error)")
	invite := flag.Bool("invite", false, "buddy: mint a ONE-TIME invite token (valid until first pairing, see --invite-timeout), print it, and wait; afterwards reconnects use a stored session secret")
	join := flag.String("join", "", "buddy: join with the one-time invite token your buddy gave you; on success a session secret is stored for reconnects")
	name := flag.String("name", "", "buddy: self-asserted .buddy hostname (e.g. --name alice → reachable as alice.buddy); letters/digits/hyphens only, max 63 chars")
	dnsFlag := flag.Bool("dns", false, "buddy: start a .buddy stub resolver on 127.0.0.153:53 (needs CAP_NET_BIND_SERVICE or root; degrades gracefully if unavailable)")
	lazyFlag := flag.Bool("lazy", false, "buddy: bind the -L listener immediately but defer the QUIC tunnel until the first connection arrives (requires -L)")

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
	// `peers` subcommands let a node curate its OWN buddy manifest (--peers-file,
	// + --known-peers for revocation) and exit: `peers <list|add|remove> [args]`.
	// Self-management only — there is no admin authority over other nodes.
	if flag.Arg(0) == "peers" {
		os.Exit(runPeersCmd(*peersFile, *knownPeers, flag.Args()[1:]))
	}

	// Env fallbacks (handy for systemd; keeps the secret token out of argv/ps).
	*roleFlag = orEnv(*roleFlag, "BUDDYNET_ROLE")
	*server = orEnv(*server, "BUDDYNET_SERVER")
	*serverKey = orEnv(*serverKey, "BUDDYNET_SERVER_KEY")
	*token = orEnv(*token, "BUDDYNET_TOKEN")
	*peerKey = orEnv(*peerKey, "BUDDYNET_PEER_KEY")
	*knownPeers = orEnv(*knownPeers, "BUDDYNET_KNOWN_PEERS")
	*code = orEnv(*code, "BUDDYNET_CODE")
	*name = orEnv(*name, "BUDDYNET_NAME")
	if !*dnsFlag {
		if v := os.Getenv("BUDDYNET_DNS"); v == "1" || v == "true" {
			*dnsFlag = true
		}
	}
	if !*quicHandshake {
		if v := os.Getenv("BUDDYNET_QUIC"); v == "1" || v == "true" {
			*quicHandshake = true
		}
	}
	if !*lazyFlag {
		if v := os.Getenv("BUDDYNET_LAZY"); v == "1" || v == "true" {
			*lazyFlag = true
		}
	}

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

	ephemeral := false
	if hasBuddy {
		if *join != "" {
			*token = *join
			ephemeral = true
		}
		if *invite {
			*token = mintInviteToken()
			ephemeral = true
		}
	}
	bArgs := buddyArgs{
		server: *server, serverKey: *serverKey, token: *token, peerKey: *peerKey,
		knownPeers: *knownPeers, insecure: *insecure, code: *code, keyPath: *keyPath,
		peersPath: *peersPath, peersFile: *peersFile, localListen: *localListen, forward: *forward, vipListen: *vipListen,
		punchDur: *punchDur, idleTimeout: *idleTimeout, status: *status,
		// Interactive only when not explicitly disabled AND a human is at the
		// terminal; otherwise an unknown buddy key is refused, never learned blind.
		interactive: !*noInteractive && secret.Interactive(), sasTimeout: *sasTimeout,
		ephemeral: ephemeral, inviteTimeout: *inviteTimeout, quic: *quicHandshake,
		reauthInterval: *reauthInterval,
		name:           *name, dns: *dnsFlag, lazy: *lazyFlag,
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

	// Parse the optional relay allowlist up front so a bad CIDR fails fast.
	allowedCIDRs, cerr := parseCIDRs(*allowCIDR)
	if cerr != nil {
		fmt.Fprintln(os.Stderr, "error:", cerr)
		os.Exit(2)
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
					Listen: orDefault(*listen, protocol.DefaultHandshakeAddr), KeyPath: *keyPath,
					Authorized: *authorized, TTL: *ttl, Debug: *debug, RelayEndpoint: *relayEndpoint,
					QUIC: *quicHandshake, AllowCIDRs: allowedCIDRs,
				}))
			case protocol.RoleRelay:
				fail("relay", role.Relay(ctx, role.RelayConfig{
					Listen: relayListen(*relayListenFlag, *listen, roles), TTL: *ttl,
					AllowCIDRs: allowedCIDRs,
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

// parseCIDRs splits a comma-separated --allow-cidr value into validated
// prefixes. An empty value yields nil (relay open to all). A bare IP is accepted
// as a /32 or /128 host route. Any malformed entry is a hard error.
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
	return protocol.DefaultRelayAddr
}

func orDefault(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

type buddyArgs struct {
	server, serverKey, token, peerKey, knownPeers, code, keyPath, peersPath string
	peersFile                                                               string
	localListen, forward, vipListen, name                                   string
	insecure, status, interactive, ephemeral, quic, dns, lazy               bool
	punchDur, idleTimeout, sasTimeout, inviteTimeout, reauthInterval        time.Duration
}

// config maps the parsed flags onto the role package's BuddyConfig.
func (a buddyArgs) config() role.BuddyConfig {
	return role.BuddyConfig{
		Server: a.server, ServerKey: a.serverKey, Token: a.token,
		PeerKey: a.peerKey, KnownPeers: a.knownPeers, Insecure: a.insecure,
		Code: a.code, KeyPath: a.keyPath, PeersPath: a.peersPath, PeersFile: a.peersFile,
		LocalListen: a.localListen, Forward: a.forward, VIPListen: a.vipListen,
		PunchDur: a.punchDur, IdleTimeout: a.idleTimeout, Status: a.status,
		Interactive: a.interactive, SASTimeout: a.sasTimeout,
		Ephemeral: a.ephemeral, InviteTimeout: a.inviteTimeout, QUIC: a.quic,
		ReauthInterval: a.reauthInterval,
		Name:           a.name, DNS: a.dns, Lazy: a.lazy,
	}
}

// validate rejects an incomplete buddy configuration (exits 2). Run before any
// role starts so the error is immediate, whether buddy runs alone or alongside
// another role.
func (a buddyArgs) validate() {
	if a.server == "" || a.serverKey == "" {
		fmt.Fprintln(os.Stderr, "error: --role=buddy needs --server and --server-key")
		os.Exit(2)
	}
	// A token is needed for a first pairing (--invite/--join/--token) and for a
	// --status probe; once paired, a stored session lets you reconnect with none.
	if a.status && a.token == "" {
		fmt.Fprintln(os.Stderr, "error: --status needs --token (the pairing token)")
		os.Exit(2)
	}
	if !a.status && a.localListen == "" && a.forward == "" && a.vipListen == "" {
		fmt.Fprintln(os.Stderr, "error: set at least one of -L, --vip-listen or -forward (otherwise the tunnel carries nothing)")
		os.Exit(2)
	}
	if a.vipListen != "" {
		if _, err := net.LookupPort("tcp", a.vipListen); err != nil {
			fmt.Fprintf(os.Stderr, "error: --vip-listen %q is not a valid TCP port\n", a.vipListen)
			os.Exit(2)
		}
	}
	// --peers-file is the multi-buddy manifest path; it owns pairing for every
	// listed buddy, so it cannot be combined with the single-peer pairing modes.
	if a.peersFile != "" {
		switch {
		case a.token != "" || a.peerKey != "":
			fmt.Fprintln(os.Stderr, "error: --peers-file cannot be combined with --token/--peer-key (the manifest pins and pairs each buddy)")
			os.Exit(2)
		case a.ephemeral:
			fmt.Fprintln(os.Stderr, "error: --peers-file cannot be combined with --invite/--join (use a bootstrap token per line in the manifest)")
			os.Exit(2)
		case a.lazy:
			fmt.Fprintln(os.Stderr, "error: --peers-file cannot be combined with --lazy")
			os.Exit(2)
		}
	}
	if a.lazy && a.localListen == "" {
		fmt.Fprintln(os.Stderr, "error: --lazy requires -L (there is no listener to keep open without it)")
		os.Exit(2)
	}
}

// runBuddy runs the one-shot --status probe and exits with its result code:
// 0 reachable, 3 unreachable, 4 offline, 5 untrusted, 1 local error.
func runBuddy(ctx context.Context, a buddyArgs) {
	a.validate()
	err := role.Buddy(ctx, a.config())
	if err == nil {
		return // online and directly reachable
	}
	var pe *role.ProbeError
	if errors.As(err, &pe) {
		os.Exit(pe.Code) // offline / unreachable / untrusted, by distinct code
	}
	os.Exit(1) // local failure (socket / DNS)
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

// runPeersCmd dispatches `peers <list|add|remove>` against the --peers-file
// manifest (and --known-peers for revocation), then exits.
func runPeersCmd(peersFile, knownPeers string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: --peers-file <file> peers <list|add|remove> [args]")
		return 2
	}
	var err error
	switch args[0] {
	case "list":
		err = role.PeersList(peersFile, knownPeers)
	case "add":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: --peers-file <file> peers add <peer-pubkey> [bootstrap-token]")
			return 2
		}
		token := ""
		if len(args) > 2 {
			token = args[2]
		}
		err = role.PeersAdd(peersFile, args[1], token)
	case "remove":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: --peers-file <file> peers remove <peer-pubkey>")
			return 2
		}
		err = role.PeersRemove(peersFile, knownPeers, args[1])
	default:
		fmt.Fprintf(os.Stderr, "unknown peers subcommand %q (want list|add|remove)\n", args[0])
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
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
	fmt.Fprintf(w, `%[1]s %[2]s — a tiny end-to-end-encrypted P2P tunnel between two
machines behind NAT.

One binary, three roles (always chosen explicitly with --role):

  buddy      an ordinary peer (NAT is fine) — run this to get a tunnel
  relay      a public-IP node that blindly forwards encrypted sessions (fallback)
  handshake  the bootstrap/matchmaking server on a VPS (pairs two buddies)

QUICK START — connect two machines (BuddyPeer)

  1) On a VPS with a public IP, run the bootstrap server and print its key:
       %[1]s --role=handshake --key /var/lib/%[1]s/id.key
       %[1]s --role=handshake --key /var/lib/%[1]s/id.key identity   # -> SERVER_KEY

  2) On machine A, expose a local service (e.g. an rsync daemon on :873):
       %[1]s --role=buddy --server VPS:51820 --server-key SERVER_KEY \
            --invite -forward 127.0.0.1:873
     It prints a ONE-TIME invite token — hand it to B over a trusted channel.

  3) On machine B, reach A's service locally (here on :9000):
       %[1]s --role=buddy --server VPS:51820 --server-key SERVER_KEY \
            --join=TOKEN -L 127.0.0.1:9000

COMMANDS
  %[1]s gen-token                            mint a strong shared token
  %[1]s --role=handshake --key PATH identity   print the server's public key
  %[1]s --role=buddy ... --status            is my buddy online and reachable?
  %[1]s version

SECURITY — please read
  • Pin your buddy with --peer-key (each buddy prints its identity at startup).
    Without a pin, first contact is verified by a Short Authentication String
    you compare out of band, then remembered in --known-peers.
  • Keep the token off the command line: prefer BUDDYNET_TOKEN or a 0600 file.

TRANSPORT
  The handshake control plane uses plain UDP by default (source addresses are
  validated by a cookie, so the server is never a reflector). Pass
  --quic-handshake on the server AND every buddy to use QUIC instead — same
  protection via QUIC's built-in address validation, at the cost of a TLS cert.

FLAGS
`, appName, version)
	flag.PrintDefaults()
	fmt.Fprintf(w, "\nMore: docs/ARCHITECTURE.md, docs/PROTOCOL.md, SECURITY.md\n")
}
