// Command buddynet is the single BuddyNet binary. One executable, three roles,
// chosen explicitly with --role (never auto-detected):
//
//	buddynet --role=buddy      # ordinary peer; NAT is fine
//	buddynet --role=relay      # public IP; blindly forwards encrypted sessions
//	buddynet --role=handshake  # bootstrap/matchmaking server on a VPS
//
// Every binary carries all three roles; a buddy contains the relay and
// handshake code as dormant fallback. Two buddies and one handshake server is
// just the two-peer case; the same binary scales to many buddies at once
// (MultiPeer):
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
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/nft"
	"github.com/tzero78/buddynet/internal/role"
	"github.com/tzero78/buddynet/internal/secret"
	"github.com/tzero78/buddynet/pkg/protocol"
)

const appName = "buddynet"

// version is set ONLY by the release workflow, which injects the exact git tag
// via ldflags (release.yml: -X main.version=${version}). It is intentionally
// empty in source: a plain `go build`/`go install` derives a coherent version
// from the embedded VCS/module info (appVersion) instead of a hand-maintained
// constant that would drift from the GitHub releases.
var version = ""

// appVersion returns the release tag injected at build time, or — for an
// un-injected local build — a version derived from the Go build info: the module
// version (e.g. a `go install`ed tag) if present, otherwise a short VCS revision
// marked -dirty when the tree had uncommitted changes.
func appVersion() string {
	if version != "" {
		return version
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	// Prefer the VCS revision of THIS build (clean, unambiguous dev marker) over
	// bi.Main.Version, which for a plain `go build` is a Go pseudo-version that
	// can reference a stale base tag.
	var rev, modified string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if rev != "" {
		v := "dev-" + rev[:min(12, len(rev))]
		if modified == "true" {
			v += "-dirty"
		}
		return v
	}
	// No VCS info (e.g. `go install module@vX.Y.Z`): the module version is the tag.
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	return "dev"
}

func main() {
	log.SetFlags(log.Ltime)

	roleFlag := flag.String("role", "", "node role: buddy | relay | handshake (required; never auto-detected)")
	keyPath := flag.String("key", "", "path to this node's Ed25519 identity key (created if missing; empty = ephemeral)")
	listen := flag.String("listen", "", fmt.Sprintf("UDP address to listen on (handshake default %s, relay default %s)", protocol.DefaultHandshakeAddr, protocol.DefaultRelayAddr))
	relayListenFlag := flag.String("relay-listen", "", fmt.Sprintf("relay: UDP address for the relay when combined with another role on one node (default %s)", protocol.DefaultRelayAddr))
	allowCIDR := flag.String("allow-cidr", "", "relay/handshake: comma-separated CIDRs allowed to reach the server role(s); other sources are dropped before any crypto (empty = open to all)")
	relayMaxSessions := flag.Int("relay-max-sessions", 0, "relay: max concurrent sessions (abuse ceiling; 0 = default 4096). Lower it for a small private relay")
	relayMaxLegsPerIP := flag.Int("relay-max-legs-per-ip", 0, "relay: max legs one source may hold (anti-hoarding; 0 = default 64). A source is one IPv4 address or one IPv6 /64 — every address in a /64 is free to mint, so they share this budget. Lower it for a small private relay")
	ttl := flag.Duration("ttl", 0, "liveness/idle window for server-side state (handshake 10s, relay 60s default)")
	authorized := flag.String("authorized", "", "handshake: client allowlist file (approval mode); also used by the approve/list/revoke subcommands")
	relayEndpoint := flag.String("relay-endpoint", "", "handshake: advertise this relay host:port to paired buddies as a fallback (set when the VPS also runs --role=relay)")
	debug := flag.Bool("debug", false, "handshake: verbose logging of parked/dropped packets (not for production)")

	server := flag.String("server", "", "buddy: handshake server host:port [required]")
	serverKey := flag.String("server-key", "", "buddy: handshake server Ed25519 public key, base64 (pin it) [required]")
	peerKey := flag.String("peer-key", "", "buddy: pin the buddy's Ed25519 public key, base64 (strongest)")
	knownPeers := flag.String("known-peers", role.DefaultKnownPeersPath(), "buddy: trust-on-first-use store (SSH-style; learns the buddy key on first connect)")
	lab := flag.Bool("lab", false, "buddy: lab/demo mode — disables buddy identity verification (MITM-exposed; never use in production). Requires BUDDYNET_LAB=1.")
	code := flag.String("code", "", "buddy: enrollment code for an allowlist handshake server")
	peersPath := flag.String("peers", role.DefaultPeersPath(), "buddy: offline peer cache (peers.json) used when the handshake server is unreachable")
	peersFile := flag.String("peers-file", "", "buddy: MultiPeer manifest (YAML: buddies with key/token/name/expose per entry; legacy line format still read — run `peers migrate`); maintains a tunnel to every listed buddy at once (Model A, each pinned). Use --vip-listen to route to them. Mutually exclusive with --invite/--join/--lazy")
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
	expose := flag.String("expose", "", "buddy (--wireguard): port(s) the partner may reach on THIS host over the tunnel, e.g. 873 or 873,8080 or tcp/873,udp/51820; 'all' = explicit whole-host access. WITHOUT this flag NOTHING is exposed (fail-closed; a manifest's per-buddy 'expose' overrides it)")
	wireguard := flag.Bool("wireguard", false, "buddy: use the kernel WireGuard data plane (bnet0) for the peer tunnel instead of QUIC — needs Linux + NET_ADMIN + the wireguard module; set on BOTH buddies. Partner reachable natively at its VIP (10.66.X.Y), direct or over a relay; -L/-forward/--vip-listen are not needed on this path (and are ignored).")

	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = usage
	flag.Parse()

	switch {
	case *showVersion || flag.Arg(0) == "version":
		fmt.Printf("%s %s\n", appName, appVersion())
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
	case flag.Arg(0) == "init":
		initIdentity(*keyPath)
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
		os.Exit(runPeersCmd(*peersFile, *knownPeers, *peersPath, flag.Args()[1:]))
	}

	// Env fallbacks (handy for systemd; keeps the secret token out of argv/ps).
	*roleFlag = orEnv(*roleFlag, "BUDDYNET_ROLE")
	*server = orEnv(*server, "BUDDYNET_SERVER")
	*serverKey = orEnv(*serverKey, "BUDDYNET_SERVER_KEY")
	*peerKey = orEnv(*peerKey, "BUDDYNET_PEER_KEY")
	*knownPeers = orEnv(*knownPeers, "BUDDYNET_KNOWN_PEERS")
	*code = orEnv(*code, "BUDDYNET_CODE")
	// The invite token is a bearer secret, so it needs a way out of argv/ps. That
	// used to be BUDDYNET_TOKEN for the removed --token; --join inherits the role.
	*join = orEnv(*join, "BUDDYNET_JOIN")
	*name = orEnv(*name, "BUDDYNET_NAME")
	if !*dnsFlag {
		if v := os.Getenv("BUDDYNET_DNS"); v == "1" || v == "true" {
			*dnsFlag = true
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

	// The pairing token is now only ever a ONE-TIME invite: --invite mints one,
	// --join carries the one your buddy gave you. Both retire it after the first
	// pairing in favour of the stored session secret, so there is no longer a mode
	// where a fixed token is replayed on every reconnect (that was --token, removed
	// in v5: a long-lived bearer secret that anyone who ever learned it could use to
	// squat the pairing, for as long as the pair existed).
	token := ""
	ephemeral := false
	if hasBuddy {
		if *join != "" {
			token = *join
			ephemeral = true
		}
		if *invite {
			token = mintInviteToken()
			ephemeral = true
		}
	}
	bArgs := buddyArgs{
		server: *server, serverKey: *serverKey, token: token, peerKey: *peerKey,
		knownPeers: *knownPeers, lab: *lab, code: *code, keyPath: *keyPath,
		peersPath: *peersPath, peersFile: *peersFile, localListen: *localListen, forward: *forward, vipListen: *vipListen,
		punchDur: *punchDur, idleTimeout: *idleTimeout, status: *status,
		// Interactive only when not explicitly disabled AND a human is at the
		// terminal; otherwise an unknown buddy key is refused, never learned blind.
		interactive: !*noInteractive && secret.Interactive(), sasTimeout: *sasTimeout,
		ephemeral: ephemeral, inviteTimeout: *inviteTimeout,
		reauthInterval: *reauthInterval,
		name:           *name, dns: *dnsFlag, lazy: *lazyFlag, wireguard: *wireguard,
		expose: *expose,
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
					AllowCIDRs: allowedCIDRs,
				}))
			case protocol.RoleRelay:
				fail("relay", role.Relay(ctx, role.RelayConfig{
					Listen: relayListen(*relayListenFlag, *listen, roles), TTL: *ttl,
					AllowCIDRs:   allowedCIDRs,
					MaxSessions:  *relayMaxSessions,
					MaxLegsPerIP: *relayMaxLegsPerIP,
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
	localListen, forward, vipListen, name, expose                           string
	lab, status, interactive, ephemeral, dns, lazy, wireguard               bool
	punchDur, idleTimeout, sasTimeout, inviteTimeout, reauthInterval        time.Duration
}

// exposeScope parses --expose; validate() has already rejected a bad value.
func (a buddyArgs) exposeScope() *nft.Scope {
	if a.expose == "" {
		return nil // fail-closed default
	}
	s, err := nft.ParseScope(a.expose)
	if err != nil {
		return nil
	}
	return &s
}

// config maps the parsed flags onto the role package's BuddyConfig.
func (a buddyArgs) config() role.BuddyConfig {
	return role.BuddyConfig{
		Server: a.server, ServerKey: a.serverKey, Token: a.token,
		PeerKey: a.peerKey, KnownPeers: a.knownPeers, Insecure: a.lab,
		Code: a.code, KeyPath: a.keyPath, PeersPath: a.peersPath, PeersFile: a.peersFile,
		LocalListen: a.localListen, Forward: a.forward, VIPListen: a.vipListen,
		PunchDur: a.punchDur, IdleTimeout: a.idleTimeout, Status: a.status,
		Interactive: a.interactive, SASTimeout: a.sasTimeout,
		Ephemeral: a.ephemeral, InviteTimeout: a.inviteTimeout,
		ReauthInterval: a.reauthInterval,
		Name:           a.name, DNS: a.dns, Lazy: a.lazy,
		WireGuard: a.wireguard, Expose: a.exposeScope(),
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
	// --lab turns off ALL buddy verification (no pin, no SAS) — a full MITM
	// exposure that only belongs in throwaway test setups. Refuse it unless the
	// operator opts in via the environment, so it can never be copy-pasted from a
	// lab command into production by accident.
	if a.lab && os.Getenv("BUDDYNET_LAB") != "1" {
		fmt.Fprintln(os.Stderr, "error: --lab disables all identity verification (MITM-exposed).\nOnly for throwaway test setups. Set BUDDYNET_LAB=1 to confirm.")
		os.Exit(2)
	}
	// A token is needed for a first pairing (--invite/--join) and for a
	// --status probe; once paired, a stored session lets you reconnect with none.
	if a.status && a.token == "" {
		fmt.Fprintln(os.Stderr, "error: --status needs a pairing token — pass --join <TOKEN> (or run it where a session is already stored)")
		os.Exit(2)
	}
	// --wireguard carries IP natively (each partner is reachable at its VIP over
	// that buddy's bnetN), so the -L/-forward/--vip-listen requirement is waived. It
	// is the WG DATA plane, opt-in. MultiPeer works (one interface per buddy); only
	// the QUIC-stream-specific --lazy is not applicable.
	// --expose gates the WireGuard data plane; the QUIC door is already scoped
	// by construction (-L/--forward carry exactly one configured service).
	if a.expose != "" {
		if !a.wireguard {
			fmt.Fprintln(os.Stderr, "error: --expose only applies to --wireguard (the QUIC path forwards exactly the one service you configure)")
			os.Exit(2)
		}
		if _, err := nft.ParseScope(a.expose); err != nil {
			fmt.Fprintf(os.Stderr, "error: --expose: %v\n", err)
			os.Exit(2)
		}
	}
	if a.wireguard {
		if a.lazy {
			fmt.Fprintln(os.Stderr, "error: --wireguard cannot be combined with --lazy (lazy is QUIC-stream specific)")
			os.Exit(2)
		}
		// -L/-forward/--vip-listen are the QUIC stream-forwarding plumbing; on the WG
		// path the partner is reachable directly at its VIP, so they do nothing. Say
		// so rather than ignoring them silently, so an operator is not left wondering
		// why a listener never carried anything.
		if a.localListen != "" || a.forward != "" || a.vipListen != "" {
			fmt.Fprintln(os.Stderr, "NOTE: --wireguard ignores -L/-forward/--vip-listen — reach the partner directly at its VIP (e.g. http://<partner-vip>:<port>)")
		}
	} else if !a.status && a.localListen == "" && a.forward == "" && a.vipListen == "" {
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
		case a.peerKey != "":
			fmt.Fprintln(os.Stderr, "error: --peers-file cannot be combined with --peer-key (the manifest pins and pairs each buddy)")
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
	fmt.Fprint(os.Stderr, `New pairing token (384-bit). Give it to your buddy as --join (or
--join). It's a bearer secret — keep it off the command line (prefer a 0600
file) and pin each other with --peer-key.
`)
	secret.RevealUntilKey(tok)
	fmt.Fprintln(os.Stderr, "Token hidden — copy it to your buddy before you lose it.")
}

// printIdentity prints the base64 public key for --key (to pin in buddies).
// printIdentity prints the public key at keyPath. It READS ONLY: creating an
// identity is `init`, deliberately a different command.
//
// It used to create one when the file was missing, which quietly made every
// wrapper that reads the key ("get the pubkey, then start the server") able to
// mint a fresh identity after a volume was lost — the exact accident this split
// exists to prevent.
func printIdentity(keyPath string) {
	if keyPath == "" {
		fmt.Fprintln(os.Stderr, "error: set --key <path> to read the persistent identity")
		os.Exit(2)
	}
	priv, _, err := bcrypto.LoadKey(keyPath)
	if errors.Is(err, bcrypto.ErrKeyMissing) {
		fmt.Fprintf(os.Stderr, "error: %v\n\n"+
			"  Create it once (this is the only command that does):\n"+
			"      buddynet --key %s init\n\n"+
			"  If this host has run before, the key is LOST rather than absent — check the\n"+
			"  volume or credential holding it before creating a new identity, or every\n"+
			"  buddy that pinned the old key will refuse this node.\n", err, keyPath)
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("identity key: %v", err)
	}
	fmt.Println(bcrypto.PubKeyB64(priv.Public().(ed25519.PublicKey)))
}

// initIdentity creates the node's identity, once. It refuses if the file already
// exists, so it can never re-key a node whose buddies have pinned it.
func initIdentity(keyPath string) {
	if keyPath == "" {
		fmt.Fprintln(os.Stderr, "error: set --key <path> — `init` creates a persistent identity, so it needs somewhere to put it")
		os.Exit(2)
	}
	priv, err := bcrypto.CreateKey(keyPath)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			fmt.Fprintf(os.Stderr, "error: %s already holds an identity — refusing to replace it.\n"+
				"  Print the existing one with: buddynet --key %s identity\n", keyPath, keyPath)
			os.Exit(2)
		}
		log.Fatalf("create identity: %v", err)
	}
	pub := bcrypto.PubKeyB64(priv.Public().(ed25519.PublicKey))
	fmt.Println(pub)
	fmt.Fprintf(os.Stderr, "\ncreated a new identity at %s\n"+
		"  Buddies pin this key — hand it to them as --server-key (handshake server)\n"+
		"  or --peer-key (buddy). Back the file up: losing it changes this node's\n"+
		"  identity AND its virtual IP, and everyone has to re-pin.\n", keyPath)
}

// runPeersCmd dispatches `peers <list|add|remove|migrate>` against the
// --peers-file manifest (and --known-peers for revocation), then exits.
func runPeersCmd(peersFile, knownPeers, peersPath string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: --peers-file <file> peers <list|add|remove|migrate> [args]")
		return 2
	}
	var err error
	switch args[0] {
	case "list":
		err = role.PeersList(peersFile, knownPeers, peersPath)
	case "add":
		positional, opts, perr := parsePeersAddArgs(args[1:])
		if perr != nil {
			fmt.Fprintln(os.Stderr, "error:", perr)
			fmt.Fprintln(os.Stderr, "usage: --peers-file <file> peers add <peer-pubkey> [bootstrap-token] [--name NAME] [--expose PORTS]")
			return 2
		}
		if len(positional) < 1 || len(positional) > 2 {
			fmt.Fprintln(os.Stderr, "usage: --peers-file <file> peers add <peer-pubkey> [bootstrap-token] [--name NAME] [--expose PORTS]")
			return 2
		}
		token := ""
		if len(positional) == 2 {
			token = positional[1]
		}
		err = role.PeersAdd(peersFile, positional[0], token, opts["name"], opts["expose"])
	case "remove":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: --peers-file <file> peers remove <peer-pubkey>")
			return 2
		}
		err = role.PeersRemove(peersFile, knownPeers, args[1])
	case "migrate":
		err = role.PeersMigrate(peersFile)
	default:
		fmt.Fprintf(os.Stderr, "unknown peers subcommand %q (want list|add|remove|migrate)\n", args[0])
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

// parsePeersAddArgs splits `peers add` arguments into positionals and the
// --name/--expose options (both `--opt value` and `--opt=value` forms). The
// global flag package has already consumed the top-level flags, so this small
// hand parser handles only the subcommand's own options.
func parsePeersAddArgs(args []string) (positional []string, opts map[string]string, err error) {
	opts = map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			positional = append(positional, a)
			continue
		}
		name, value := strings.TrimPrefix(a, "--"), ""
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name, value = name[:eq], name[eq+1:]
		} else {
			if i+1 >= len(args) {
				return nil, nil, fmt.Errorf("option --%s needs a value", name)
			}
			i++
			value = args[i]
		}
		switch name {
		case "name", "expose":
			opts[name] = value
		default:
			return nil, nil, fmt.Errorf("unknown option --%s (want --name or --expose)", name)
		}
	}
	return positional, opts, nil
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
		// Removed in v5.0.0 with the server's pending file: there is no longer any
		// on-disk record mapping a code to a key, so nothing here could look one up.
		// Kept as a named case purely so operators (and their scripts) get told what
		// to do instead of "unknown command".
		fmt.Fprintln(os.Stderr, "allowclient was removed in v5.0.0: the server no longer keeps a pending file.\n"+
			"The server prints the ready-to-run command when a client enrols — approve by key instead:\n"+
			"  buddynet --role=handshake --authorized "+path+" approve <CLIENT-PUBKEY>\n"+
			"Find the key in the server log: AUTHZ: action=pending key=… code=… — approve with: …\n"+
			"(The client must still be running: pending enrolments now live in memory only.)")
		return 2
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

QUICK START — connect two machines

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

MANY BUDDIES (MultiPeer) — one node, several tunnels at once

  List each buddy's pinned key (+ a one-time bootstrap token) in a manifest, then
  hold a tunnel to every one of them and route by name:
       %[1]s --role=buddy --server VPS:51820 --server-key SERVER_KEY \
            --peers-file /var/lib/%[1]s/peers --vip-listen 8080 --dns
  Now  curl http://alice.buddy:8080  reaches that buddy through its own tunnel.
  Curate the list with the peers subcommands below; one failing buddy never
  affects the others.

NAMES & ON-DEMAND

  --name NAME --dns   Reach buddies by NAME.buddy instead of a virtual IP — a
                      local stub resolver (BuddyDNS) answers *.buddy from the
                      live peer list. See docs/BUDDYDNS.md.
  --lazy              With -L, bind the local listener immediately but defer the
                      tunnel until the first connection actually arrives (the
                      tunnel sleeps until something connects).

COMMANDS
  %[1]s gen-token                            mint a strong shared token
  %[1]s --key PATH init                         create this node's identity (once)
  %[1]s --role=handshake --key PATH identity   print the server's public key
  %[1]s --role=buddy ... --status            is my buddy online and reachable?
  %[1]s --peers-file PATH peers list|add|remove|migrate   manage your buddies (MultiPeer)
  %[1]s --authorized FILE approve|list|revoke    server allowlist (approval mode)
  %[1]s version

SECURITY — please read
  • Pin your buddy with --peer-key (each buddy prints its identity at startup).
    Without a pin, first contact is verified by a Short Authentication String
    you compare out of band, then remembered in --known-peers.
  • The invite token is one-time and retired after the first pairing; reconnects
    use the stored session secret, so it never has to be kept around.

TRANSPORT
  The handshake control plane is encrypted with QUIC/TLS 1.3 BY DEFAULT: the
  pairing token never travels in cleartext, source addresses are validated by the
  QUIC handshake (the server is never a reflector), and with --authorized the
  server pins clients to the allowlist at the TLS handshake. Pass
  --quic-handshake=false (or BUDDYNET_QUIC=0) on the server AND every buddy for the
  legacy plain-UDP control plane (token in cleartext; cookie-validated sources).

FLAGS
`, appName, appVersion())
	flag.PrintDefaults()
	fmt.Fprintf(w, "\nMore: docs/ARCHITECTURE.md, docs/PROTOCOL.md, SECURITY.md\n")
}
