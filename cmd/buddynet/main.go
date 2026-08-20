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
	binvite "github.com/tzero78/buddynet/internal/invite"
	"github.com/tzero78/buddynet/internal/nft"
	"github.com/tzero78/buddynet/internal/role"
	"github.com/tzero78/buddynet/internal/secret"
	"github.com/tzero78/buddynet/internal/ticket"
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
	allowCIDR := flag.String("allow-cidr", "", "relay/handshake: comma-separated CIDRs allowed to reach the server role(s); a disallowed source is refused before it can occupy a connection slot, and on the relay before any crypto. On the HANDSHAKE server empty means open to all; on the RELAY it is one of the two authorization policies (the other is --server-key) and the relay refuses to start with neither — 0.0.0.0/0 and ::/0 are refused, an open relay is not a supported configuration")
	relayMaxSessions := flag.Int("relay-max-sessions", 0, "relay: max concurrent sessions (abuse ceiling; 0 = default 4096). Lower it for a small private relay")
	relayMaxLegsPerIP := flag.Int("relay-max-legs-per-ip", 0, "relay: max legs one source may hold (anti-hoarding; 0 = default 64). A source is one IPv4 address or one IPv6 /64 — every address in a /64 is free to mint, so they share this budget. Lower it for a small private relay")
	ttl := flag.Duration("ttl", 0, "liveness/idle window for server-side state (handshake 10s, relay 60s default)")
	authorized := flag.String("authorized", "", "handshake: client allowlist file (approval mode); also used by the approve/list/revoke subcommands")
	relayEndpoint := flag.String("relay-endpoint", "", "handshake: advertise this relay host:port to paired buddies as a fallback (set when the VPS also runs --role=relay)")
	relayID := flag.String("relay-id", "", "handshake/relay: the relay's id, the SAME value on both (mint one with `buddynet gen-relay-id`). On the handshake server it turns on relay tickets — every paired buddy is issued a short-lived signed permit for that relay; on the relay it names which tickets to accept")
	debug := flag.Bool("debug", false, "handshake/relay: verbose logging of parked/dropped packets; on the relay it also puts SOURCE ADDRESSES in ticket-rejection lines, which a shipped relay deliberately does not log (not for production)")

	server := flag.String("server", "", "buddy: handshake server host:port [required]")
	serverKey := flag.String("server-key", "", "buddy: handshake server Ed25519 public key, base64 (pin it) [required]. RELAY: the handshake server whose relay tickets this relay accepts — pass two comma-separated keys during a server key rotation")
	peerKey := flag.String("peer-key", "", "buddy: pin the buddy's Ed25519 public key, base64 (strongest). Must agree with the key stored from a previous pairing: a pin that contradicts it refuses to connect (revoke the old buddy with \"peers remove <key>\", then pair again)")
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
	invite := flag.Bool("invite", false, "buddy: mint a ONE-TIME invite (valid until first pairing, see --invite-timeout), print it, and wait. The invite carries this node's public key, so your buddy pins YOUR identity from it — hand it over on a channel you trust. Afterwards reconnects use a stored session secret")
	join := flag.String("join", "", "buddy: join with the one-time invite your buddy gave you. A key-bearing invite pins them automatically (no code to compare on this side); a bare token falls back to first-contact verification. On success a session secret is stored for reconnects")
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
	case flag.Arg(0) == "gen-relay-id":
		genRelayID()
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
	// sasShow marks the joining side of a KEY-BOUND invite: the blob pinned the
	// inviter, so this side has nothing left to verify and only shows its code
	// for the inviter to type. See role.BuddyConfig.SASShow.
	sasShow := false
	if hasBuddy {
		if *join != "" {
			tok, pin, show, jerr := resolveJoin(*join, *peerKey)
			if jerr != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", jerr)
				os.Exit(2)
			}
			token, *peerKey, sasShow = tok, pin, show
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
		inviting: *invite, sasShow: sasShow,
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
	// On the RELAY, --server-key names the handshake server(s) whose tickets it
	// accepts — a different meaning from the buddy's "the server I pin", and one or
	// two keys rather than exactly one. Resolved here so a typo fails before a
	// socket is opened.
	var relayServerKeys []ed25519.PublicKey
	if hasRole(roles, protocol.RoleRelay) {
		relayServerKeys, cerr = relayKeys(roles, *serverKey, *keyPath)
		if cerr != nil {
			fmt.Fprintln(os.Stderr, "error:", cerr)
			os.Exit(2)
		}
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
					RelayID: *relayID, AllowCIDRs: allowedCIDRs,
				}))
			case protocol.RoleRelay:
				fail("relay", role.Relay(ctx, role.RelayConfig{
					Listen: relayListen(*relayListenFlag, *listen, roles), TTL: *ttl,
					ServerKeys:   relayServerKeys,
					RelayID:      *relayID,
					AllowCIDRs:   allowedCIDRs,
					MaxSessions:  *relayMaxSessions,
					MaxLegsPerIP: *relayMaxLegsPerIP,
					Debug:        *debug,
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

// hasRole reports whether r is among the selected roles.
func hasRole(roles []protocol.Role, r protocol.Role) bool {
	for _, have := range roles {
		if have == r {
			return true
		}
	}
	return false
}

// relayKeys resolves which handshake server(s) the relay trusts.
//
// The common deployment is one VPS running --role=handshake,relay. There the
// answer is not in doubt — the relay should accept the tickets THIS process
// issues — so the public half of the node's own identity is used and the
// operator only has to set --relay-id, one flag, on one command. An explicit
// --server-key always wins, which is what a separated deployment (recommended
// for an exposed relay) passes.
//
// The derivation needs a persistent --key: with an ephemeral identity the two
// roles would not even agree on a key, so there is nothing to derive and the
// relay falls back to whatever policy was configured explicitly.
func relayKeys(roles []protocol.Role, serverKey, keyPath string) ([]ed25519.PublicKey, error) {
	if strings.TrimSpace(serverKey) != "" {
		return parseServerKeys(serverKey)
	}
	if !hasRole(roles, protocol.RoleHandshake) || keyPath == "" {
		return nil, nil
	}
	priv, _, err := bcrypto.LoadKey(keyPath)
	if err != nil {
		// Reported here rather than swallowed: falling through to "no policy" would
		// send the operator looking for a missing flag when the actual problem is a
		// key that could not be read.
		return nil, fmt.Errorf("the relay derives the handshake key it trusts from --key %s, which could not be read: %w\n"+
			"  Create the identity once:  %s --key %s init\n"+
			"  Or name the server explicitly:  --server-key <SERVER_KEY>", keyPath, err, appName, keyPath)
	}
	log.Printf("NOTE: the relay accepts tickets from the handshake server in THIS process (--key %s). "+
		"Pass --server-key explicitly if it should trust a different server.", keyPath)
	return []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)}, nil
}

// parseServerKeys parses the relay's --server-key: one or two base64 Ed25519
// public keys, comma-separated. Two are allowed so a handshake-server key
// rotation can be made before-break — the relay accepts tickets from either
// while buddies move over.
//
// A relay that also runs --role=buddy shares this flag with the buddy's own
// "pin the server I talk to", where exactly one key is meaningful; the buddy
// therefore keeps its own strict parse, and only this side accepts a pair.
func parseServerKeys(s string) ([]ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil // network mode, or no policy at all — role.Relay decides
	}
	var out []ed25519.PublicKey
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, err := bcrypto.DecodePubKey(part)
		if err != nil {
			return nil, fmt.Errorf("invalid --server-key entry %q: %w (want the base64 the server prints with `identity`)", part, err)
		}
		out = append(out, k)
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
	inviting, sasShow                                                       bool
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
		Inviting: a.inviting, SASShow: a.sasShow,
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
	// A punch longer than this would eat into the window a relay ticket leaves for
	// binding, so the ticket could expire while the punch it was issued for is
	// still running. Refused here rather than silently shortened.
	if a.punchDur > role.PunchDurMax {
		fmt.Fprintf(os.Stderr, "error: --punch %s is over the %s maximum (a relay ticket is short-lived and has to cover the punch AND the bind that follows it)\n", a.punchDur, role.PunchDurMax)
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

// resolveJoin turns the value of --join into the rendezvous token plus, when the
// invite carries one, the inviter's key to pin. sasShow reports that the pin came
// from the invite, which is what makes this side the DISPLAY half of first
// contact (nothing to verify here; see role.BuddyConfig.SASShow).
//
// A key-bearing invite is what removes the human from this direction entirely: it
// arrived over a channel the user already trusts, so the identity on it beats
// anything the handshake server has to say. A bare token (an older inviter) is
// still accepted and pairs by trust-on-first-use — but a MALFORMED invite is an
// error, never a silent downgrade to that weaker path.
func resolveJoin(join, peerKey string) (token, pin string, sasShow bool, err error) {
	tok, inviterPub, perr := binvite.Parse(join)
	if perr != nil {
		return "", "", false, fmt.Errorf("--join: %w\n"+
			"  Paste the invite EXACTLY as your buddy sent it — a truncated or edited one is\n"+
			"  refused rather than falling back to the weaker unpinned path", perr)
	}
	if inviterPub == nil {
		return tok, peerKey, false, nil // bare token from an older inviter
	}
	pinned := bcrypto.PubKeyB64(inviterPub)
	if peerKey != "" && peerKey != pinned {
		return "", "", false, fmt.Errorf("--peer-key does not match the key inside the invite.\n"+
			"  invite:     %s\n  --peer-key: %s\n"+
			"  One of the two is not your buddy — refusing rather than picking one", pinned, peerKey)
	}
	return tok, pinned, true, nil
}

// mintInviteToken mints a fresh one-time rendezvous token for --invite. It only
// returns it: the invite the human actually hands over is the BLOB (token plus
// this node's public key), and that is printed by role.Buddy, which is the first
// place the identity key is settled — for an ephemeral node it does not exist
// until then. See internal/invite.
func mintInviteToken() string {
	tok, err := secret.NewToken()
	if err != nil {
		log.Fatalf("could not mint token: %v", err)
	}
	return tok
}

// genRelayID mints a relay id: the value that must be configured IDENTICALLY on
// the handshake server (--relay-id, which turns on ticket issuance) and on the
// relay (--relay-id, which names the tickets it accepts). It is not a secret —
// it only has to be unguessable enough that a ticket for one relay cannot be
// replayed at another by picking the right string — so unlike a token it is
// printed plainly and needs no reveal-and-hide.
func genRelayID() {
	id, err := ticket.NewID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: could not read random bytes: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(id)
	if secret.Interactive() {
		fmt.Fprintf(os.Stderr, "\nUse the SAME value on both sides:\n"+
			"  handshake:  %[1]s --role=handshake ... --relay-endpoint <VPS:51821> --relay-id %[2]s\n"+
			"  relay:      %[1]s --role=relay ... --relay-id %[2]s --server-key <SERVER_KEY>\n"+
			"It is not a secret; a mismatch shows up as every ticket being rejected.\n", appName, id)
	}
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
     It prints a ONE-TIME invite — hand it to B over a channel you trust (phone,
     Signal). The invite carries A's key, so B pins A's identity straight from it.

  3) On machine B, reach A's service locally (here on :9000):
       %[1]s --role=buddy --server VPS:51820 --server-key SERVER_KEY \
            --join=INVITE -L 127.0.0.1:9000
     B is now done. A asks once for the six-character code shown on B's screen —
     call B and type it in. That single step verifies B; A was already pinned.

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
  • An invite from --invite carries the inviter's public key, so --join pins it
    without anyone comparing anything: a hostile handshake server cannot put a
    different identity on that end. The inviter verifies the joiner by typing the
    six-character code the joiner displays — one human step, and it cannot be
    click-confirmed away.
  • --peer-key pins a buddy explicitly and is still the strongest option for
    unattended nodes (no human, no prompt). Without either, first contact falls
    back to comparing a Short Authentication String out of band, then remembers
    the key in --known-peers.
  • --peer-key is checked on EVERY connect, including reconnects that use a
    stored session. If it names a different key than the stored one, the buddy
    stops before registering and says so: that is a re-pin or a revocation, and
    it needs "peers remove <old key>" plus a new invite. Removing --peer-key is
    NOT a revocation — the stored pin still governs.
  • The invite is one-time and retired after the first pairing; reconnects use the
    stored session secret, so it never has to be kept around.

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
