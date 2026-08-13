package role

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/tzero78/buddynet/internal/relay"
	"github.com/tzero78/buddynet/internal/ticket"
)

// RelayConfig configures a relay node (--role=relay). A relay needs a publicly
// reachable address; it blindly forwards encrypted datagrams between the two
// legs of a session and never sees content.
type RelayConfig struct {
	Listen string        // UDP address, e.g. "[::]:51821"
	TTL    time.Duration // drop a session leg after this long with no traffic
	// ServerKeys are the handshake server identity keys whose relay tickets this
	// relay accepts (ticket mode). Two may be given so a server key rotation has a
	// grace window. They are PUBLIC keys: a relay holds no signing key, so
	// compromising it yields no ability to authorise a session anywhere.
	ServerKeys []ed25519.PublicKey
	// RelayID is this relay's id, configured identically on the handshake server.
	// Required with ServerKeys — it is what stops a ticket minted for another
	// relay from being spent here.
	RelayID string
	// AllowCIDRs, if non-empty, restricts which source networks may bind a leg
	// (network mode). Combined with ServerKeys it is an AND, never an alternative.
	AllowCIDRs []netip.Prefix
	// MaxSessions / MaxLegsPerIP override the relay's abuse ceilings; 0 uses the
	// defaults. A private relay for a small group may lower them to tighten the
	// ceiling further (e.g. 256 / 16).
	MaxSessions  int
	MaxLegsPerIP int
	// Debug adds source addresses to rejection logs (see relay.Config.Debug).
	Debug bool
}

// ErrNoRelayPolicy is returned when a relay is started with no way to decide who
// may use it. It is a startup refusal on purpose: a relay carries the operator's
// bandwidth and cost, and a determined stranger can hoard its capacity so the two
// people it was built for cannot fall back when they need it.
var ErrNoRelayPolicy = errors.New("relay has no authorization policy — refusing to start")

// checkPolicy validates the relay's authorization configuration. It is the one
// place that decides whether a relay may run at all.
//
// There is deliberately no --relay-open switch: an "I know what I am doing" flag
// ends up in production. `--allow-cidr 0.0.0.0/0` would be that switch spelled
// differently, so an allow-everything prefix is refused with its own message
// rather than quietly accepted as a policy. An operator who genuinely wants to
// serve the world can put something else in front of it; BuddyNet will not hand
// them the switch.
func (cfg RelayConfig) checkPolicy() error {
	for _, p := range cfg.AllowCIDRs {
		if p.Bits() == 0 {
			return fmt.Errorf("--allow-cidr %s allows every source, which is an open relay spelled differently — refusing.\n"+
				"  Name the networks that may use this relay, or verify tickets from your handshake server:\n"+
				"      --server-key <SERVER_KEY>  --relay-id <RELAY_ID>", p)
		}
	}
	if len(cfg.ServerKeys) == 0 && len(cfg.AllowCIDRs) == 0 {
		return fmt.Errorf("%w.\n"+
			"  Verify relay tickets from your handshake server (recommended — tickets follow\n"+
			"  a buddy whose address changes, which a CIDR list cannot):\n"+
			"      --server-key <SERVER_KEY>  --relay-id <RELAY_ID>\n"+
			"  and/or restrict who may reach it:\n"+
			"      --allow-cidr 203.0.113.0/24\n"+
			"  Mint the id once with `buddynet gen-relay-id` and set the SAME value on the\n"+
			"  handshake server (--relay-id).", ErrNoRelayPolicy)
	}
	if len(cfg.ServerKeys) > 2 {
		return fmt.Errorf("--server-key takes at most two keys (current and next, for a rotation), got %d", len(cfg.ServerKeys))
	}
	if len(cfg.ServerKeys) > 0 && !ticket.ValidID(cfg.RelayID) {
		return fmt.Errorf("--server-key needs --relay-id: a ticket names the relay it is valid at, so without an id "+
			"this relay would reject every ticket it is handed.\n"+
			"  Use the SAME value the handshake server was started with (mint one with `buddynet gen-relay-id`).\n"+
			"  Got: %q", cfg.RelayID)
	}
	return nil
}

// Relay runs the blind forwarder until ctx is cancelled. It is the same dormant
// code every buddy binary carries; running --role=relay just activates it on a
// node that happens to have a public IP.
//
// The startup refusal above applies ONLY to a process that actually starts this
// role. It is not a requirement on the handshake server and not on a buddy:
// BuddyNet must keep working P2P-only, with no relay configured anywhere and no
// relay port open. Refusing to start something nobody asked for would be its own
// kind of bug.
func Relay(ctx context.Context, cfg RelayConfig) error {
	if cfg.TTL == 0 {
		cfg.TTL = 60 * time.Second
	}
	if err := cfg.checkPolicy(); err != nil {
		return err
	}
	udpAddr, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Printf("RELAY: action=listening addr=%s transport=udp detail=%q", conn.LocalAddr(), "forwarding encrypted sessions blind")
	if len(cfg.ServerKeys) > 0 {
		// The id is printed because it is configured in TWO places; a mismatch would
		// otherwise surface only as "every ticket rejected", with nothing in either
		// log naming the cause.
		log.Printf("relay tickets ON: rid=%s keys=%d detail=%q", cfg.RelayID, len(cfg.ServerKeys),
			"only sessions that handshake server authorised may bind; the relay learns nothing about who they are")
		if len(cfg.ServerKeys) > 1 {
			log.Print("NOTE: two server keys are configured — a rotation window. Drop the retired one once every buddy has re-registered.")
		}
	}
	switch {
	case len(cfg.AllowCIDRs) > 0 && len(cfg.ServerKeys) > 0:
		log.Printf("relay access control ON (AND with tickets): only %v may bind a leg", cfg.AllowCIDRs)
	case len(cfg.AllowCIDRs) > 0:
		log.Printf("relay access control ON: only %v may bind a leg", cfg.AllowCIDRs)
		log.Print("NOTE: a CIDR list cannot follow a buddy whose address changes — which is exactly the buddy that needs a relay. " +
			"Prefer tickets: --server-key <SERVER_KEY> --relay-id <RELAY_ID>.")
	}
	go func() { <-ctx.Done(); conn.Close() }()

	relay.New(relay.Config{
		TTL:          cfg.TTL,
		ServerKeys:   cfg.ServerKeys,
		RelayID:      cfg.RelayID,
		AllowCIDRs:   cfg.AllowCIDRs,
		MaxSessions:  cfg.MaxSessions,
		MaxLegsPerIP: cfg.MaxLegsPerIP,
		Debug:        cfg.Debug,
	}).Run(conn)
	if ctx.Err() != nil {
		log.Print("shutting down")
	}
	return nil
}
