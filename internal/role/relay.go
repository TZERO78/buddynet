package role

import (
	"context"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/tzero78/buddynet/internal/relay"
)

// RelayConfig configures a relay node (--role=relay). A relay needs a publicly
// reachable address; it blindly forwards encrypted datagrams between the two
// legs of a session and never sees content.
type RelayConfig struct {
	Listen string        // UDP address, e.g. "[::]:51821"
	TTL    time.Duration // drop a session leg after this long with no traffic
	// AllowCIDRs, if non-empty, restricts which source networks may use the relay
	// (it stays unauthenticated by design — this is a coarse access control for a
	// private relay). Empty keeps it open to all.
	AllowCIDRs []netip.Prefix
	// MaxSessions / MaxLegsPerIP override the relay's abuse ceilings; 0 uses the
	// defaults. A private relay for a small group may lower them to tighten the
	// ceiling further (e.g. 256 / 16).
	MaxSessions  int
	MaxLegsPerIP int
}

// Relay runs the blind forwarder until ctx is cancelled. It is the same dormant
// code every buddy binary carries; running --role=relay just activates it on a
// node that happens to have a public IP.
func Relay(ctx context.Context, cfg RelayConfig) error {
	if cfg.TTL == 0 {
		cfg.TTL = 60 * time.Second
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
	if len(cfg.AllowCIDRs) > 0 {
		log.Printf("relay access control ON: only %v may bind a leg", cfg.AllowCIDRs)
	} else {
		log.Print("NOTE: the relay is UNAUTHENTICATED by design (open bandwidth, never a reflector). " +
			"If it faces the public internet, restrict reach with --allow-cidr or a firewall — it sees only ciphertext, but anyone can use it.")
	}
	go func() { <-ctx.Done(); conn.Close() }()

	relay.NewServer(cfg.TTL, cfg.AllowCIDRs, cfg.MaxSessions, cfg.MaxLegsPerIP).Run(conn)
	if ctx.Err() != nil {
		log.Print("shutting down")
	}
	return nil
}
