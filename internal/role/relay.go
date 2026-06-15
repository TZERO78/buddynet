package role

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/tzero78/buddynet/internal/relay"
)

// RelayConfig configures a relay node (--role=relay). A relay needs a publicly
// reachable address; it blindly forwards encrypted datagrams between the two
// legs of a session and never sees content.
type RelayConfig struct {
	Listen string        // UDP address, e.g. "[::]:51821"
	TTL    time.Duration // drop a session leg after this long with no traffic
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
	log.Printf("buddynet relay listening on %s (udp, dual-stack) — forwarding encrypted sessions blind", conn.LocalAddr())
	log.Print("NOTE: the relay is UNAUTHENTICATED by design (open bandwidth, never a reflector). " +
		"If it faces the public internet, restrict reach with a firewall — it sees only ciphertext, but anyone can use it.")
	go func() { <-ctx.Done(); conn.Close() }()

	relay.NewServer(cfg.TTL).Run(conn)
	if ctx.Err() != nil {
		log.Print("shutting down")
	}
	return nil
}
