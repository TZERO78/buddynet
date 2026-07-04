package role

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/relay"
	"github.com/tzero78/buddynet/internal/tunnel"
	"github.com/tzero78/buddynet/pkg/protocol"
)

// Probe exit codes for --status, returned through ProbeError so a script can
// distinguish the outcomes by exit code (not just by parsing stdout). The
// contract matches BuddyPeer's:
//
//	0  online and directly reachable          (nil error)
//	1  local error (socket / DNS)             (any non-ProbeError)
//	3  online but not directly reachable      (a relay would be used)
//	4  offline (no buddy registered)
//	5  registered but identity not trusted    (possible hijack)
const (
	ProbeUnreachable = 3
	ProbeOffline     = 4
	ProbeUntrusted   = 5
)

// ProbeError carries a --status outcome as a process exit code. main maps it to
// os.Exit; the human-readable line is printed to stdout by buddyProbe.
type ProbeError struct {
	Code int
	Msg  string
}

func (e *ProbeError) Error() string { return e.Msg }

// logSASFailure records everything known about a failed first-contact SAS, so an
// operator can later tell whether there was an attack (journalctl --namespace=
// buddynet | grep "SAS REJECTED"). An explicit mismatch is a positive attack
// signal; a timeout is only logged as caution (the user may have stepped away).
// The remote endpoint is the peer's real IP ONLY on a direct path; over a relay
// it is the relay's address, so it is annotated accordingly and must not be
// mistaken for the attacker.
func logSASFailure(reason error, remote string, used relay.Path, partner protocol.Peer, token string) {
	headline := "SAS REJECTED — possible MITM / token-theft attack"
	if errors.Is(reason, ErrSASTimeout) {
		headline = "SAS NOT CONFIRMED (timed out) — aborting, treat with caution"
	}
	remoteNote := "direct path: this is the peer's real address"
	if used.Kind == relay.Relayed {
		remoteNote = "RELAYED path: this is the RELAY's address, NOT the peer — do not ban it"
	}
	log.Printf("%s\n"+
		"  remote endpoint : %s   [%s]\n"+
		"  virtual IP claim: %s\n"+
		"  partner pubkey  : %s\n"+
		"  token hash      : %s\n"+
		"  timestamp       : %s\n"+
		"  -> key NOT trusted. Run --invite to generate a fresh token for your buddy.",
		headline, remote, remoteNote, partner.VirtualIP, partner.PubKey,
		tokenKey(token), time.Now().UTC().Format(time.RFC3339))
}

// buddyProbe answers "is my buddy online and reachable?" without forwarding. It
// returns nil when online and directly reachable, a *ProbeError carrying a
// distinct exit code for the offline/unreachable/untrusted cases, or a plain
// error for a local failure (which main maps to exit 1).
func buddyProbe(ctx context.Context, cfg BuddyConfig, nd *node) error {
	trust, myID := nd.trust, nd.id
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		return err
	}
	defer conn.Close()
	serverAddrs, err := resolveAll(cfg.Server)
	if err != nil {
		return err
	}
	log.Print("status: checking whether the buddy is online...")
	partner, err := buddyRegister(conn, serverAddrs, cfg, nd, cfg.Token, 10*time.Second)
	if err != nil {
		fmt.Println("buddy is OFFLINE (no peer registered with this token)")
		return &ProbeError{Code: ProbeOffline, Msg: "offline"}
	}
	partnerPub, derr := bcrypto.DecodePubKey(partner.PubKey)
	if derr != nil {
		fmt.Println("a peer registered under this token but its key is malformed")
		return &ProbeError{Code: ProbeUntrusted, Msg: "untrusted"}
	}
	// A probe never learns a key; a CHANGED known key is a hijack signal, while a
	// brand-new key (needSAS) just means first contact not yet confirmed.
	if _, terr := trust.decide(cfg.Token, partnerPub); terr != nil {
		fmt.Println("a peer registered under this token but its identity is NOT trusted (possible hijack)")
		return &ProbeError{Code: ProbeUntrusted, Msg: "untrusted"}
	}
	if _, err := tunnel.Punch(conn, myID, partner.Candidates, cfg.PunchDur); err != nil {
		fmt.Println("buddy is ONLINE but NOT directly reachable (a relay would be used)")
		return &ProbeError{Code: ProbeUnreachable, Msg: "not directly reachable"}
	}
	fmt.Printf("buddy is ONLINE and REACHABLE — direct path available (vip=%s)\n", partner.VirtualIP)
	return nil
}
