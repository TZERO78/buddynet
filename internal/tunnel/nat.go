package tunnel

import (
	"errors"
	"net"
	"time"

	"github.com/tzero78/buddynet/pkg/protocol"
)

// punchPrefix marks a hole-punch datagram so it is not confused with QUIC.
const punchPrefix = "BNPNCH1"

// Punch hole-punches toward a peer's candidate endpoints over the given socket
// and returns the first endpoint we actually hear back from. It sends a small
// tagged datagram to every candidate ~5x/second and listens for the peer's; the
// address a reply arrives from is the reachable one. IPv6 wins immediately
// (there is no NAT to punch); an IPv4 mapping is returned only if no IPv6 path
// appears. The SAME socket must then be handed to NewQUIC so the punched NAT
// mapping is reused.
func Punch(conn *net.UDPConn, myID string, cands []protocol.Candidate, dur time.Duration) (*net.UDPAddr, error) {
	pkt := []byte(punchPrefix + myID)
	targets := make([]*net.UDPAddr, 0, len(cands))
	for _, c := range cands {
		if a, err := net.ResolveUDPAddr("udp", c.Addr); err == nil {
			targets = append(targets, a)
		}
	}
	if len(targets) == 0 {
		return nil, errors.New("no candidate endpoints to punch")
	}

	stopSend := make(chan struct{})
	go func() {
		t := time.NewTicker(200 * time.Millisecond)
		defer t.Stop()
		for {
			for _, a := range targets {
				conn.WriteToUDP(pkt, a)
			}
			select {
			case <-stopSend:
				return
			case <-t.C:
			}
		}
	}()
	defer close(stopSend)

	reachable := map[string]*net.UDPAddr{}
	deadline := time.Now().Add(dur)
	buf := make([]byte, 1500)
	for time.Now().Before(deadline) {
		conn.SetReadDeadline(deadline)
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if n >= len(punchPrefix) && string(buf[:len(punchPrefix)]) == punchPrefix {
			reachable[src.String()] = src
		}
	}
	conn.SetReadDeadline(time.Time{})

	var v4 *net.UDPAddr
	for _, a := range reachable {
		if a.IP.To4() == nil {
			return a, nil // IPv6: prefer immediately
		}
		v4 = a
	}
	if v4 != nil {
		return v4, nil
	}
	return nil, errors.New("no candidate became reachable")
}
