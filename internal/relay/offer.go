// Package relay carries a session when a direct hole punch fails. The relay is
// a blind UDP forwarder: two buddies each bind a "leg" to it under a shared
// session token, and the relay pipes datagrams between the two legs without ever
// terminating the QUIC/TLS the buddies run end to end. It therefore sees only
// encrypted QUIC packets — virtual IPs and ciphertext, never content.
//
// This file is the signaling: the RELAY_OFFER a handshake server (or a buddy)
// uses to advertise a relay, and the tiny bind handshake a buddy speaks to the
// relay to claim its leg of a session.
package relay

import (
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/tzero78/buddynet/pkg/protocol"
)

// BindPrefix tags a relay control datagram so the relay can tell a bind request
// from the QUIC data it forwards. QUIC's first byte is never our prefix, so
// there is no ambiguity.
const BindPrefix = "BNRELAY1"

// Bind is the control message a buddy sends a relay to claim one leg of a
// session. Two legs presenting the same SessionToken are spliced together. The
// token is short-lived and unguessable, minted by the buddy that initiates the
// session and handed to the partner in a CONNECT, so only the intended pair can
// join. The relay echoes the bind back as an ack.
type Bind struct {
	SessionToken string `json:"s"`
}

// MarshalBind encodes a bind control datagram: BindPrefix || JSON(Bind).
func MarshalBind(b Bind) []byte {
	body, _ := json.Marshal(b)
	out := make([]byte, 0, len(BindPrefix)+len(body))
	out = append(out, BindPrefix...)
	return append(out, body...)
}

// ParseBind decodes a bind control datagram, reporting ok=false for anything
// that is not one (i.e. QUIC data to forward).
func ParseBind(pkt []byte) (Bind, bool) {
	if len(pkt) < len(BindPrefix) || string(pkt[:len(BindPrefix)]) != BindPrefix {
		return Bind{}, false
	}
	var b Bind
	if json.Unmarshal(pkt[len(BindPrefix):], &b) != nil || b.SessionToken == "" ||
		len(b.SessionToken) > protocol.MaxFieldLen {
		return Bind{}, false
	}
	return b, true
}

// BindLeg claims this node's leg of a session on the relay over conn: it sends
// bind datagrams ~5x/second until the relay echoes an ack (which also opens the
// NAT path back), then returns. The SAME conn must then be used to run QUIC,
// with the relay's address as the peer endpoint, so the relay forwards the
// punched/QUIC packets to the partner's leg.
func BindLeg(conn *net.UDPConn, relayAddr *net.UDPAddr, token string, timeout time.Duration) error {
	req := MarshalBind(Bind{SessionToken: token})
	deadline := time.Now().Add(timeout)
	next := time.Now()
	buf := make([]byte, 1500)
	for time.Now().Before(deadline) {
		if !time.Now().Before(next) {
			conn.WriteToUDP(req, relayAddr)
			next = time.Now().Add(200 * time.Millisecond)
		}
		conn.SetReadDeadline(next)
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if b, ok := ParseBind(buf[:n]); ok && b.SessionToken == token && sameAddr(src, relayAddr) {
			conn.SetReadDeadline(time.Time{})
			return nil // relay acked our leg
		}
	}
	return errors.New("relay did not acknowledge the session (unreachable or wrong endpoint)")
}

func sameAddr(a, b *net.UDPAddr) bool {
	return a.Port == b.Port && a.IP.Equal(b.IP)
}
