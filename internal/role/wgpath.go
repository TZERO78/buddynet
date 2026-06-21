package role

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/tzero78/buddynet/internal/wg"
)

// This is the buddy-side glue for the WireGuard data path (Phase 3 step 4c):
// the EKM-free SAS binding run over the punched UDP socket, and the socket→WG
// handoff. connect.go calls these on the WG path; the QUIC path is unchanged.

// bindFramePrefix tags a SAS-binding datagram so it is not confused with punch
// (BNPNCH1), relay control (BNRELAY1), or WireGuard packets (first byte 0x01-0x04).
const bindFramePrefix = "BNBIND1"

// runBindingOverConn performs the ephemeral-DH SAS binding (binding.go) over the
// already-punched UDP path to remote, framing each message with bindFramePrefix
// and retransmitting the last message on timeout (UDP is lossy). committer must be
// opposite on the two ends — reuse the transport role (lower public key commits).
// It returns the 32-byte session binding to feed ComputeSAS in place of TLS EKM.
func runBindingOverConn(conn *net.UDPConn, remote *net.UDPAddr, committer bool, total time.Duration) ([]byte, error) {
	var lastSent []byte
	send := func(b []byte) error {
		lastSent = append([]byte(bindFramePrefix), b...)
		_, err := conn.WriteToUDP(lastSent, remote)
		return err
	}
	deadline := time.Now().Add(total)
	recv := func() ([]byte, error) {
		buf := make([]byte, 1500)
		for time.Now().Before(deadline) {
			_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil { // timeout (or transient) → retransmit our last message
				if lastSent != nil {
					_, _ = conn.WriteToUDP(lastSent, remote)
				}
				continue
			}
			if !udpAddrEqual(src, remote) {
				continue
			}
			if n < len(bindFramePrefix) || string(buf[:len(bindFramePrefix)]) != bindFramePrefix {
				continue
			}
			return append([]byte(nil), buf[len(bindFramePrefix):n]...), nil
		}
		return nil, errors.New("binding: timed out waiting for peer")
	}
	defer conn.SetReadDeadline(time.Time{})
	return runBinding(committer, send, recv)
}

// bringUpWGDirect hands the freshly punched UDP socket to kernel WireGuard: it
// reads the local port, derives the device config from the pinned identities, then
// CLOSES the Go socket and brings up ifName with the partner as the sole peer on
// that same port (so the NAT mapping survives — see lab/test-wg-handoff.sh).
// Returns the teardown func. On a host without NET_ADMIN/module the error wraps
// wg.ErrUnsupported (callers chose this path via wg.Available, so that is unexpected).
func bringUpWGDirect(conn *net.UDPConn, ifName string, myPriv ed25519.PrivateKey, partnerPub ed25519.PublicKey, remote netip.AddrPort) (func() error, error) {
	la, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, errors.New("wgpath: socket has no UDP local address")
	}
	cfg, err := wg.ConfigForPeer(ifName, la.Port, myPriv, partnerPub, remote)
	if err != nil {
		return nil, err
	}
	if err := conn.Close(); err != nil {
		return nil, fmt.Errorf("wgpath: close punch socket before handoff: %w", err)
	}
	return wg.Up(cfg)
}

func udpAddrEqual(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.IP.Equal(b.IP)
}
