//go:build linux

// Package vip assigns a buddy's virtual IP (10.66.X.Y) to the loopback
// interface so the local host can listen on it and route per-buddy traffic
// through that buddy's tunnel (Phase 1 routing — see docs/plans/v2-roadmap.md).
//
// It talks to the kernel over a raw NETLINK_ROUTE socket (RTM_NEWADDR /
// RTM_DELADDR) rather than shelling out to `ip addr`: no root subprocess, no
// PATH/iproute2 dependency, no gosec G204, and no external module — in keeping
// with the project's zero-dependency, security-first posture. Adding an address
// needs NET_ADMIN; callers degrade gracefully when it is missing (same pattern
// as the DNS bind).
package vip

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// Assign adds ip/32 to the loopback interface (host scope) and returns a release
// func that removes it again. Both operations are idempotent: assigning an
// address that already exists, or releasing one already gone, is not an error.
// On a host without NET_ADMIN, Assign returns an error wrapping syscall.EPERM so
// callers can degrade gracefully.
func Assign(ip netip.Addr) (release func() error, err error) {
	if !ip.Is4() {
		return nil, fmt.Errorf("vip: only IPv4 virtual IPs are supported, got %s", ip)
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return nil, fmt.Errorf("vip: find loopback: %w", err)
	}
	if err := addrOp(syscall.RTM_NEWADDR,
		syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|syscall.NLM_F_CREATE|syscall.NLM_F_REPLACE,
		ip, lo.Index); err != nil {
		return nil, err
	}
	released := false
	return func() error {
		if released {
			return nil
		}
		released = true
		return addrOp(syscall.RTM_DELADDR, syscall.NLM_F_REQUEST|syscall.NLM_F_ACK, ip, lo.Index)
	}, nil
}

// ReconcileStale removes leftover BuddyNet VIPs (10.66.0.0/16 as /32) from the
// loopback interface that are NOT in keep — the cleanup for a previous run that
// died via SIGKILL before its deferred release() ran (and for buddies that have
// since been removed). keep is the set of VIPs this run will manage. Returns how
// many stale addresses were removed. Best-effort: a listing error is returned,
// per-address delete errors are ignored (idempotent).
func ReconcileStale(keep []netip.Addr) (removed int, err error) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return 0, fmt.Errorf("vip: find loopback: %w", err)
	}
	have, err := listLoV4(lo.Index)
	if err != nil {
		return 0, err
	}
	keepSet := make(map[netip.Addr]bool, len(keep))
	for _, k := range keep {
		keepSet[k] = true
	}
	for _, a := range have {
		if !inVIPRange(a) || keepSet[a] {
			continue
		}
		if addrOp(syscall.RTM_DELADDR, syscall.NLM_F_REQUEST|syscall.NLM_F_ACK, a, lo.Index) == nil {
			removed++
		}
	}
	return removed, nil
}

// inVIPRange reports whether ip is in the BuddyNet overlay range 10.66.0.0/16.
func inVIPRange(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	b := ip.As4()
	return b[0] == 10 && b[1] == 66
}

// listLoV4 dumps the IPv4 /32 addresses currently on interface ifIndex via a
// netlink RTM_GETADDR request — the read-side companion to addrOp, using raw
// syscall netlink (no external netlink library) and the stdlib netlink parsers.
func listLoV4(ifIndex int) ([]netip.Addr, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("vip: netlink socket: %w", err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("vip: netlink bind: %w", err)
	}

	// Header (NLM_F_DUMP = ROOT|MATCH) + a bare ifaddrmsg requesting AF_INET.
	body := make([]byte, syscall.SizeofIfAddrmsg)
	body[0] = syscall.AF_INET
	hdr := make([]byte, syscall.NLMSG_HDRLEN)
	binary.NativeEndian.PutUint32(hdr[0:4], uint32(syscall.NLMSG_HDRLEN+len(body)))
	binary.NativeEndian.PutUint16(hdr[4:6], uint16(syscall.RTM_GETADDR))
	binary.NativeEndian.PutUint16(hdr[6:8], uint16(syscall.NLM_F_REQUEST|syscall.NLM_F_ROOT|syscall.NLM_F_MATCH))
	binary.NativeEndian.PutUint32(hdr[8:12], 1)
	if err := syscall.Sendto(fd, append(hdr, body...), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("vip: netlink send: %w", err)
	}

	var out []netip.Addr
	buf := make([]byte, 1<<16)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, fmt.Errorf("vip: netlink recv: %w", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, fmt.Errorf("vip: parse netlink: %w", err)
		}
		done := false
		for _, m := range msgs {
			switch m.Header.Type {
			case syscall.NLMSG_DONE:
				done = true
			case syscall.NLMSG_ERROR:
				return nil, fmt.Errorf("vip: netlink dump error")
			case syscall.RTM_NEWADDR:
				if len(m.Data) < syscall.SizeofIfAddrmsg {
					continue
				}
				family := m.Data[0]
				prefix := m.Data[1]
				index := binary.NativeEndian.Uint32(m.Data[4:8])
				if family != syscall.AF_INET || int(index) != ifIndex || prefix != 32 {
					continue
				}
				sub := syscall.NetlinkMessage{Header: m.Header, Data: m.Data[syscall.SizeofIfAddrmsg:]}
				attrs, _ := syscall.ParseNetlinkRouteAttr(&sub)
				for _, a := range attrs {
					if (a.Attr.Type == syscall.IFA_LOCAL || a.Attr.Type == syscall.IFA_ADDRESS) && len(a.Value) == 4 {
						out = append(out, netip.AddrFrom4([4]byte{a.Value[0], a.Value[1], a.Value[2], a.Value[3]}))
						break
					}
				}
			}
		}
		if done {
			break
		}
	}
	return out, nil
}

// addrOp sends a single RTM_NEWADDR/RTM_DELADDR request for ip/32 on ifIndex and
// waits for the kernel's ACK. EEXIST (add) and EADDRNOTAVAIL/ESRCH (del) are
// treated as success so the operations stay idempotent across reconnects.
func addrOp(msgType, flags int, ip netip.Addr, ifIndex int) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("vip: netlink socket: %w", err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return fmt.Errorf("vip: netlink bind: %w", err)
	}

	req := buildAddrMessage(msgType, flags, ip, ifIndex)
	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return fmt.Errorf("vip: netlink send: %w", err)
	}

	buf := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return fmt.Errorf("vip: netlink recv: %w", err)
	}
	return parseAck(buf[:n], msgType)
}

// buildAddrMessage assembles the netlink request: a struct nlmsghdr, a struct
// ifaddrmsg (AF_INET, /32, host scope, the loopback index) and two equal
// IFA_LOCAL/IFA_ADDRESS attributes carrying the four address octets.
func buildAddrMessage(msgType, flags int, ip netip.Addr, ifIndex int) []byte {
	v4 := ip.As4()

	ifa := make([]byte, syscall.SizeofIfAddrmsg)
	ifa[0] = syscall.AF_INET                                 // Family
	ifa[1] = 32                                              // Prefixlen (/32)
	ifa[2] = 0                                               // Flags
	ifa[3] = syscall.RT_SCOPE_HOST                           // Scope: this host only
	binary.NativeEndian.PutUint32(ifa[4:8], uint32(ifIndex)) // Index

	body := append([]byte{}, ifa...)
	body = append(body, rtAttr(syscall.IFA_LOCAL, v4[:])...)
	body = append(body, rtAttr(syscall.IFA_ADDRESS, v4[:])...)

	total := syscall.NLMSG_HDRLEN + len(body)
	hdr := make([]byte, syscall.NLMSG_HDRLEN)
	binary.NativeEndian.PutUint32(hdr[0:4], uint32(total))   // nlmsg_len
	binary.NativeEndian.PutUint16(hdr[4:6], uint16(msgType)) // nlmsg_type
	binary.NativeEndian.PutUint16(hdr[6:8], uint16(flags))   // nlmsg_flags
	binary.NativeEndian.PutUint32(hdr[8:12], 1)              // nlmsg_seq
	binary.NativeEndian.PutUint32(hdr[12:16], 0)             // nlmsg_pid (kernel fills)

	return append(hdr, body...)
}

// rtAttr encodes one rtattr TLV (4-byte aligned), as netlink expects.
func rtAttr(attrType int, data []byte) []byte {
	const hdr = 4 // sizeof(struct rtattr)
	length := hdr + len(data)
	aligned := (length + 3) &^ 3
	out := make([]byte, aligned)
	binary.NativeEndian.PutUint16(out[0:2], uint16(length))
	binary.NativeEndian.PutUint16(out[2:4], uint16(attrType))
	copy(out[hdr:], data)
	return out
}

// parseAck reads the kernel's NLMSG_ERROR reply. A zero error code is success;
// EEXIST on add and EADDRNOTAVAIL/ESRCH on delete are folded to success so the
// caller can add/remove the same VIP across reconnects without spurious errors.
func parseAck(buf []byte, msgType int) error {
	if len(buf) < syscall.NLMSG_HDRLEN+4 {
		return fmt.Errorf("vip: short netlink ack (%d bytes)", len(buf))
	}
	nlType := binary.NativeEndian.Uint16(buf[4:6])
	if nlType != syscall.NLMSG_ERROR {
		return nil // DONE/other: no error payload to inspect
	}
	// NLMSG_ERROR payload begins with a signed errno (negated).
	code := int32(binary.NativeEndian.Uint32(buf[syscall.NLMSG_HDRLEN : syscall.NLMSG_HDRLEN+4]))
	if code == 0 {
		return nil
	}
	errno := syscall.Errno(-code)
	switch {
	case msgType == syscall.RTM_NEWADDR && errno == syscall.EEXIST:
		return nil
	case msgType == syscall.RTM_DELADDR && (errno == syscall.EADDRNOTAVAIL || errno == syscall.ESRCH):
		return nil
	}
	return fmt.Errorf("vip: kernel rejected address change: %w", errno)
}
