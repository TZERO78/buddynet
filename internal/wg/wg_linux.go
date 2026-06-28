//go:build linux

package wg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// --- WireGuard generic-netlink constants (uapi/linux/wireguard.h) -----------

const (
	wgGenlName    = "wireguard"
	wgGenlVersion = 1

	wgCmdGetDevice = 0
	wgCmdSetDevice = 1

	wgDeviceAIfindex    = 1
	wgDeviceAPrivateKey = 3
	wgDeviceAFlags      = 5
	wgDeviceAListenPort = 6
	wgDeviceAPeers      = 8

	wgDeviceFReplacePeers = 1

	// WGPEER_A_* are 1-based (WGPEER_A_UNSPEC = 0), per uapi/linux/wireguard.h.
	wgPeerAPublicKey                   = 1
	wgPeerAFlags                       = 3
	wgPeerAEndpoint                    = 4
	wgPeerAPersistentKeepaliveInterval = 5
	wgPeerAAllowedips                  = 9

	wgPeerFRemoveMe          = 1 // 1<<0 — drop this peer from the device
	wgPeerFReplaceAllowedips = 2 // 1<<1

	wgAllowedipAFamily   = 1
	wgAllowedipAIpaddr   = 2
	wgAllowedipACidrMask = 3
)

// --- generic-netlink controller constants (uapi/linux/genetlink.h) ----------

const (
	genlIDCtrl         = 0x10
	ctrlCmdGetFamily   = 3
	ctrlAttrFamilyID   = 1
	ctrlAttrFamilyName = 2

	genlHdrLen = 4 // struct genlmsghdr: cmd, version, reserved(2)
)

// --- rtnetlink link constants not always present in package syscall ---------

const (
	iflaLinkinfo = 18
	iflaInfoKind = 1

	nlaFNested      = 0x8000
	nlaTypeMask     = 0x3fff
	rtScopeUniverse = 0

	// route attributes (RTM_NEWROUTE rtmsg fields) — a directly-connected /32 to a
	// partner's VIP out the buddy's own bnetN interface (one interface per buddy).
	rtTableMain = 254
	rtProtBoot  = 3
	rtScopeLink = 253
	rtnUnicast  = 1
)

var nativeEndian = binary.NativeEndian

// --- attribute / message encoders (pure; unit-tested) -----------------------

// nlAttr encodes one netlink attribute TLV, padded to 4 bytes.
func nlAttr(typ uint16, data []byte) []byte {
	l := 4 + len(data)
	out := make([]byte, (l+3)&^3)
	nativeEndian.PutUint16(out[0:2], uint16(l))
	nativeEndian.PutUint16(out[2:4], typ)
	copy(out[4:], data)
	return out
}

func nlAttrU8(typ uint16, v uint8) []byte { return nlAttr(typ, []byte{v}) }
func nlAttrU16(typ uint16, v uint16) []byte {
	b := make([]byte, 2)
	nativeEndian.PutUint16(b, v)
	return nlAttr(typ, b)
}
func nlAttrU32(typ uint16, v uint32) []byte {
	b := make([]byte, 4)
	nativeEndian.PutUint32(b, v)
	return nlAttr(typ, b)
}

// nlNested wraps an attribute payload as a nested attribute.
func nlNested(typ uint16, payload []byte) []byte {
	return nlAttr(typ|nlaFNested, payload)
}

// encodeSockaddr serialises an endpoint as a struct sockaddr_in / sockaddr_in6
// (family host-order, port/addr network-order) as the kernel expects in
// WGPEER_A_ENDPOINT.
func encodeSockaddr(ap netip.AddrPort) []byte {
	if ap.Addr().Is4() {
		b := make([]byte, 16) // sizeof(struct sockaddr_in)
		nativeEndian.PutUint16(b[0:2], uint16(syscall.AF_INET))
		binary.BigEndian.PutUint16(b[2:4], ap.Port())
		a := ap.Addr().As4()
		copy(b[4:8], a[:])
		return b
	}
	b := make([]byte, 28) // sizeof(struct sockaddr_in6)
	nativeEndian.PutUint16(b[0:2], uint16(syscall.AF_INET6))
	binary.BigEndian.PutUint16(b[2:4], ap.Port())
	a := ap.Addr().As16()
	copy(b[8:24], a[:])
	return b
}

// buildAllowedIP encodes one WGALLOWEDIP nested entry's attributes.
func buildAllowedIP(p netip.Prefix) []byte {
	var fam uint16 = syscall.AF_INET
	var ip []byte
	if p.Addr().Is4() {
		a := p.Addr().As4()
		ip = a[:]
	} else {
		fam = syscall.AF_INET6
		a := p.Addr().As16()
		ip = a[:]
	}
	out := nlAttrU16(wgAllowedipAFamily, fam)
	out = append(out, nlAttr(wgAllowedipAIpaddr, ip)...)
	out = append(out, nlAttrU8(wgAllowedipACidrMask, uint8(p.Bits()))...)
	return out
}

// buildPeer encodes one peer's attributes (replacing its allowed-ips).
func buildPeer(p Peer) []byte {
	out := nlAttr(wgPeerAPublicKey, p.PublicKey[:])
	out = append(out, nlAttrU32(wgPeerAFlags, wgPeerFReplaceAllowedips)...)
	if p.Endpoint.IsValid() {
		out = append(out, nlAttr(wgPeerAEndpoint, encodeSockaddr(p.Endpoint))...)
	}
	if p.Keepalive > 0 {
		out = append(out, nlAttrU16(wgPeerAPersistentKeepaliveInterval, p.Keepalive)...)
	}
	var aips []byte
	for i, pfx := range p.AllowedIPs {
		aips = append(aips, nlNested(uint16(i), buildAllowedIP(pfx))...)
	}
	out = append(out, nlNested(wgPeerAAllowedips, aips)...)
	return out
}

// buildSetDeviceAttrs encodes the WG_CMD_SET_DEVICE attribute body for a single
// peer (replacing the device's peer list).
func buildSetDeviceAttrs(ifindex int, cfg Config) []byte {
	out := nlAttrU32(wgDeviceAIfindex, uint32(ifindex))
	out = append(out, nlAttrU32(wgDeviceAFlags, wgDeviceFReplacePeers)...)
	out = append(out, nlAttr(wgDeviceAPrivateKey, cfg.PrivateKey[:])...)
	if cfg.ListenPort > 0 {
		out = append(out, nlAttrU16(wgDeviceAListenPort, uint16(cfg.ListenPort))...)
	}
	out = append(out, nlNested(wgDeviceAPeers, nlNested(0, buildPeer(cfg.Peer)))...)
	return out
}

// buildAddPeerAttrs encodes a WG_CMD_SET_DEVICE body that ADDS/updates one peer
// WITHOUT WGDEVICE_F_REPLACE_PEERS — so the device's other peers stay intact
// (the bnet0 adapter model: one device, one peer per buddy).
func buildAddPeerAttrs(ifindex int, p Peer) []byte {
	out := nlAttrU32(wgDeviceAIfindex, uint32(ifindex))
	out = append(out, nlNested(wgDeviceAPeers, nlNested(0, buildPeer(p)))...)
	return out
}

// buildRemovePeerAttrs encodes a WG_CMD_SET_DEVICE body that removes one peer by
// public key (WGPEER_F_REMOVE_ME), leaving the device's other peers intact.
func buildRemovePeerAttrs(ifindex int, pub [32]byte) []byte {
	peer := nlAttr(wgPeerAPublicKey, pub[:])
	peer = append(peer, nlAttrU32(wgPeerAFlags, wgPeerFRemoveMe)...)
	out := nlAttrU32(wgDeviceAIfindex, uint32(ifindex))
	out = append(out, nlNested(wgDeviceAPeers, nlNested(0, peer))...)
	return out
}

// nlMessage frames a netlink message: nlmsghdr + body.
func nlMessage(msgType, flags uint16, seq uint32, body []byte) []byte {
	total := syscall.NLMSG_HDRLEN + len(body)
	out := make([]byte, syscall.NLMSG_HDRLEN, total)
	nativeEndian.PutUint32(out[0:4], uint32(total))
	nativeEndian.PutUint16(out[4:6], msgType)
	nativeEndian.PutUint16(out[6:8], flags)
	nativeEndian.PutUint32(out[8:12], seq)
	nativeEndian.PutUint32(out[12:16], 0)
	return append(out, body...)
}

// genlMessage frames a generic-netlink message: nlmsghdr + genlmsghdr + attrs.
func genlMessage(family, flags uint16, seq uint32, cmd, version uint8, attrs []byte) []byte {
	body := make([]byte, genlHdrLen, genlHdrLen+len(attrs))
	body[0] = cmd
	body[1] = version
	return nlMessage(family, flags, seq, append(body, attrs...))
}

// attrWalk iterates netlink attributes in b, calling fn(type, value) for each.
func attrWalk(b []byte, fn func(typ uint16, val []byte)) {
	for len(b) >= 4 {
		l := nativeEndian.Uint16(b[0:2])
		t := nativeEndian.Uint16(b[2:4])
		if int(l) < 4 || int(l) > len(b) {
			return
		}
		fn(t&nlaTypeMask, b[4:l])
		adv := (int(l) + 3) &^ 3
		if adv > len(b) {
			return
		}
		b = b[adv:]
	}
}

// parseFamilyID extracts CTRL_ATTR_FAMILY_ID from a CTRL_CMD_GETFAMILY reply.
func parseFamilyID(resp []byte) (uint16, error) {
	msgs, err := syscall.ParseNetlinkMessage(resp)
	if err != nil {
		return 0, fmt.Errorf("wg: parse genl reply: %w", err)
	}
	for _, m := range msgs {
		if m.Header.Type == syscall.NLMSG_ERROR {
			return 0, ackErr(m.Data)
		}
		if len(m.Data) < genlHdrLen {
			continue
		}
		var id uint16
		attrWalk(m.Data[genlHdrLen:], func(typ uint16, val []byte) {
			if typ == ctrlAttrFamilyID && len(val) >= 2 {
				id = nativeEndian.Uint16(val)
			}
		})
		if id != 0 {
			return id, nil
		}
	}
	return 0, errors.New("wg: wireguard genl family not found (kernel module loaded?)")
}

// --- netlink I/O ------------------------------------------------------------

// roundtrip opens a netlink socket of proto, sends req, and returns the reply.
func roundtrip(proto int, req []byte) ([]byte, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, fmt.Errorf("wg: netlink socket: %w", err)
	}
	defer syscall.Close(fd)
	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, sa); err != nil {
		return nil, fmt.Errorf("wg: netlink bind: %w", err)
	}
	if err := syscall.Sendto(fd, req, 0, sa); err != nil {
		return nil, fmt.Errorf("wg: netlink send: %w", err)
	}
	buf := make([]byte, 1<<16)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return nil, fmt.Errorf("wg: netlink recv: %w", err)
	}
	return buf[:n], nil
}

// ackErr decodes an NLMSG_ERROR payload (leading negated errno). Zero is success.
func ackErr(payload []byte) error {
	if len(payload) < 4 {
		return errors.New("wg: short netlink error payload")
	}
	code := int32(nativeEndian.Uint32(payload[0:4]))
	if code == 0 {
		return nil
	}
	return syscall.Errno(-code)
}

// expectAck reads the kernel's NLMSG_ERROR reply (0 = success).
func expectAck(resp []byte, what string) error {
	msgs, err := syscall.ParseNetlinkMessage(resp)
	if err != nil {
		return fmt.Errorf("wg: parse %s ack: %w", what, err)
	}
	for _, m := range msgs {
		if m.Header.Type == syscall.NLMSG_ERROR {
			if e := ackErr(m.Data); e != nil {
				return fmt.Errorf("wg: %s: %w", what, e)
			}
			return nil
		}
	}
	return nil
}

// --- link / address operations over NETLINK_ROUTE ---------------------------

const reqAck = syscall.NLM_F_REQUEST | syscall.NLM_F_ACK

func createLink(name string) error {
	ifi := make([]byte, syscall.SizeofIfInfomsg) // AF_UNSPEC, index 0
	body := append([]byte{}, ifi...)
	body = append(body, nlAttr(syscall.IFLA_IFNAME, append([]byte(name), 0))...)
	kind := nlAttr(iflaInfoKind, append([]byte(wgGenlName), 0))
	body = append(body, nlNested(iflaLinkinfo, kind)...)
	req := nlMessage(syscall.RTM_NEWLINK, reqAck|syscall.NLM_F_CREATE|syscall.NLM_F_EXCL, 1, body)
	resp, err := roundtrip(syscall.NETLINK_ROUTE, req)
	if err != nil {
		return err
	}
	return expectAck(resp, "create link")
}

func setLinkUp(ifindex int) error {
	ifi := make([]byte, syscall.SizeofIfInfomsg)
	nativeEndian.PutUint32(ifi[4:8], uint32(ifindex))  // ifi_index
	nativeEndian.PutUint32(ifi[8:12], syscall.IFF_UP)  // ifi_flags
	nativeEndian.PutUint32(ifi[12:16], syscall.IFF_UP) // ifi_change
	req := nlMessage(syscall.RTM_NEWLINK, reqAck, 1, ifi)
	resp, err := roundtrip(syscall.NETLINK_ROUTE, req)
	if err != nil {
		return err
	}
	return expectAck(resp, "set link up")
}

func delLink(ifindex int) error {
	ifi := make([]byte, syscall.SizeofIfInfomsg)
	nativeEndian.PutUint32(ifi[4:8], uint32(ifindex))
	req := nlMessage(syscall.RTM_DELLINK, reqAck, 1, ifi)
	resp, err := roundtrip(syscall.NETLINK_ROUTE, req)
	if err != nil {
		return err
	}
	return expectAck(resp, "delete link")
}

func addrAdd(ifindex int, p netip.Prefix) error {
	v4 := p.Addr().As4()
	ifa := make([]byte, syscall.SizeofIfAddrmsg)
	ifa[0] = syscall.AF_INET
	ifa[1] = byte(p.Bits())
	ifa[3] = rtScopeUniverse
	nativeEndian.PutUint32(ifa[4:8], uint32(ifindex))
	body := append([]byte{}, ifa...)
	body = append(body, nlAttr(syscall.IFA_LOCAL, v4[:])...)
	body = append(body, nlAttr(syscall.IFA_ADDRESS, v4[:])...)
	req := nlMessage(syscall.RTM_NEWADDR, reqAck|syscall.NLM_F_CREATE|syscall.NLM_F_REPLACE, 1, body)
	resp, err := roundtrip(syscall.NETLINK_ROUTE, req)
	if err != nil {
		return err
	}
	return expectAck(resp, "add address")
}

// routeAdd installs a route for dst out the given interface (scope link — the
// partner's VIP is directly connected over its bnetN). The route is dropped
// automatically when the interface is deleted, so teardown needs no counterpart.
// Kernel WireGuard does not add routes itself (unlike wg-quick), so the overlay
// needs this explicit /32 per partner when each buddy has its own interface (a
// shared /16 would overlap across the bnet0..N interfaces).
func routeAdd(ifindex int, dst netip.Prefix) error {
	d4 := dst.Addr().As4()
	rtm := make([]byte, syscall.SizeofRtMsg)
	rtm[0] = syscall.AF_INET
	rtm[1] = byte(dst.Bits()) // dst_len
	rtm[4] = rtTableMain
	rtm[5] = rtProtBoot
	rtm[6] = rtScopeLink
	rtm[7] = rtnUnicast
	body := append([]byte{}, rtm...)
	body = append(body, nlAttr(syscall.RTA_DST, d4[:])...)
	var oif [4]byte
	nativeEndian.PutUint32(oif[:], uint32(ifindex))
	body = append(body, nlAttr(syscall.RTA_OIF, oif[:])...)
	req := nlMessage(syscall.RTM_NEWROUTE, reqAck|syscall.NLM_F_CREATE|syscall.NLM_F_REPLACE, 1, body)
	resp, err := roundtrip(syscall.NETLINK_ROUTE, req)
	if err != nil {
		return err
	}
	return expectAck(resp, "add route")
}

// --- device config over NETLINK_GENERIC -------------------------------------

func resolveFamily(name string) (uint16, error) {
	attrs := nlAttr(ctrlAttrFamilyName, append([]byte(name), 0))
	req := genlMessage(genlIDCtrl, syscall.NLM_F_REQUEST, 1, ctrlCmdGetFamily, 1, attrs)
	resp, err := roundtrip(syscall.NETLINK_GENERIC, req)
	if err != nil {
		return 0, err
	}
	return parseFamilyID(resp)
}

func setDevice(family uint16, ifindex int, cfg Config) error {
	return sendSetDevice(family, buildSetDeviceAttrs(ifindex, cfg))
}

// sendSetDevice issues one WG_CMD_SET_DEVICE with the given attribute body.
func sendSetDevice(family uint16, attrs []byte) error {
	req := genlMessage(family, reqAck, 1, wgCmdSetDevice, wgGenlVersion, attrs)
	resp, err := roundtrip(syscall.NETLINK_GENERIC, req)
	if err != nil {
		return err
	}
	return expectAck(resp, "set device")
}

// resolveDevice looks up the wireguard genl family and the index of an existing
// interface by name.
func resolveDevice(ifName string) (family uint16, ifindex int, err error) {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return 0, 0, fmt.Errorf("wg: device %q not found: %w", ifName, err)
	}
	family, err = resolveFamily(wgGenlName)
	if err != nil {
		return 0, 0, err
	}
	return family, iface.Index, nil
}

// AddPeer adds or updates a single peer on an existing device, leaving the
// device's other peers intact (the bnet0 adapter model — one device, one peer per
// buddy). Re-adding the same public key updates that peer's endpoint/allowed-ips.
func AddPeer(ifName string, p Peer) error {
	if p.PublicKey == ([32]byte{}) {
		return errors.New("wg: AddPeer: zero PublicKey")
	}
	family, ifindex, err := resolveDevice(ifName)
	if err != nil {
		return err
	}
	return sendSetDevice(family, buildAddPeerAttrs(ifindex, p))
}

// RemovePeer removes a single peer by its public key, leaving other peers intact.
// Removing an unknown peer is a no-op (the kernel does not error).
func RemovePeer(ifName string, pub [32]byte) error {
	family, ifindex, err := resolveDevice(ifName)
	if err != nil {
		return err
	}
	return sendSetDevice(family, buildRemovePeerAttrs(ifindex, pub))
}

// --- orchestration ----------------------------------------------------------

// Up creates the WireGuard interface, configures it and the peer, assigns the
// address and brings the link up. It returns a teardown func that removes the
// interface (which also drops its addresses and connected routes). On a host
// without NET_ADMIN or the wireguard module, the returned error wraps
// syscall.EPERM / syscall.ENODEV so callers can degrade gracefully.
func Up(cfg Config) (down func() error, err error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	// Clean any stale interface of the same name so repeated runs are idempotent.
	if existing, e := net.InterfaceByName(cfg.IfName); e == nil {
		_ = delLink(existing.Index)
	}
	if err := createLink(cfg.IfName); err != nil {
		return nil, fmt.Errorf("wg: create %s: %w", cfg.IfName, err)
	}
	iface, err := net.InterfaceByName(cfg.IfName)
	if err != nil {
		_ = delLinkByName(cfg.IfName)
		return nil, fmt.Errorf("wg: lookup %s after create: %w", cfg.IfName, err)
	}
	ifindex := iface.Index
	teardown := func() error { return delLink(ifindex) }

	family, err := resolveFamily(wgGenlName)
	if err != nil {
		_ = teardown()
		return nil, err
	}
	if err := setDevice(family, ifindex, cfg); err != nil {
		_ = teardown()
		return nil, err
	}
	if cfg.Address.IsValid() {
		if err := addrAdd(ifindex, cfg.Address); err != nil {
			_ = teardown()
			return nil, err
		}
	}
	if err := setLinkUp(ifindex); err != nil {
		_ = teardown()
		return nil, err
	}
	// Per-partner routes (one interface per buddy): the connected /32 to the
	// partner's VIP out this interface. Added after link-up; removed implicitly
	// when teardown deletes the interface.
	for _, r := range cfg.Routes {
		if err := routeAdd(ifindex, r); err != nil {
			_ = teardown()
			return nil, fmt.Errorf("wg: add route %s: %w", r, err)
		}
	}

	released := false
	return func() error {
		if released {
			return nil
		}
		released = true
		return teardown()
	}, nil
}

// PeerEndpoint returns the underlay UDP endpoint the kernel currently has for the
// peer with public key peerPub on ifName — the address it learned from that peer's
// completed WireGuard handshake. It returns an invalid AddrPort (ok=false) when the
// peer exists but has no endpoint yet, and an error only on a netlink failure.
//
// This is the WG-handshake's endpoint discovery: when a REGISTER arrives inside the
// ephemeral WireGuard tunnel, the inner source is only the buddy's VIP, so the
// server cannot observe a punchable address from the datagram. The kernel, however,
// knows the buddy's real outer endpoint (the WG peer endpoint) — this reads it, so
// direct hole-punching still works over a WireGuard control plane.
func PeerEndpoint(ifName string, peerPub [32]byte) (ap netip.AddrPort, ok bool, err error) {
	family, ifindex, err := resolveDevice(ifName)
	if err != nil {
		return netip.AddrPort{}, false, err
	}
	req := genlMessage(family, syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP, 1,
		wgCmdGetDevice, wgGenlVersion, nlAttrU32(wgDeviceAIfindex, uint32(ifindex)))
	resp, err := dump(req)
	if err != nil {
		return netip.AddrPort{}, false, err
	}
	msgs, perr := syscall.ParseNetlinkMessage(resp)
	if perr != nil {
		return netip.AddrPort{}, false, fmt.Errorf("wg: parse get-device: %w", perr)
	}
	for _, m := range msgs {
		if m.Header.Type == syscall.NLMSG_DONE || m.Header.Type == syscall.NLMSG_ERROR ||
			m.Header.Type == syscall.NLMSG_NOOP || len(m.Data) < genlHdrLen {
			continue
		}
		attrWalk(m.Data[genlHdrLen:], func(typ uint16, val []byte) {
			if typ != wgDeviceAPeers {
				return
			}
			attrWalk(val, func(_ uint16, peer []byte) { // each nested entry is one peer
				var thisPub [32]byte
				var endpoint []byte
				attrWalk(peer, func(pt uint16, pv []byte) {
					switch pt {
					case wgPeerAPublicKey:
						copy(thisPub[:], pv)
					case wgPeerAEndpoint:
						endpoint = pv
					}
				})
				if thisPub == peerPub && len(endpoint) > 0 {
					if a, dok := decodeSockaddr(endpoint); dok {
						ap, ok = a, true
					}
				}
			})
		})
	}
	return ap, ok, nil
}

// decodeSockaddr reverses encodeSockaddr: a struct sockaddr_in / sockaddr_in6 as
// the kernel reports in WGPEER_A_ENDPOINT (family host-order, port/addr network-order).
func decodeSockaddr(b []byte) (netip.AddrPort, bool) {
	if len(b) < 4 {
		return netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(b[2:4])
	switch nativeEndian.Uint16(b[0:2]) {
	case syscall.AF_INET:
		if len(b) < 8 {
			return netip.AddrPort{}, false
		}
		var a [4]byte
		copy(a[:], b[4:8])
		return netip.AddrPortFrom(netip.AddrFrom4(a), port), true
	case syscall.AF_INET6:
		if len(b) < 24 {
			return netip.AddrPort{}, false
		}
		var a [16]byte
		copy(a[:], b[8:24])
		return netip.AddrPortFrom(netip.AddrFrom16(a), port), true
	}
	return netip.AddrPort{}, false
}

// dump performs a multi-part NETLINK_GENERIC request, concatenating every reply
// datagram until NLMSG_DONE (a GET_DEVICE dump can span several recvs).
func dump(req []byte) ([]byte, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_GENERIC)
	if err != nil {
		return nil, fmt.Errorf("wg: netlink socket: %w", err)
	}
	defer syscall.Close(fd)
	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, sa); err != nil {
		return nil, fmt.Errorf("wg: netlink bind: %w", err)
	}
	if err := syscall.Sendto(fd, req, 0, sa); err != nil {
		return nil, fmt.Errorf("wg: netlink send: %w", err)
	}
	var out []byte
	for {
		buf := make([]byte, 1<<16)
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, fmt.Errorf("wg: netlink recv: %w", err)
		}
		msgs, perr := syscall.ParseNetlinkMessage(buf[:n])
		if perr != nil {
			return nil, fmt.Errorf("wg: parse dump: %w", perr)
		}
		done := false
		for _, m := range msgs {
			if m.Header.Type == syscall.NLMSG_ERROR {
				if e := ackErr(m.Data); e != nil {
					return nil, fmt.Errorf("wg: get-device: %w", e)
				}
			}
			if m.Header.Type == syscall.NLMSG_DONE {
				done = true
			}
		}
		out = append(out, buf[:n]...)
		if done {
			break
		}
	}
	return out, nil
}

func delLinkByName(name string) error {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	return delLink(iface.Index)
}

// Available reports whether kernel WireGuard can be brought up on this host —
// Linux with NET_ADMIN and the wireguard module — by creating and immediately
// deleting a throwaway device. Callers use it to choose the WG data path and fall
// back to QUIC otherwise. Cheap and side-effect-free (the probe device is removed).
func Available() bool {
	const probe = "bn-probe0"
	_ = delLinkByName(probe) // clear any leftover from a crashed run
	if err := createLink(probe); err != nil {
		return false
	}
	_ = delLinkByName(probe)
	return true
}
