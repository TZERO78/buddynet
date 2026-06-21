//go:build linux

package wg

import (
	"net/netip"
	"syscall"
	"testing"
)

func TestNlAttrAlignment(t *testing.T) {
	// 3-byte payload → 4 (hdr) + 3 = 7, padded to 8.
	a := nlAttr(7, []byte{1, 2, 3})
	if len(a) != 8 {
		t.Fatalf("want padded len 8, got %d", len(a))
	}
	if got := nativeEndian.Uint16(a[0:2]); got != 7 {
		t.Fatalf("nla_len: want 7, got %d", got)
	}
	if got := nativeEndian.Uint16(a[2:4]); got != 7 {
		t.Fatalf("nla_type: want 7, got %d", got)
	}
	if a[7] != 0 {
		t.Fatalf("padding byte not zero")
	}
}

func TestNlNestedSetsFlag(t *testing.T) {
	n := nlNested(8, nlAttrU32(1, 0xdeadbeef))
	typ := nativeEndian.Uint16(n[2:4])
	if typ&nlaFNested == 0 {
		t.Fatalf("nested flag not set on type 0x%x", typ)
	}
	if typ&nlaTypeMask != 8 {
		t.Fatalf("masked type: want 8, got %d", typ&nlaTypeMask)
	}
}

func TestEncodeSockaddrV4(t *testing.T) {
	ap := netip.MustParseAddrPort("203.0.113.7:51820")
	b := encodeSockaddr(ap)
	if len(b) != 16 {
		t.Fatalf("sockaddr_in size: want 16, got %d", len(b))
	}
	if fam := nativeEndian.Uint16(b[0:2]); fam != uint16(syscall.AF_INET) {
		t.Fatalf("family: want AF_INET, got %d", fam)
	}
	// Port is network byte order (big-endian): 51820 = 0xCA6C.
	if b[2] != 0xCA || b[3] != 0x6C {
		t.Fatalf("port bytes: want CA 6C, got %02X %02X", b[2], b[3])
	}
	if b[4] != 203 || b[5] != 0 || b[6] != 113 || b[7] != 7 {
		t.Fatalf("addr bytes wrong: %v", b[4:8])
	}
}

func TestEncodeSockaddrV6Size(t *testing.T) {
	ap := netip.MustParseAddrPort("[2001:db8::1]:51820")
	if got := len(encodeSockaddr(ap)); got != 28 {
		t.Fatalf("sockaddr_in6 size: want 28, got %d", got)
	}
}

func TestBuildAllowedIPRoundTrip(t *testing.T) {
	p := netip.MustParsePrefix("10.66.5.9/32")
	got := map[uint16][]byte{}
	attrWalk(buildAllowedIP(p), func(typ uint16, val []byte) { got[typ] = val })

	if fam := nativeEndian.Uint16(got[wgAllowedipAFamily]); fam != uint16(syscall.AF_INET) {
		t.Fatalf("allowedip family: want AF_INET, got %d", fam)
	}
	ip := got[wgAllowedipAIpaddr]
	if len(ip) != 4 || ip[0] != 10 || ip[1] != 66 || ip[2] != 5 || ip[3] != 9 {
		t.Fatalf("allowedip addr wrong: %v", ip)
	}
	if mask := got[wgAllowedipACidrMask]; len(mask) != 1 || mask[0] != 32 {
		t.Fatalf("allowedip cidr mask wrong: %v", mask)
	}
}

func TestBuildSetDeviceAttrsTopLevel(t *testing.T) {
	cfg := Config{
		IfName:     "bn-wg0",
		PrivateKey: [32]byte{1, 2, 3},
		ListenPort: 51820,
		Peer: Peer{
			PublicKey:  [32]byte{9, 9, 9},
			Endpoint:   netip.MustParseAddrPort("198.51.100.4:7000"),
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.66.1.2/32")},
			Keepalive:  25,
		},
	}
	seen := map[uint16]bool{}
	var peers []byte
	attrWalk(buildSetDeviceAttrs(7, cfg), func(typ uint16, val []byte) {
		seen[typ] = true
		if typ == wgDeviceAPeers {
			peers = val
		}
	})
	for _, want := range []uint16{wgDeviceAIfindex, wgDeviceAFlags, wgDeviceAPrivateKey, wgDeviceAListenPort, wgDeviceAPeers} {
		if !seen[want] {
			t.Fatalf("missing top-level device attr %d", want)
		}
	}
	// The peers nest must contain exactly one indexed entry (index 0) carrying a
	// public key.
	var entries int
	attrWalk(peers, func(typ uint16, val []byte) {
		if typ != 0 {
			t.Fatalf("unexpected peer index %d", typ)
		}
		entries++
		var hasPub bool
		attrWalk(val, func(pt uint16, pv []byte) {
			if pt == wgPeerAPublicKey && len(pv) == 32 {
				hasPub = true
			}
		})
		if !hasPub {
			t.Fatalf("peer entry missing 32-byte public key")
		}
	})
	if entries != 1 {
		t.Fatalf("want 1 peer entry, got %d", entries)
	}
}

// TestPeerAttrNumbers pins the WGPEER_A_* attribute numbers to the kernel uapi
// values (uapi/linux/wireguard.h) using hard-coded literals — verified against
// the real `wg` tool's netlink bytes. A regression to 0-based numbering (an easy
// mistake: WGPEER_A_UNSPEC = 0) would make the kernel reject SET_DEVICE with
// EINVAL, which unit tests on encoding alone would NOT catch.
func TestPeerAttrNumbers(t *testing.T) {
	if wgPeerAPublicKey != 1 || wgPeerAFlags != 3 || wgPeerAEndpoint != 4 ||
		wgPeerAPersistentKeepaliveInterval != 5 || wgPeerAAllowedips != 9 {
		t.Fatalf("WGPEER_A_* numbers drifted from kernel uapi: pub=%d flags=%d ep=%d ka=%d aip=%d (want 1,3,4,5,9)",
			wgPeerAPublicKey, wgPeerAFlags, wgPeerAEndpoint, wgPeerAPersistentKeepaliveInterval, wgPeerAAllowedips)
	}
	// WGPEER_F_REPLACE_ALLOWEDIPS is 1<<1; 1<<0 is WGPEER_F_REMOVE_ME.
	if wgPeerFReplaceAllowedips != 2 {
		t.Fatalf("WGPEER_F_REPLACE_ALLOWEDIPS = %d, want 2 (1 would REMOVE the peer)", wgPeerFReplaceAllowedips)
	}
	// Device-level numbers (verified against `wg`): ifindex=1, privkey=3,
	// flags=5, listenport=6, peers=8; allowed-ip: family=1, addr=2, cidr=3.
	if wgDeviceAIfindex != 1 || wgDeviceAPrivateKey != 3 || wgDeviceAFlags != 5 ||
		wgDeviceAListenPort != 6 || wgDeviceAPeers != 8 {
		t.Fatalf("WGDEVICE_A_* numbers drifted from kernel uapi")
	}
	if wgAllowedipAFamily != 1 || wgAllowedipAIpaddr != 2 || wgAllowedipACidrMask != 3 {
		t.Fatalf("WGALLOWEDIP_A_* numbers drifted from kernel uapi")
	}
}

func TestParseFamilyID(t *testing.T) {
	// Synthesize a CTRL_NEWFAMILY reply: nlmsghdr + genlmsghdr + FAMILY_ID attr.
	attrs := nlAttrU16(ctrlAttrFamilyID, 0x2a)
	msg := genlMessage(genlIDCtrl, 0, 1, 1 /*CTRL_NEWFAMILY*/, 1, attrs)
	id, err := parseFamilyID(msg)
	if err != nil {
		t.Fatalf("parseFamilyID: %v", err)
	}
	if id != 0x2a {
		t.Fatalf("family id: want 0x2a, got 0x%x", id)
	}
}

func TestParseFamilyIDError(t *testing.T) {
	// An NLMSG_ERROR with non-zero errno must surface as an error.
	payload := make([]byte, 4)
	var code int32 = -int32(syscall.ENOENT)
	nativeEndian.PutUint32(payload, uint32(code))
	msg := nlMessage(syscall.NLMSG_ERROR, 0, 1, payload)
	if _, err := parseFamilyID(msg); err == nil {
		t.Fatalf("want error for NLMSG_ERROR reply, got nil")
	}
}

func TestConfigValidate(t *testing.T) {
	good := Config{IfName: "bn-wg0", PrivateKey: [32]byte{1}, Peer: Peer{PublicKey: [32]byte{1}}}
	if err := good.validate(); err != nil {
		t.Fatalf("good config rejected: %v", err)
	}
	bad := []Config{
		{IfName: "", PrivateKey: [32]byte{1}, Peer: Peer{PublicKey: [32]byte{1}}},
		{IfName: "waytoolonginterfacename", PrivateKey: [32]byte{1}, Peer: Peer{PublicKey: [32]byte{1}}},
		{IfName: "bn-wg0", Peer: Peer{PublicKey: [32]byte{1}}},
		{IfName: "bn-wg0", PrivateKey: [32]byte{1}},
	}
	for i, c := range bad {
		if err := c.validate(); err == nil {
			t.Fatalf("bad config %d accepted", i)
		}
	}
}
