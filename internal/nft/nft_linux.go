//go:build linux

package nft

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"syscall"
)

// This file programs the scoped-exposure rules into the kernel's nftables
// subsystem over raw NETLINK_NETFILTER — the same no-subprocess posture as
// internal/wg. Everything lives in the private `table inet buddynet` with one
// base chain on the input hook (policy accept, so the host's other traffic is
// never affected); per bnetN the rules are:
//
//	iifname "bnetN" ct state established,related accept
//	iifname "bnetN" <proto> dport <port> accept        (per exposed port)
//	iifname "bnetN" meta l4proto {icmp,icmpv6} accept  (ping for diagnosis)
//	iifname "bnetN" drop
//
// State is rebuilt atomically on every change with the add-table/del-table/
// add-table batch idiom, so a stale table from a SIGKILLed run is cleared on
// the next Apply and teardown is idempotent.

// --- nftables netlink constants (uapi/linux/netfilter/nf_tables.h) ----------

const (
	nfnlSubsysNftables = 10
	nfnlMsgBatchBegin  = 0x10
	nfnlMsgBatchEnd    = 0x11

	nftMsgNewTable = 0
	nftMsgDelTable = 2
	nftMsgNewChain = 3
	nftMsgNewRule  = 6

	nfprotoInet   = 1
	nfInetLocalIn = 1 // NF_INET_LOCAL_IN hook
	nfAccept      = 1 // NF_ACCEPT verdict
	nfDrop        = 0 // NF_DROP verdict

	nftaTableName = 1

	nftaChainTable  = 1
	nftaChainName   = 3
	nftaChainHook   = 4
	nftaChainPolicy = 5
	nftaChainType   = 7

	nftaHookHooknum  = 1
	nftaHookPriority = 2

	nftaRuleTable       = 1
	nftaRuleChain       = 2
	nftaRuleExpressions = 4

	nftaListElem = 1
	nftaExprName = 1
	nftaExprData = 2

	nftaMetaDreg = 1
	nftaMetaKey  = 2

	nftMetaIifname = 6
	nftMetaL4Proto = 16

	nftaCmpSreg = 1
	nftaCmpOp   = 2
	nftaCmpData = 3

	nftCmpEq  = 0
	nftCmpNeq = 1

	nftaPayloadDreg   = 1
	nftaPayloadBase   = 2
	nftaPayloadOffset = 3
	nftaPayloadLen    = 4

	nftPayloadTransportHeader = 2

	nftaCtDreg = 1
	nftaCtKey  = 2

	nftCtState = 0
	// conntrack state bits (uapi ip_conntrack_common.h, as nft ct state sees them)
	ctStateEstablished = 1 << 1
	ctStateRelated     = 1 << 2

	nftaBitwiseSreg = 1
	nftaBitwiseDreg = 2
	nftaBitwiseLen  = 3
	nftaBitwiseMask = 4
	nftaBitwiseXor  = 5

	nftaImmediateDreg = 1
	nftaImmediateData = 2

	nftaDataValue   = 1
	nftaDataVerdict = 2

	nftaVerdictCode = 1

	nftRegVerdict = 0
	nftReg1       = 1

	nlaFNested  = 0x8000
	nlaTypeMask = 0x3fff

	ifNameSize = 16 // IFNAMSIZ — meta iifname loads this many zero-padded bytes

	tableName = "buddynet"
	chainName = "in"
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

// nlAttrBE32 encodes a u32 attribute. Unlike rtnetlink, the nftables subsystem
// carries its u32s in network byte order (libnftnl uses htonl throughout).
func nlAttrBE32(typ uint16, v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return nlAttr(typ, b)
}

func nlAttrStrZ(typ uint16, s string) []byte {
	return nlAttr(typ, append([]byte(s), 0))
}

// nlNested wraps an attribute payload as a nested attribute.
func nlNested(typ uint16, payload []byte) []byte {
	return nlAttr(typ|nlaFNested, payload)
}

// expr encodes one NFTA_LIST_ELEM expression: its kernel name + attribute body.
func expr(name string, data []byte) []byte {
	body := nlAttrStrZ(nftaExprName, name)
	body = append(body, nlNested(nftaExprData, data)...)
	return nlNested(nftaListElem, body)
}

// dataValue wraps a raw register value for NFTA_CMP_DATA / NFTA_BITWISE_MASK…
func dataValue(typ uint16, b []byte) []byte {
	return nlNested(typ, nlAttr(nftaDataValue, b))
}

// exprCmp compares NFT_REG_1 against a constant.
func exprCmp(op uint32, value []byte) []byte {
	d := nlAttrBE32(nftaCmpSreg, nftReg1)
	d = append(d, nlAttrBE32(nftaCmpOp, op)...)
	d = append(d, dataValue(nftaCmpData, value)...)
	return expr("cmp", d)
}

// exprsIifname loads meta iifname and compares it to name (zero-padded to
// IFNAMSIZ, the register layout meta produces).
func exprsIifname(name string) []byte {
	d := nlAttrBE32(nftaMetaDreg, nftReg1)
	d = append(d, nlAttrBE32(nftaMetaKey, nftMetaIifname)...)
	out := expr("meta", d)
	padded := make([]byte, ifNameSize)
	copy(padded, name)
	return append(out, exprCmp(nftCmpEq, padded)...)
}

// exprsL4Proto matches meta l4proto == proto (IPPROTO_*, one byte).
func exprsL4Proto(proto byte) []byte {
	d := nlAttrBE32(nftaMetaDreg, nftReg1)
	d = append(d, nlAttrBE32(nftaMetaKey, nftMetaL4Proto)...)
	out := expr("meta", d)
	return append(out, exprCmp(nftCmpEq, []byte{proto})...)
}

// exprsDport matches the transport-header destination port (offset 2, len 2,
// network byte order — same layout for TCP and UDP).
func exprsDport(port uint16) []byte {
	d := nlAttrBE32(nftaPayloadDreg, nftReg1)
	d = append(d, nlAttrBE32(nftaPayloadBase, nftPayloadTransportHeader)...)
	d = append(d, nlAttrBE32(nftaPayloadOffset, 2)...)
	d = append(d, nlAttrBE32(nftaPayloadLen, 2)...)
	out := expr("payload", d)
	v := make([]byte, 2)
	binary.BigEndian.PutUint16(v, port)
	return append(out, exprCmp(nftCmpEq, v)...)
}

// exprsCtStateEstRel matches ct state established,related: load the state
// bits, mask with (ESTABLISHED|RELATED), compare != 0. The register value is
// host-endian (ct loads a host-order u32).
func exprsCtStateEstRel() []byte {
	d := nlAttrBE32(nftaCtDreg, nftReg1)
	d = append(d, nlAttrBE32(nftaCtKey, nftCtState)...)
	out := expr("ct", d)

	mask := make([]byte, 4)
	nativeEndian.PutUint32(mask, ctStateEstablished|ctStateRelated)
	bw := nlAttrBE32(nftaBitwiseSreg, nftReg1)
	bw = append(bw, nlAttrBE32(nftaBitwiseDreg, nftReg1)...)
	bw = append(bw, nlAttrBE32(nftaBitwiseLen, 4)...)
	bw = append(bw, dataValue(nftaBitwiseMask, mask)...)
	bw = append(bw, dataValue(nftaBitwiseXor, make([]byte, 4))...)
	out = append(out, expr("bitwise", bw)...)

	return append(out, exprCmp(nftCmpNeq, make([]byte, 4))...)
}

// exprVerdict emits an immediate verdict (NF_ACCEPT / NF_DROP).
func exprVerdict(code uint32) []byte {
	verdict := nlNested(nftaDataVerdict, nlAttrBE32(nftaVerdictCode, code))
	d := nlAttrBE32(nftaImmediateDreg, nftRegVerdict)
	d = append(d, nlNested(nftaImmediateData, verdict)...)
	return expr("immediate", d)
}

// ruleExprs builds the expression lists for one interface's scope, in match
// order. A Scope with All set yields no rules (the chain's accept policy
// exposes the host — the operator said `all` explicitly).
func ruleExprs(ifName string, s Scope) [][]byte {
	if s.All {
		return nil
	}
	var rules [][]byte
	add := func(exprs ...[]byte) {
		var rule []byte
		for _, e := range exprs {
			rule = append(rule, e...)
		}
		rules = append(rules, rule)
	}
	// Established/related first: return traffic for our own outbound
	// connections to the buddy stays allowed even with nothing exposed.
	add(exprsIifname(ifName), exprsCtStateEstRel(), exprVerdict(nfAccept))
	for _, p := range s.Ports {
		proto := byte(syscall.IPPROTO_TCP)
		if p.Proto == "udp" {
			proto = syscall.IPPROTO_UDP
		}
		add(exprsIifname(ifName), exprsL4Proto(proto), exprsDport(p.Port), exprVerdict(nfAccept))
	}
	// Ping stays possible so "is the tunnel up" is diagnosable with nothing exposed.
	add(exprsIifname(ifName), exprsL4Proto(syscall.IPPROTO_ICMP), exprVerdict(nfAccept))
	add(exprsIifname(ifName), exprsL4Proto(syscall.IPPROTO_ICMPV6), exprVerdict(nfAccept))
	// Everything else from this buddy is dropped — the fail-closed floor.
	add(exprsIifname(ifName), exprVerdict(nfDrop))
	return rules
}

// --- nftables message framing ------------------------------------------------

// nftMessage frames one nftables message: nlmsghdr + nfgenmsg + attrs. The
// nfgenmsg res_id is big-endian per nfnetlink convention.
func nftMessage(msgType, flags uint16, seq uint32, family uint8, attrs []byte) []byte {
	body := make([]byte, 4, 4+len(attrs)) // struct nfgenmsg
	body[0] = family
	body[1] = 0 // NFNETLINK_V0
	// res_id stays 0 for regular messages
	body = append(body, attrs...)

	total := syscall.NLMSG_HDRLEN + len(body)
	out := make([]byte, syscall.NLMSG_HDRLEN, total)
	nativeEndian.PutUint32(out[0:4], uint32(total))
	nativeEndian.PutUint16(out[4:6], msgType)
	nativeEndian.PutUint16(out[6:8], flags)
	nativeEndian.PutUint32(out[8:12], seq)
	nativeEndian.PutUint32(out[12:16], 0)
	return append(out, body...)
}

// batchDelim frames NFNL_MSG_BATCH_BEGIN/END, whose res_id names the subsystem.
func batchDelim(msgType uint16, seq uint32) []byte {
	out := nftMessage(msgType, syscall.NLM_F_REQUEST, seq, 0, nil)
	binary.BigEndian.PutUint16(out[syscall.NLMSG_HDRLEN+2:], nfnlSubsysNftables)
	return out
}

// buildBatch renders the complete desired ruleset for scopes as one atomic
// nfnetlink batch: ensure the table exists, delete it (clearing any stale
// state), and — if any interface is scoped — recreate it with the chain and
// rules. An empty scopes map therefore just removes the table.
func buildBatch(scopes map[string]Scope, order []string) []byte {
	const create = syscall.NLM_F_REQUEST | syscall.NLM_F_CREATE
	nft := func(msg uint16) uint16 { return nfnlSubsysNftables<<8 | msg }

	seq := uint32(1)
	next := func() uint32 { seq++; return seq }

	// The kernel does not ack the BATCH_END delimiter, so the LAST inner message
	// carries NLM_F_ACK — success then produces exactly one reply to wait for.
	var lastInner int // offset of the most recent inner message
	appendMsg := func(out, msg []byte) []byte {
		lastInner = len(out)
		return append(out, msg...)
	}

	out := batchDelim(nfnlMsgBatchBegin, seq)
	tbl := nlAttrStrZ(nftaTableName, tableName)
	// add-del-add idiom: the first NEWTABLE makes DELTABLE succeed even when the
	// table does not exist yet (older kernels have no "ignore ENOENT" delete).
	out = appendMsg(out, nftMessage(nft(nftMsgNewTable), create, next(), nfprotoInet, tbl))
	out = appendMsg(out, nftMessage(nft(nftMsgDelTable), syscall.NLM_F_REQUEST, next(), nfprotoInet, tbl))

	if len(scopes) > 0 {
		out = appendMsg(out, nftMessage(nft(nftMsgNewTable), create, next(), nfprotoInet, tbl))

		hook := nlAttrBE32(nftaHookHooknum, nfInetLocalIn)
		hook = append(hook, nlAttrBE32(nftaHookPriority, 0)...) // filter priority
		chain := nlAttrStrZ(nftaChainTable, tableName)
		chain = append(chain, nlAttrStrZ(nftaChainName, chainName)...)
		chain = append(chain, nlNested(nftaChainHook, hook)...)
		// Policy ACCEPT: this chain only ever restricts bnetN traffic; the host's
		// other interfaces and its own firewall are untouched.
		chain = append(chain, nlAttrBE32(nftaChainPolicy, nfAccept)...)
		chain = append(chain, nlAttrStrZ(nftaChainType, "filter")...)
		out = appendMsg(out, nftMessage(nft(nftMsgNewChain), create, next(), nfprotoInet, chain))

		for _, ifName := range order {
			for _, exprs := range ruleExprs(ifName, scopes[ifName]) {
				rule := nlAttrStrZ(nftaRuleTable, tableName)
				rule = append(rule, nlAttrStrZ(nftaRuleChain, chainName)...)
				rule = append(rule, nlNested(nftaRuleExpressions, exprs)...)
				out = appendMsg(out, nftMessage(nft(nftMsgNewRule), create|syscall.NLM_F_APPEND, next(), nfprotoInet, rule))
			}
		}
	}

	// Flag the last inner message for an ack (see appendMsg).
	flags := nativeEndian.Uint16(out[lastInner+6 : lastInner+8])
	nativeEndian.PutUint16(out[lastInner+6:lastInner+8], flags|syscall.NLM_F_ACK)

	return append(out, batchDelim(nfnlMsgBatchEnd, next())...)
}

// --- netlink I/O --------------------------------------------------------------

// sendBatch ships one batch to NETLINK_NETFILTER and waits for the ack/error.
func sendBatch(batch []byte) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_NETFILTER)
	if err != nil {
		return fmt.Errorf("nft: netlink socket: %w", err)
	}
	defer syscall.Close(fd)
	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, sa); err != nil {
		return fmt.Errorf("nft: netlink bind: %w", err)
	}
	// Safety net: never hang the tunnel bring-up on a missing ack.
	tv := syscall.Timeval{Sec: 5}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("nft: set recv timeout: %w", err)
	}
	if err := syscall.Sendto(fd, batch, 0, sa); err != nil {
		return fmt.Errorf("nft: netlink send: %w", err)
	}
	buf := make([]byte, 1<<16)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return fmt.Errorf("nft: netlink recv: %w", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return fmt.Errorf("nft: parse reply: %w", err)
	}
	for _, m := range msgs {
		if m.Header.Type != syscall.NLMSG_ERROR {
			continue
		}
		if len(m.Data) < 4 {
			return errors.New("nft: short netlink error payload")
		}
		if code := int32(nativeEndian.Uint32(m.Data[0:4])); code != 0 {
			return fmt.Errorf("nft: kernel rejected ruleset: %w", syscall.Errno(-code))
		}
	}
	return nil
}

// --- public API ----------------------------------------------------------------

// mu guards the desired per-interface state; every change re-renders the whole
// buddynet table atomically from it.
var (
	mu     sync.Mutex
	scopes = map[string]Scope{}
	order  []string // stable rule order across rebuilds
)

// Apply programs (or reprograms) the inbound scope for one interface,
// fail-closed: on error nothing is exposed AND the caller must not bring the
// tunnel up. A Scope with All set still creates the table entry (explicitly
// whole-host, visible in `nft list table inet buddynet` as the absence of
// rules for that interface).
func Apply(ifName string, s Scope) error {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := scopes[ifName]; !ok {
		order = append(order, ifName)
	}
	prev, had := scopes[ifName]
	scopes[ifName] = s
	if err := sendBatch(buildBatch(scopes, order)); err != nil {
		if had {
			scopes[ifName] = prev
		} else {
			delete(scopes, ifName)
			order = order[:len(order)-1]
		}
		return err
	}
	return nil
}

// Remove drops an interface's rules (called next to the wg teardown). When the
// last interface is gone the whole buddynet table is removed.
func Remove(ifName string) error {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := scopes[ifName]; !ok {
		return nil
	}
	delete(scopes, ifName)
	for i, n := range order {
		if n == ifName {
			order = append(order[:i], order[i+1:]...)
			break
		}
	}
	return sendBatch(buildBatch(scopes, order))
}
