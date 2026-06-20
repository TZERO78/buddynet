package dns

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"syscall"

	"github.com/miekg/dns"

	"github.com/tzero78/buddynet/internal/peer"
)

// stubAddr is the loopback address the .buddy stub resolver binds on.
// The full 127.0.0.0/8 block is loopback on Linux, so no interface setup is
// needed; we pick .153 to avoid conflicts with the default 127.0.0.1.
const stubAddr = "127.0.0.153:53"

// Run starts the .buddy stub resolver, binding UDP+TCP on stubAddr, and serves
// until ctx is cancelled. reg is read on every query (lock-free snapshot) so
// the table stays current as peers come and go.
//
// Graceful degradation: if the bind fails with a permission error (port 53
// requires CAP_NET_BIND_SERVICE or root), a WARNING is logged and Run returns
// nil — the tunnel keeps working, DNS is simply unavailable.
func Run(ctx context.Context, reg *peer.Registry, selfName string, selfIP netip.Addr) error {
	mux := dns.NewServeMux()
	mux.HandleFunc("buddy.", func(w dns.ResponseWriter, r *dns.Msg) {
		handleBuddy(w, r, reg, selfName, selfIP)
	})
	// Non-.buddy queries: return NXDOMAIN (this resolver is not authoritative
	// for any other TLD; the default ServeMux behaviour is REFUSED, which is
	// misleading for a stub that simply doesn't know about other namespaces).
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(m)
	})

	udpSrv := &dns.Server{Addr: stubAddr, Net: "udp", Handler: mux}
	tcpSrv := &dns.Server{Addr: stubAddr, Net: "tcp", Handler: mux}
	// Report the successful bind in the structured schema (the failure case is the
	// WARNING below); fires once the UDP listener is actually up.
	udpSrv.NotifyStartedFunc = func() { log.Printf("BUDDYDNS: action=listening addr=%s", stubAddr) }

	udpErr := make(chan error, 1)
	tcpErr := make(chan error, 1)

	go func() { udpErr <- udpSrv.ListenAndServe() }()
	go func() { tcpErr <- tcpSrv.ListenAndServe() }()

	// Wait briefly for both servers to start or fail.
	select {
	case err := <-udpErr:
		_ = tcpSrv.Shutdown()
		if isPermissionError(err) {
			log.Printf("WARNING: BuddyDNS disabled — cannot bind %s (need CAP_NET_BIND_SERVICE or root): %v", stubAddr, err)
			return nil
		}
		return err
	case err := <-tcpErr:
		_ = udpSrv.Shutdown()
		if isPermissionError(err) {
			log.Printf("WARNING: BuddyDNS disabled — cannot bind %s (need CAP_NET_BIND_SERVICE or root): %v", stubAddr, err)
			return nil
		}
		return err
	case <-ctx.Done():
		_ = udpSrv.Shutdown()
		_ = tcpSrv.Shutdown()
		return nil
	}
}

func handleBuddy(w dns.ResponseWriter, r *dns.Msg, reg *peer.Registry, selfName string, selfIP netip.Addr) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) == 0 {
		w.WriteMsg(m)
		return
	}
	q := r.Question[0]

	// Only answer A queries; return NXDOMAIN for everything else under .buddy.
	if q.Qtype != dns.TypeA {
		m.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(m)
		return
	}

	table := BuildTable(reg.Snapshot(), selfName, selfIP)
	addr, ok := Resolve(table, q.Name)
	if !ok {
		m.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(m)
		return
	}

	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(q.Name),
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: net.IP(addr.AsSlice()),
	}
	m.Answer = append(m.Answer, rr)
	w.WriteMsg(m)
}

func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return errors.Is(opErr.Err, syscall.EACCES) || errors.Is(opErr.Err, syscall.EPERM)
	}
	return false
}
