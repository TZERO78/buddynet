// Package nft gates inbound traffic on a buddy's WireGuard interface (bnetN) to
// an explicitly exposed set of ports — the scoped-exposure counterpart of
// wg.Up. It talks to the kernel's nftables subsystem directly over raw
// nfnetlink (the same no-subprocess, no-external-module posture as internal/wg
// and internal/vip), so it depends on NONE of nft/iptables/ufw/firewalld being
// installed — only on kernel nftables support and CAP_NET_ADMIN, both already
// required for the WireGuard data plane.
//
// All rules live in a dedicated `table inet buddynet`, separate from the
// host's own filter/ufw/firewalld tables: netfilter evaluates every table on
// the input hook and a DROP in any of them wins, so the per-bnetN scope is
// enforced regardless of what the host firewall allows, and a ufw/firewalld
// reload never touches it.
package nft

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Scope is the inbound exposure for one buddy interface: either the explicit
// whole host (All) or a fixed set of ports. The zero value is fail-closed —
// nothing exposed (established return traffic for our own outbound connections
// and ICMP ping stay allowed for diagnosis).
type Scope struct {
	All   bool
	Ports []Port // ignored when All is set
}

// Port is one exposed port. Proto is "tcp" or "udp".
type Port struct {
	Proto string
	Port  uint16
}

// ParseScope parses an --expose port specification: "all" for the explicit
// whole host, or a comma list of ports, each "873" (tcp by default) or
// "tcp/873" / "udp/51820". Duplicates are folded. An empty string is an error —
// fail-closed is expressed by NOT passing --expose, never by an empty value.
func ParseScope(spec string) (Scope, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return Scope{}, fmt.Errorf("empty --expose value (omit the flag for fail-closed, or name ports like 873 or tcp/873,udp/51820, or 'all')")
	}
	if strings.EqualFold(spec, "all") {
		return Scope{All: true}, nil
	}
	var s Scope
	for _, part := range strings.Split(spec, ",") {
		p, err := parsePort(part)
		if err != nil {
			return Scope{}, err
		}
		s.add(p)
	}
	s.normalize()
	return s, nil
}

// parsePort parses one "873" / "tcp/873" / "udp/51820" entry.
func parsePort(part string) (Port, error) {
	part = strings.TrimSpace(part)
	proto, portStr := "tcp", part
	if i := strings.IndexByte(part, '/'); i >= 0 {
		proto, portStr = strings.ToLower(strings.TrimSpace(part[:i])), strings.TrimSpace(part[i+1:])
	}
	if proto != "tcp" && proto != "udp" {
		return Port{}, fmt.Errorf("bad expose entry %q: protocol must be tcp or udp", part)
	}
	n, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || n == 0 {
		return Port{}, fmt.Errorf("bad expose entry %q: want a port 1-65535 like 873 or tcp/873 or udp/51820", part)
	}
	return Port{Proto: proto, Port: uint16(n)}, nil
}

func (s *Scope) add(p Port) {
	for _, q := range s.Ports {
		if q == p {
			return
		}
	}
	s.Ports = append(s.Ports, p)
}

// normalize sorts ports (tcp before udp, then numeric) so String() and the
// generated ruleset are deterministic regardless of input order.
func (s *Scope) normalize() {
	sort.Slice(s.Ports, func(i, j int) bool {
		if s.Ports[i].Proto != s.Ports[j].Proto {
			return s.Ports[i].Proto < s.Ports[j].Proto
		}
		return s.Ports[i].Port < s.Ports[j].Port
	})
}

// String renders the scope for logs: "all", "NONE", or "tcp/873,udp/51820".
func (s Scope) String() string {
	if s.All {
		return "all"
	}
	if len(s.Ports) == 0 {
		return "NONE"
	}
	parts := make([]string, len(s.Ports))
	for i, p := range s.Ports {
		parts[i] = fmt.Sprintf("%s/%d", p.Proto, p.Port)
	}
	return strings.Join(parts, ",")
}
