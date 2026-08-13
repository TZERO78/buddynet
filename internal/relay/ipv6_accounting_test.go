package relay

// Regression tests for H-01: the relay accounts abuse budgets per EXACT source
// address, while the QUIC control plane (tunnel.ipKey) accounts IPv6 per /64.
// A single routable /64 is the smallest block a site is normally handed, so one
// host can mint 2^64 "distinct sources" for free — each getting a fresh
// maxLegsPerIP budget and a fresh per-source token bucket.
//
// TEST SAFETY. Every source address below is from 2001:db8::/32 (RFC 3849
// documentation prefix, never routed) or fc00::/7 (ULA). The relay's socket in
// these tests is an IPv4 loopback socket, so the ack/challenge the relay writes
// back to such a source fails locally in the kernel with an address-family
// mismatch and NO packet ever leaves this host. The only test that puts real
// packets on a wire uses the IPv6 loopback ::1.
//
// Nothing here reaches a foreign or public system.

import (
	"encoding/base64"
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tzero78/buddynet/internal/ratelimit"
)

// --- harness ---------------------------------------------------------------

// v4LoopbackConn returns an IPv4-only loopback socket. Used as the relay's conn
// so that any reply addressed to a v6 test source fails in the kernel without
// emitting a packet (see TEST SAFETY above).
func v4LoopbackConn(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp4 loopback: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// udpAddr builds a source address from a textual IP and a port.
func udpAddr(t *testing.T, ip string, port int) *net.UDPAddr {
	t.Helper()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("bad test IP %q", ip)
	}
	return &net.UDPAddr{IP: parsed, Port: port}
}

// token returns a session token of the real production shape: 22 characters,
// which is what role.sessionToken emits and what MinSessionTokenLen demands.
func token(n int) string {
	s := fmt.Sprintf("tok%019d", n)
	if len(s) != 22 {
		panic("test token must be 22 chars like the real one, got " + s)
	}
	return s
}

// doBind drives the REAL bind path: it marshals a genuine bind datagram, parses
// it with the production ParseBind, and calls Server.bind with the true wire
// length (so the anti-amplification gate sees what it would see in production).
// cookie is attached verbatim; pass validCookieFor(s, src) for a good one.
func doBind(t *testing.T, s *Server, conn *net.UDPConn, tok string, src *net.UDPAddr, cookie string) {
	t.Helper()
	pkt := MarshalBind(Bind{SessionToken: tok, Cookie: cookie})
	b, ok := ParseBind(pkt)
	if !ok {
		t.Fatalf("test harness built a bind the production parser rejects (token %q)", tok)
	}
	s.bind(conn, b, src, len(pkt))
}

// validCookieFor mints a cookie that is genuinely valid for src — the same
// value the relay would have handed out in a challenge, so the bind proves
// return-routability exactly as a real buddy's second bind does.
func validCookieFor(s *Server, src *net.UDPAddr) string {
	return base64.RawURLEncoding.EncodeToString(s.freshCookie(src.IP))
}

// legBound reports whether src holds a leg of tok's session — i.e. whether the
// bind was ACCEPTED and created state.
func legBound(s *Server, tok string, src *net.UDPAddr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ses := s.sessions[tok]
	if ses == nil {
		return false
	}
	for _, l := range ses.legs {
		if l.addr.String() == src.String() {
			return true
		}
	}
	return false
}

// accounting renders the live legsPerIP map, sorted, for failure diagnostics.
func accounting(s *Server) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.legsPerIP))
	for k := range s.legsPerIP {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, s.legsPerIP[k]))
	}
	return "{" + strings.Join(parts, " ") + "}"
}

func sessionCount(s *Server) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// --- positive control: the harness really binds ----------------------------

// TestHarnessBindsAndCookieIsEnforced proves the test harness exercises the
// real thing before any of the security assertions below rely on it:
//   - a bind WITHOUT a cookie creates no state and is counted as challenged,
//   - a bind WITH a valid cookie creates a leg,
//   - a bind with a GARBAGE cookie still creates no state.
//
// Without this control, "leg not bound" in a later test could mean a broken
// harness rather than an enforced limit.
func TestHarnessBindsAndCookieIsEnforced(t *testing.T) {
	conn := v4LoopbackConn(t)
	s := New(Config{TTL: time.Minute, MaxSessions: 128, MaxLegsPerIP: 4})
	src := udpAddr(t, "2001:db8:1234:5678::1", 41000)

	doBind(t, s, conn, token(1), src, "")
	if legBound(s, token(1), src) {
		t.Fatalf("cookie-less bind created state: the relay's return-routability check is not running")
	}
	if got := s.statChallenged.Load(); got != 1 {
		t.Fatalf("cookie-less bind: statChallenged = %d, want 1", got)
	}

	doBind(t, s, conn, token(2), src, "AAAAAAAAAAAAAAAAAAAAAA")
	if legBound(s, token(2), src) {
		t.Fatalf("bind with a forged cookie created state")
	}

	doBind(t, s, conn, token(3), src, validCookieFor(s, src))
	if !legBound(s, token(3), src) {
		t.Fatalf("bind with a VALID cookie did not create a leg — the harness is broken, not the relay; accounting=%s", accounting(s))
	}
}

// TestRelayIPv6BindRoundTripOverLoopback is the positive control that the IPv6
// bind path works end to end against a really running relay: challenge out,
// cookie echoed back, leg acked. It uses the IPv6 LOOPBACK only.
func TestRelayIPv6BindRoundTripOverLoopback(t *testing.T) {
	srv, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("BLOCKER: no IPv6 loopback socket available here: %v", err)
	}
	defer srv.Close()
	s := New(Config{TTL: time.Minute, MaxSessions: 128, MaxLegsPerIP: 4})
	go s.Run(srv)

	cli, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("BLOCKER: no IPv6 loopback client socket: %v", err)
	}
	defer cli.Close()

	if err := BindLeg(cli, srv.LocalAddr().(*net.UDPAddr), token(1), 5*time.Second, nil); err != nil {
		t.Fatalf("IPv6 bind round-trip failed: %v", err)
	}
	if n := sessionCount(s); n != 1 {
		t.Fatalf("after a successful IPv6 bind: sessions = %d, want 1", n)
	}
	if s.statChallenged.Load() == 0 {
		t.Fatalf("expected the relay to have issued an address-validation challenge")
	}
}

// TestLegCapEnforcedForOneExactIPv6Address is the positive control for the
// hoarding cap itself: from ONE exact IPv6 address, the 5th leg is refused at
// maxLegsPerIP=4. It proves the cap mechanism works and that the failure in
// TestLegCapSharedAcrossIPv6Slash64 is about the KEY, not about a broken cap.
func TestLegCapEnforcedForOneExactIPv6Address(t *testing.T) {
	conn := v4LoopbackConn(t)
	s := New(Config{TTL: time.Minute, MaxSessions: 128, MaxLegsPerIP: 4})
	src := "2001:db8:1234:5678::1"

	for i := 1; i <= 4; i++ {
		a := udpAddr(t, src, 41000+i)
		doBind(t, s, conn, token(i), a, validCookieFor(s, a))
		if !legBound(s, token(i), a) {
			t.Fatalf("leg %d from the same address was refused below the cap; accounting=%s", i, accounting(s))
		}
	}
	fifth := udpAddr(t, src, 41005)
	doBind(t, s, conn, token(5), fifth, validCookieFor(s, fifth))
	if legBound(s, token(5), fifth) {
		t.Fatalf("leg 5 from one exact address was accepted at maxLegsPerIP=4; accounting=%s", accounting(s))
	}
	if got := s.statHoard.Load(); got != 1 {
		t.Fatalf("statHoard = %d, want 1 (the cap should have been recorded)", got)
	}
}

// --- H-01.2: the leg cap must be shared across one /64 ---------------------

// TestLegCapSharedAcrossIPv6Slash64 states the security invariant:
//
//	"All IPv6 addresses of the same /64 share ONE hoarding budget at the relay."
//
// Legs 1..4 of 2001:db8:1234:5678::/64 must be accepted, leg 5 must be refused,
// and a leg from the neighbouring 2001:db8:1234:5679::/64 must still be
// accepted (so the limit is per /64, not a global stall).
func TestLegCapSharedAcrossIPv6Slash64(t *testing.T) {
	conn := v4LoopbackConn(t)
	const maxLegs = 4
	s := New(Config{TTL: time.Minute, MaxSessions: 128, MaxLegsPerIP: maxLegs})

	addrs := []string{
		"2001:db8:1234:5678::1",
		"2001:db8:1234:5678::2",
		"2001:db8:1234:5678::3",
		"2001:db8:1234:5678::4",
		"2001:db8:1234:5678::5",
	}

	var accepted, refused []string
	for i, ip := range addrs {
		a := udpAddr(t, ip, 42000+i) // own UDP port per address
		tok := token(100 + i)        // own, full-length session token per address
		doBind(t, s, conn, tok, a, validCookieFor(s, a))
		if legBound(s, tok, a) {
			accepted = append(accepted, ip)
		} else {
			refused = append(refused, ip)
		}
	}

	// Not the global cap: maxSessions is 128 and at most 5 sessions exist.
	if n := sessionCount(s); n >= 128 {
		t.Fatalf("test setup wrong: hit the global session cap (%d sessions)", n)
	}

	// A different /64 must remain free — proves the expected refusal is a per-/64
	// budget and not the relay refusing everything.
	other := udpAddr(t, "2001:db8:1234:5679::1", 42099)
	doBind(t, s, conn, token(200), other, validCookieFor(s, other))
	if !legBound(s, token(200), other) {
		t.Fatalf("a leg from a DIFFERENT /64 was refused — the budget is not per-/64 but global; accounting=%s", accounting(s))
	}

	if len(accepted) != maxLegs || len(refused) != 1 {
		t.Fatalf(`H-01: the relay's leg cap is keyed by the exact IPv6 address, not by /64.

  accepted legs : %d %v
  refused legs  : %d %v
  want          : %d accepted, 1 refused (all from 2001:db8:1234:5678::/64)
  sessions      : %d (global cap 128 — not the cause)
  legsPerIP     : %s

Each address of one /64 gets its own maxLegsPerIP budget, so a single /64 —
which a site gets for free — can hold the whole relay's session table.`,
			len(accepted), accepted, len(refused), refused, maxLegs, sessionCount(s), accounting(s))
	}
}

// TestLegCapUnmapsIPv4MappedIPv6 checks whether an IPv4-mapped IPv6 source is
// accounted on the same key as the plain IPv4 address — i.e. whether a peer can
// double its allowance by reaching the relay over ::ffff:a.b.c.d.
func TestLegCapUnmapsIPv4MappedIPv6(t *testing.T) {
	conn := v4LoopbackConn(t)
	s := New(Config{TTL: time.Minute, MaxSessions: 128, MaxLegsPerIP: 2})

	plain := udpAddr(t, "192.0.2.7", 43001)
	doBind(t, s, conn, token(300), plain, validCookieFor(s, plain))
	doBind(t, s, conn, token(301), udpAddr(t, "192.0.2.7", 43002), validCookieFor(s, udpAddr(t, "192.0.2.7", 43002)))
	if !legBound(s, token(301), udpAddr(t, "192.0.2.7", 43002)) {
		t.Fatalf("setup: second leg from the plain IPv4 address should fit under maxLegsPerIP=2; accounting=%s", accounting(s))
	}

	mapped := udpAddr(t, "::ffff:192.0.2.7", 43003)
	doBind(t, s, conn, token(302), mapped, validCookieFor(s, mapped))
	if legBound(s, token(302), mapped) {
		t.Fatalf(`the IPv4-mapped form ::ffff:192.0.2.7 got its OWN budget on top of 192.0.2.7.
  legsPerIP: %s`, accounting(s))
	}
}

// --- a refused bind must not keep a global session slot --------------------

// TestRefusedBindLeavesNoEmptySession covers the second half of the H-01 denial
// of service, found by the netns lab rather than by the unit tests: bind()
// inserts the session into the global map BEFORE it checks the per-source leg
// cap. If a refused leg leaves that empty session behind, the leg cap stops
// being the binding constraint — a source may hold only N legs, but it can still
// fill the entire maxSessions table with LEGLESS sessions, one per token, and
// lock out everyone else.
func TestRefusedBindLeavesNoEmptySession(t *testing.T) {
	conn := v4LoopbackConn(t)
	const maxLegs = 2
	s := New(Config{TTL: time.Minute, MaxSessions: 128, MaxLegsPerIP: maxLegs})
	ip := "2001:db8:dddd:1::1"

	// Spend the per-source budget with real legs.
	for i := 0; i < maxLegs; i++ {
		a := udpAddr(t, ip, 46000+i)
		doBind(t, s, conn, token(600+i), a, validCookieFor(s, a))
		if !legBound(s, token(600+i), a) {
			t.Fatalf("setup: leg %d below the cap was refused; accounting=%s", i, accounting(s))
		}
	}
	if got := sessionCount(s); got != maxLegs {
		t.Fatalf("setup: want %d sessions after %d legs, got %d", maxLegs, maxLegs, got)
	}

	// Now 20 refused binds, each with a FRESH token — every one of them would
	// create a session before the leg cap refuses the leg.
	for i := 0; i < 20; i++ {
		a := udpAddr(t, ip, 46100+i)
		doBind(t, s, conn, token(700+i), a, validCookieFor(s, a))
		if legBound(s, token(700+i), a) {
			t.Fatalf("leg %d was accepted past the cap of %d", i, maxLegs)
		}
	}

	if got := sessionCount(s); got != maxLegs {
		t.Fatalf(`a refused bind left an empty session behind: %d sessions, want %d.

20 binds were refused by the per-source leg cap, yet each one still consumed a
slot in the global session table. The per-source cap then bounds only LEGS, not
table occupancy: one throttled source can still fill maxSessions with legless
sessions and lock out unrelated users. accounting=%s`, got, maxLegs, accounting(s))
	}
}

// TestThirdLegRefusalLeavesTheSessionIntact is the counterpart guard: cleaning up
// after a refused bind must NEVER delete a session that already belongs to
// someone else. A third party hitting an established pair must be refused
// without disturbing the two legs already spliced together.
func TestThirdLegRefusalLeavesTheSessionIntact(t *testing.T) {
	conn := v4LoopbackConn(t)
	s := New(Config{TTL: time.Minute, MaxSessions: 128, MaxLegsPerIP: 64})
	tok := token(800)

	a := udpAddr(t, "2001:db8:eeee:1::1", 47001)
	b := udpAddr(t, "2001:db8:eeee:2::1", 47002)
	doBind(t, s, conn, tok, a, validCookieFor(s, a))
	doBind(t, s, conn, tok, b, validCookieFor(s, b))
	if !legBound(s, tok, a) || !legBound(s, tok, b) {
		t.Fatalf("setup: the pair did not bind; accounting=%s", accounting(s))
	}

	third := udpAddr(t, "2001:db8:ffff:1::1", 47003)
	doBind(t, s, conn, tok, third, validCookieFor(s, third))
	if legBound(s, tok, third) {
		t.Fatalf("a third leg joined an established session")
	}
	// The pair must survive untouched.
	if !legBound(s, tok, a) || !legBound(s, tok, b) {
		t.Fatalf("refusing a third leg destroyed the established pair; accounting=%s", accounting(s))
	}
	if got := sessionCount(s); got != 1 {
		t.Fatalf("want 1 session after a refused third leg, got %d", got)
	}
}

// --- H-01.3: the per-source token bucket must be shared across one /64 -----

// TestBindRateLimitSharedAcrossIPv6Slash64 exercises Server.bind itself (not a
// helper) to prove which key actually reaches bindRL.Allow.
//
// The limiter is replaced with a deliberately tiny per-source bucket (rate 1/s,
// burst 2) and a huge global bucket, so the global ceiling can neither turn the
// test green nor red by accident.
func TestBindRateLimitSharedAcrossIPv6Slash64(t *testing.T) {
	conn := v4LoopbackConn(t)
	// maxLegsPerIP high so the hoarding cap cannot be what refuses a bind here.
	s := New(Config{TTL: time.Minute, MaxSessions: 128, MaxLegsPerIP: 64})
	s.bindRL = ratelimit.New(100000, 1, 8192) // global 100k/s, per-source 1/s (burst 2)

	first := udpAddr(t, "2001:db8:aaaa:1::1", 44001)
	second := udpAddr(t, "2001:db8:aaaa:1::1", 44002)
	third := udpAddr(t, "2001:db8:aaaa:1::1", 44003)

	// Spend the per-source budget from ONE address: burst = 2 accepted binds.
	doBind(t, s, conn, token(400), first, validCookieFor(s, first))
	doBind(t, s, conn, token(401), second, validCookieFor(s, second))
	if !legBound(s, token(400), first) || !legBound(s, token(401), second) {
		t.Fatalf("setup: the first two binds should fit in the burst; accounting=%s", accounting(s))
	}
	// Positive control: the bucket is real and Server.bind consults it.
	doBind(t, s, conn, token(402), third, validCookieFor(s, third))
	if legBound(s, token(402), third) {
		t.Fatalf("the per-source bucket did not throttle a third bind from the same exact address — Server.bind is not consulting bindRL as assumed")
	}

	// Positive control: a genuinely different /64 must still be admitted, so a
	// refusal below cannot be the global bucket.
	otherPrefix := udpAddr(t, "2001:db8:bbbb:1::1", 44010)
	doBind(t, s, conn, token(410), otherPrefix, validCookieFor(s, otherPrefix))
	if !legBound(s, token(410), otherPrefix) {
		t.Fatalf("a bind from a different /64 was throttled — the global bucket is interfering; accounting=%s", accounting(s))
	}

	// The invariant: a sibling address inside the SAME /64 must draw on the same
	// exhausted bucket.
	sibling := udpAddr(t, "2001:db8:aaaa:1::2", 44020)
	doBind(t, s, conn, token(420), sibling, validCookieFor(s, sibling))
	if legBound(s, token(420), sibling) {
		t.Fatalf(`H-01.3: the per-source bind rate limiter is keyed by the exact IPv6
address, so 2001:db8:aaaa:1::2 got a FRESH token bucket after
2001:db8:aaaa:1::1 had exhausted its own.

  key passed to bindRL.Allow : src.IP.String()  (internal/relay/server.go:312)
  key used by the control
  plane for the same purpose : tunnel.ipKey() -> /64  (internal/tunnel/control.go:289)
  legsPerIP                  : %s

Rotating through a single /64 therefore resets the per-source throttle at will.`, accounting(s))
	}
}

// --- H-01.4: reaping must release exactly the key that was charged ---------

// TestReapReleasesTheAccountingKeyItCharged is the guard that a future fix keeps
// bind and reap on the SAME key. It must hold before and after any change to the
// accounting key: after a leg expires, the budget is free again, and no stale or
// negative counter is left behind.
func TestReapReleasesTheAccountingKeyItCharged(t *testing.T) {
	conn := v4LoopbackConn(t)
	s := New(Config{TTL: 20 * time.Millisecond, MaxSessions: 128, MaxLegsPerIP: 1}) // maxLegsPerIP=1: the budget is visible
	defer s.stop()

	a := udpAddr(t, "2001:db8:cccc:1::1", 45001)
	doBind(t, s, conn, token(500), a, validCookieFor(s, a))
	if !legBound(s, token(500), a) {
		t.Fatalf("setup: first leg was not bound; accounting=%s", accounting(s))
	}
	// Budget is spent: a second leg from the same address is refused.
	b := udpAddr(t, "2001:db8:cccc:1::1", 45002)
	doBind(t, s, conn, token(501), b, validCookieFor(s, b))
	if legBound(s, token(501), b) {
		t.Fatalf("setup: maxLegsPerIP=1 did not refuse the second leg; accounting=%s", accounting(s))
	}

	// Make the leg expire deterministically (no sleep-as-synchronisation: the
	// last-seen stamp is set to the epoch, so the very first reap tick collects it).
	s.mu.Lock()
	for _, ses := range s.sessions {
		for _, l := range ses.legs {
			l.fwd.seen.Store(0)
		}
	}
	s.mu.Unlock()
	go s.reap()

	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		empty := len(s.legsPerIP) == 0 && len(s.sessions) == 0
		s.mu.Unlock()
		if empty {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("reaping did not release the accounting key within 5s; accounting=%s", accounting(s))
		}
		time.Sleep(2 * time.Millisecond) // poll for a ticker-driven state change
	}

	// No negative or orphaned counters.
	s.mu.Lock()
	for k, v := range s.legsPerIP {
		if v <= 0 {
			t.Fatalf("legsPerIP kept a non-positive counter %s=%d", k, v)
		}
	}
	s.mu.Unlock()

	// And the budget is genuinely usable again.
	c := udpAddr(t, "2001:db8:cccc:1::1", 45003)
	doBind(t, s, conn, token(502), c, validCookieFor(s, c))
	if !legBound(s, token(502), c) {
		t.Fatalf("after reaping, the freed budget was not reusable; accounting=%s", accounting(s))
	}
}
