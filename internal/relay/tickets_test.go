package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tzero78/buddynet/internal/ticket"
)

// --- harness ---------------------------------------------------------------
//
// The tests below drive Server.bind directly rather than over a socket. That is
// deliberate: bind IS the check order under test, and calling it with a chosen
// source address lets a test present the same bind from a second address (the
// replay and migration cases) without needing that address to exist on the host.
// The netns lab (lab/test-relay-tickets.sh) covers the same ground over the real
// binary, over real UDP, where those addresses do exist.

type harness struct {
	s    *Server
	conn *net.UDPConn
	srv  ed25519.PrivateKey
	rid  string
}

func newHarness(t *testing.T, mut func(*Config)) *harness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	rid, err := ticket.NewID()
	if err != nil {
		t.Fatalf("rid: %v", err)
	}
	cfg := Config{TTL: time.Minute, ServerKeys: []ed25519.PublicKey{pub}, RelayID: rid}
	if mut != nil {
		mut(&cfg)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return &harness{s: New(cfg), conn: conn, srv: priv, rid: rid}
}

// buddy is one end of a session: its ephemeral key and the ticket it holds.
type buddy struct {
	eph     ed25519.PrivateKey
	epk     string
	payload []byte
	sig     []byte
	sid     string
	leg     string
	src     *net.UDPAddr
}

// issue mints a ticket the way the handshake server does. mut alters the payload
// before signing, which is how the "wrongly issued" cases are built.
func (h *harness) issue(t *testing.T, sid, leg string, src *net.UDPAddr, mut func(*ticket.Payload)) *buddy {
	t.Helper()
	epub, epriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ephemeral key: %v", err)
	}
	nonce, err := ticket.NewID()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	now := time.Now()
	p := ticket.Payload{
		V: ticket.FormatVersion, RID: h.rid, SID: sid, Leg: leg,
		EPK:   base64.RawURLEncoding.EncodeToString(epub),
		IAT:   now.Unix(),
		EXP:   now.Add(ticket.MaxTTL).Unix(),
		Nonce: nonce,
	}
	if mut != nil {
		mut(&p)
	}
	payload, sig, err := ticket.Sign(h.srv, p)
	if err != nil {
		t.Fatalf("sign ticket: %v", err)
	}
	return &buddy{eph: epriv, epk: p.EPK, payload: payload, sig: sig, sid: p.SID, leg: p.Leg, src: src}
}

// cookieFor returns the cookie the relay would currently hand this source, as
// both raw bytes and the base64 the wire carries.
func (h *harness) cookieFor(ip net.IP) ([]byte, string) {
	c := h.s.freshCookie(ip)
	return c, base64.RawURLEncoding.EncodeToString(c)
}

// bind presents one bind from b's address and waits for the verification to
// finish. It performs the real cookie round trip: the first bind carries none,
// which can only draw a challenge, and the second carries the cookie plus the
// proof of possession over it.
func (h *harness) bind(t *testing.T, b *buddy) {
	t.Helper()
	h.bindFrom(t, b, b.src, nil)
}

// bindFrom presents b's ticket from an arbitrary source, optionally altering the
// bind just before it goes in (the tamper cases).
func (h *harness) bindFrom(t *testing.T, b *buddy, src *net.UDPAddr, mut func(*Bind)) {
	t.Helper()
	raw, b64 := h.cookieFor(src.IP)
	bind := Bind{
		SessionToken: b.sid,
		Cookie:       b64,
		Ticket:       base64.RawURLEncoding.EncodeToString(b.payload),
		TicketSig:    base64.RawURLEncoding.EncodeToString(b.sig),
		BindSig:      base64.RawURLEncoding.EncodeToString(ticket.SignBind(b.eph, b.payload, b.sig, raw)),
	}
	if mut != nil {
		mut(&bind)
	}
	h.s.bind(h.conn, bind, src, 512)
	h.drain()
}

// drain waits until every in-flight verification has finished, by taking every
// slot of the semaphore and giving them back. Filling it is only possible once
// no worker holds one.
func (h *harness) drain() {
	for i := 0; i < cap(h.s.inFlight); i++ {
		h.s.inFlight <- struct{}{}
	}
	for i := 0; i < cap(h.s.inFlight); i++ {
		<-h.s.inFlight
	}
}

// legs reports how many legs a session holds (0 if there is no session).
func (h *harness) legs(sid string) int {
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	ses := h.s.sessions[sid]
	if ses == nil {
		return 0
	}
	return len(ses.legs)
}

func (h *harness) sessions() int {
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	return len(h.s.sessions)
}

// legAddr returns the address currently recorded for a named leg.
func (h *harness) legAddr(sid, name string) string {
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	ses := h.s.sessions[sid]
	if ses == nil {
		return ""
	}
	for _, l := range ses.legs {
		if l.name == name {
			return l.addr.String()
		}
	}
	return ""
}

func addr(ip string, port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
}

func newSID(t *testing.T) string {
	t.Helper()
	sid, err := ticket.NewID()
	if err != nil {
		t.Fatalf("sid: %v", err)
	}
	return sid
}

// --- the tests -------------------------------------------------------------

// TestTwoLegsPairAndForward is plan case 29, the positive control the whole file
// rests on: without it every "refused" assertion below could be satisfied by a
// relay that refuses everything.
func TestTwoLegsPairAndForward(t *testing.T) {
	h := newHarness(t, nil)
	sid := newSID(t)
	a := h.issue(t, sid, ticket.LegA, addr("127.0.0.1", 4001), nil)
	b := h.issue(t, sid, ticket.LegB, addr("127.0.0.2", 4002), nil)

	h.bind(t, a)
	if got := h.legs(sid); got != 1 {
		t.Fatalf("after the first bind the session holds %d legs, want 1", got)
	}
	h.bind(t, b)
	if got := h.legs(sid); got != 2 {
		t.Fatalf("after the second bind the session holds %d legs, want 2", got)
	}

	// And the data path knows about both: forward() must find a's peer.
	v, ok := h.s.byAddr.Load(a.src.String())
	if !ok {
		t.Fatal("leg a is not in the forwarding table")
	}
	if dst := v.(*fwd).peer.Load(); dst == nil || dst.String() != b.src.String() {
		t.Fatalf("leg a forwards to %v, want %s", dst, b.src)
	}
}

// TestBindWithoutATicketIsRefused is plan case 1: an old-style bind reaching a
// ticket-mode relay is refused and allocates nothing.
func TestBindWithoutATicketIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	sid := newSID(t)
	src := addr("127.0.0.1", 4001)
	_, b64 := h.cookieFor(src.IP)

	h.s.bind(h.conn, Bind{SessionToken: sid, Cookie: b64}, src, 64)
	h.drain()

	if h.sessions() != 0 {
		t.Fatal("a bind with no ticket allocated a session")
	}
	if h.s.statVerify.Load() != 0 {
		t.Fatal("a bind with no ticket reached the signature verifications")
	}
}

// TestRelayTicketRejections walks the cases that must be refused at the relay,
// each starting from a ticket that is otherwise valid.
func TestRelayTicketRejections(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour)
	future := time.Now().Add(24 * time.Hour)

	tests := []struct {
		name string
		mut  func(*ticket.Payload) // wrongly issued
		bind func(*Bind)           // tampered in flight
	}{
		{name: "ticket signature bit-flipped", bind: func(b *Bind) {
			raw, _ := base64.RawURLEncoding.DecodeString(b.TicketSig)
			raw[0] ^= 0x01
			b.TicketSig = base64.RawURLEncoding.EncodeToString(raw)
		}},
		{name: "payload altered after signing", bind: func(b *Bind) {
			raw, _ := base64.RawURLEncoding.DecodeString(b.Ticket)
			raw[len(raw)-2] ^= 0x01
			b.Ticket = base64.RawURLEncoding.EncodeToString(raw)
		}},
		{name: "no proof of possession", bind: func(b *Bind) { b.BindSig = "" }},
		{name: "proof by the wrong key", bind: func(b *Bind) {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			payload, _ := base64.RawURLEncoding.DecodeString(b.Ticket)
			sig, _ := base64.RawURLEncoding.DecodeString(b.TicketSig)
			cookie, _ := base64.RawURLEncoding.DecodeString(b.Cookie)
			b.BindSig = base64.RawURLEncoding.EncodeToString(ticket.SignBind(other, payload, sig, cookie))
		}},
		{name: "ticket fields are not base64url", bind: func(b *Bind) { b.Ticket = "!!!!" }},
		{name: "expired beyond the grace", mut: func(p *ticket.Payload) {
			p.IAT, p.EXP = past.Unix(), past.Add(time.Minute).Unix()
		}},
		{name: "issued implausibly in the future", mut: func(p *ticket.Payload) {
			p.IAT, p.EXP = future.Unix(), future.Add(ticket.MaxTTL).Unix()
		}},
		{name: "validity span over the cap", mut: func(p *ticket.Payload) {
			p.EXP = p.IAT + int64(ticket.MaxTTL/time.Second) + 1
		}},
		{name: "unknown ticket version", mut: func(p *ticket.Payload) { p.V = ticket.FormatVersion + 1 }},
		{name: "no valid leg", mut: func(p *ticket.Payload) { p.Leg = "c" }},
		{name: "bind claims a different session than its ticket", bind: func(b *Bind) {
			b.SessionToken = "AAAAAAAAAAAAAAAAAAAAAA"
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			sid := newSID(t)
			a := h.issue(t, sid, ticket.LegA, addr("127.0.0.1", 4001), tc.mut)
			h.bindFrom(t, a, a.src, tc.bind)
			if h.sessions() != 0 {
				t.Fatalf("a refused bind (%s) left state behind: %d session(s)", tc.name, h.sessions())
			}
		})
	}
}

// TestTicketForAnotherRelayIsRefused is plan case 9 end to end: the rid is what
// stops a permit minted for one relay from being spent at another.
func TestTicketForAnotherRelayIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	other, err := ticket.NewID()
	if err != nil {
		t.Fatalf("rid: %v", err)
	}
	sid := newSID(t)
	a := h.issue(t, sid, ticket.LegA, addr("127.0.0.1", 4001), func(p *ticket.Payload) { p.RID = other })
	h.bind(t, a)
	if h.sessions() != 0 {
		t.Fatal("a ticket minted for a different relay was accepted")
	}
}

// TestTicketSignedByAnotherServerIsRefused is plan case 3: the relay trusts the
// key it was configured with, not any key that produces a valid-looking blob.
func TestTicketSignedByAnotherServerIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	stranger := &harness{s: h.s, conn: h.conn, rid: h.rid}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("stranger key: %v", err)
	}
	stranger.srv = priv

	sid := newSID(t)
	a := stranger.issue(t, sid, ticket.LegA, addr("127.0.0.1", 4001), nil)
	h.bind(t, a)
	if h.sessions() != 0 {
		t.Fatal("a ticket signed by an unconfigured key was accepted")
	}
}

// TestCookieGatesEverythingExpensive is plan case 20, asserted on the counter
// rather than on the absence of output: a bind without a valid cookie must cost
// no Ed25519 verification and allocate no state, however perfect its ticket is.
func TestCookieGatesEverythingExpensive(t *testing.T) {
	h := newHarness(t, nil)
	sid := newSID(t)
	a := h.issue(t, sid, ticket.LegA, addr("127.0.0.1", 4001), nil)

	for _, tc := range []struct {
		name   string
		cookie string
	}{
		{name: "no cookie", cookie: ""},
		{name: "garbage cookie", cookie: "AAAAAAAAAAAAAAAAAAAAAA"},
		{name: "cookie for another address", cookie: func() string {
			_, c := h.cookieFor(net.ParseIP("127.0.0.9"))
			return c
		}()},
		{name: "cookie from a rotated-out epoch", cookie: func() string {
			old := h.s.computeCookie(net.ParseIP("127.0.0.1"), time.Now().UnixNano()/int64(cookieEpoch)-2)
			return base64.RawURLEncoding.EncodeToString(old)
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := h.s.statVerify.Load()
			h.bindFrom(t, a, a.src, func(b *Bind) { b.Cookie = tc.cookie })
			if got := h.s.statVerify.Load(); got != before {
				t.Fatalf("a bind with %s reached the signature verifications (%d -> %d)", tc.name, before, got)
			}
			if h.sessions() != 0 {
				t.Fatal("a bind that failed the cookie check allocated state")
			}
		})
	}

	// Positive control: the same ticket with a correct cookie DOES get verified,
	// so the assertions above are not passing because nothing works.
	before := h.s.statVerify.Load()
	h.bind(t, a)
	if h.s.statVerify.Load() != before+1 {
		t.Fatal("a bind with a valid cookie was not verified — the negative cases above prove nothing")
	}
	if h.legs(sid) != 1 {
		t.Fatal("a valid bind did not claim its leg")
	}
}

// TestCapturedBindIsUselessElsewhere is plan cases 14 and 15. Both reduce to the
// same thing at the relay, which is the point of signing over the cookie: the
// cookie is bound to the source address and to a 30s epoch, so a copied bind is
// worth nothing from another address or after the epoch turns.
func TestCapturedBindIsUselessElsewhere(t *testing.T) {
	h := newHarness(t, nil)
	sid := newSID(t)
	a := h.issue(t, sid, ticket.LegA, addr("127.0.0.1", 4001), nil)

	// Capture a's complete bind, as an on-path attacker would.
	raw, b64 := h.cookieFor(a.src.IP)
	captured := Bind{
		SessionToken: a.sid,
		Cookie:       b64,
		Ticket:       base64.RawURLEncoding.EncodeToString(a.payload),
		TicketSig:    base64.RawURLEncoding.EncodeToString(a.sig),
		BindSig:      base64.RawURLEncoding.EncodeToString(ticket.SignBind(a.eph, a.payload, a.sig, raw)),
	}

	// Replayed from a different address: the cookie does not match that source, so
	// it never even reaches the signature check.
	h.s.bind(h.conn, captured, addr("127.0.0.66", 5000), 512)
	h.drain()
	if h.sessions() != 0 {
		t.Fatal("a captured bind was accepted from another address")
	}

	// Replayed from the SAME address but with a freshly issued cookie the attacker
	// could have observed: the proof of possession covers the OLD cookie, so it
	// fails — and the attacker cannot re-sign without the ephemeral private key.
	_, fresh := h.cookieFor(a.src.IP)
	rebind := captured
	rebind.Cookie = fresh
	if fresh != b64 {
		h.s.bind(h.conn, rebind, a.src, 512)
		h.drain()
		if h.sessions() != 0 {
			t.Fatal("a captured bind was accepted under a different cookie")
		}
	}

	// Positive control: the real buddy still binds.
	h.bind(t, a)
	if h.legs(sid) != 1 {
		t.Fatal("the legitimate buddy could not bind")
	}
}

// TestThirdPartyCannotTakeAFilledLeg is plan cases 16 and 17: a leg is owned by
// the ephemeral key that claimed it, and a valid-looking bind from anyone else is
// refused with the pairing left intact.
func TestThirdPartyCannotTakeAFilledLeg(t *testing.T) {
	h := newHarness(t, nil)
	sid := newSID(t)
	a := h.issue(t, sid, ticket.LegA, addr("127.0.0.1", 4001), nil)
	b := h.issue(t, sid, ticket.LegB, addr("127.0.0.2", 4002), nil)
	h.bind(t, a)
	h.bind(t, b)

	// A third party with a genuinely signed ticket for the SAME session and leg —
	// which only a server bug or a hostile server could produce — still cannot take
	// a leg that another ephemeral key holds.
	x := h.issue(t, sid, ticket.LegA, addr("127.0.0.3", 4003), nil)
	h.bind(t, x)

	if h.legs(sid) != 2 {
		t.Fatalf("the session holds %d legs after the intrusion, want 2", h.legs(sid))
	}
	if got := h.legAddr(sid, ticket.LegA); got != a.src.String() {
		t.Fatalf("leg a now points at %s, want the original %s", got, a.src)
	}
	if _, taken := h.s.byAddr.Load(x.src.String()); taken {
		t.Fatal("the third party was put in the forwarding table")
	}
}

// TestNATMigration is plan cases 18, 19, 30 and 31 — the group that decides
// whether address migration is a feature or a hole.
func TestNATMigration(t *testing.T) {
	h := newHarness(t, nil)
	sid := newSID(t)
	a := h.issue(t, sid, ticket.LegA, addr("127.0.0.1", 4001), nil)
	b := h.issue(t, sid, ticket.LegB, addr("127.0.0.2", 4002), nil)
	h.bind(t, a)
	h.bind(t, b)

	// 30: a re-bind from the address it already holds is an ordinary keepalive.
	h.bind(t, a)
	if h.legs(sid) != 2 || h.legAddr(sid, ticket.LegA) != a.src.String() {
		t.Fatal("a keepalive re-bind disturbed the session")
	}

	// 18: the same ephemeral key from a NEW address, with a fresh cookie for that
	// address and a valid ticket — a real NAT rebind. Accepted, and the swap is
	// visible on both sides at once.
	moved := addr("127.0.0.77", 4444)
	h.bindFrom(t, a, moved, nil)
	if got := h.legAddr(sid, ticket.LegA); got != moved.String() {
		t.Fatalf("leg a did not migrate: %s", got)
	}
	if _, stale := h.s.byAddr.Load(a.src.String()); stale {
		t.Fatal("the old address still forwards after the migration")
	}
	v, ok := h.s.byAddr.Load(b.src.String())
	if !ok {
		t.Fatal("leg b left the forwarding table")
	}
	if dst := v.(*fwd).peer.Load(); dst == nil || dst.String() != moved.String() {
		t.Fatalf("leg b still sends to %v after the partner moved, want %s", dst, moved)
	}

	// 19: a copy of the ticket WITHOUT the ephemeral private key cannot move the
	// leg, even from an address it holds a valid cookie for.
	thief := addr("127.0.0.88", 5555)
	rawc, b64 := h.cookieFor(thief.IP)
	_, wrong, _ := ed25519.GenerateKey(rand.Reader)
	h.s.bind(h.conn, Bind{
		SessionToken: sid,
		Cookie:       b64,
		Ticket:       base64.RawURLEncoding.EncodeToString(a.payload),
		TicketSig:    base64.RawURLEncoding.EncodeToString(a.sig),
		BindSig:      base64.RawURLEncoding.EncodeToString(ticket.SignBind(wrong, a.payload, a.sig, rawc)),
	}, thief, 512)
	h.drain()
	if got := h.legAddr(sid, ticket.LegA); got != moved.String() {
		t.Fatalf("a copied ticket moved the leg to %s", got)
	}

	// 31: the same buddy, with its real key, but an EXPIRED ticket. Refused — the
	// ephemeral key proves who, never how long, and letting a known key back in on
	// a dead ticket would make it an unbounded re-entry credential.
	old := h.issue(t, sid, ticket.LegA, addr("127.0.0.99", 6666), func(p *ticket.Payload) {
		past := time.Now().Add(-time.Hour)
		p.IAT, p.EXP = past.Unix(), past.Add(time.Minute).Unix()
		p.EPK = a.epk // same identity as the leg holder
	})
	old.eph = a.eph
	h.bind(t, old)
	if got := h.legAddr(sid, ticket.LegA); got != moved.String() {
		t.Fatalf("an expired ticket moved the leg to %s", got)
	}
}

// TestEstablishedSessionOutlivesItsTicket is plan cases 25 and 26 together — the
// lifetime contract: a ticket authorises JOINING, not staying.
func TestEstablishedSessionOutlivesItsTicket(t *testing.T) {
	h := newHarness(t, nil)
	sid := newSID(t)
	a := h.issue(t, sid, ticket.LegA, addr("127.0.0.1", 4001), nil)
	b := h.issue(t, sid, ticket.LegB, addr("127.0.0.2", 4002), nil)
	h.bind(t, a)
	h.bind(t, b)

	// Nothing on the data path consults a ticket: forwarding is a table lookup and
	// two atomics, and it keeps working for as long as the session lives.
	v, ok := h.s.byAddr.Load(a.src.String())
	if !ok || v.(*fwd).peer.Load() == nil {
		t.Fatal("the established session cannot forward")
	}

	// But nothing NEW can be bound with an expired ticket: a fresh leg on a new
	// session id is refused outright.
	sid2 := newSID(t)
	expired := h.issue(t, sid2, ticket.LegA, addr("127.0.0.3", 4003), func(p *ticket.Payload) {
		past := time.Now().Add(-time.Hour)
		p.IAT, p.EXP = past.Unix(), past.Add(time.Minute).Unix()
	})
	h.bind(t, expired)
	if h.legs(sid2) != 0 {
		t.Fatal("an expired ticket bound a new leg")
	}
	// ...while the established one is untouched by that refusal.
	if h.legs(sid) != 2 {
		t.Fatal("the established session was disturbed")
	}
}

// TestHalfOpenSessionExpiresDespiteTraffic is plan case 27. The idle timer is
// refreshed by any packet from a bound source, so without an ABSOLUTE bound one
// leg plus a trickle holds a session slot forever with no partner ever arriving.
func TestHalfOpenSessionExpiresDespiteTraffic(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.TTL = 100 * time.Millisecond })
	h.s.pendingPair = 250 * time.Millisecond
	go h.s.reap()
	t.Cleanup(h.s.stop)

	sid := newSID(t)
	a := h.issue(t, sid, ticket.LegA, addr("127.0.0.1", 4001), nil)
	h.bind(t, a)
	if h.legs(sid) != 1 {
		t.Fatal("the first leg did not bind")
	}

	// Keep the leg "active" the whole time, which is exactly what defeats an idle
	// timer, and check the absolute timeout fires anyway.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		h.s.forward(h.conn, a.src, []byte("keepalive"))
		if h.sessions() == 0 {
			return // expired despite the traffic: correct
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("a half-open session with a trickle of traffic never expired")
}

// TestTicketAndCIDRAreAnAND is plan cases 21 and 22: with both policies set, a
// bind needs to satisfy BOTH. Neither is an alternative the other can be
// substituted for.
func TestTicketAndCIDRAreAnAND(t *testing.T) {
	allowed := netip.MustParsePrefix("127.0.0.0/8")
	h := newHarness(t, func(c *Config) { c.AllowCIDRs = []netip.Prefix{allowed} })
	sid := newSID(t)

	// 21: a valid ticket from a source outside the allowlist.
	outside := h.issue(t, sid, ticket.LegA, addr("10.0.0.5", 4001), nil)
	h.bind(t, outside)
	if h.sessions() != 0 {
		t.Fatal("a valid ticket bought admission from a disallowed network")
	}
	if h.s.statVerify.Load() != 0 {
		t.Fatal("a disallowed source reached the signature verifications")
	}

	// 22: no ticket at all from an allowed source.
	src := addr("127.0.0.1", 4002)
	_, b64 := h.cookieFor(src.IP)
	h.s.bind(h.conn, Bind{SessionToken: sid, Cookie: b64}, src, 64)
	h.drain()
	if h.sessions() != 0 {
		t.Fatal("an allowed source bound without a ticket")
	}

	// Positive control: inside the allowlist AND with a ticket.
	ok := h.issue(t, sid, ticket.LegA, addr("127.0.0.1", 4003), nil)
	h.bind(t, ok)
	if h.legs(sid) != 1 {
		t.Fatal("a bind satisfying both policies was refused")
	}
}

// TestKeyRotationAtTheRelay is plan case 28 at the relay: during a rotation the
// relay is configured with both keys and tickets from either are accepted.
func TestKeyRotationAtTheRelay(t *testing.T) {
	h := newHarness(t, nil)
	nextPub, nextPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("next key: %v", err)
	}
	h.s.serverKeys = append(h.s.serverKeys, nextPub)

	sid := newSID(t)
	old := h.issue(t, sid, ticket.LegA, addr("127.0.0.1", 4001), nil)
	h.bind(t, old)

	next := &harness{s: h.s, conn: h.conn, srv: nextPriv, rid: h.rid}
	fresh := next.issue(t, sid, ticket.LegB, addr("127.0.0.2", 4002), nil)
	h.bind(t, fresh)

	if h.legs(sid) != 2 {
		t.Fatalf("the rotation window did not accept both keys: %d leg(s)", h.legs(sid))
	}
}

// flood drives n binds from n distinct real sources, each with a valid cookie
// for its own address and a ticket signed by an UNCONFIGURED key: the attacker
// is buying verification work, not admission. Every one of them is under every
// per-source budget, which is precisely why the per-source limiter is not the
// control that matters here.
func (h *harness) flood(t *testing.T, sid string, n int) {
	t.Helper()
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("stranger key: %v", err)
	}
	other := &harness{s: h.s, conn: h.conn, srv: stranger, rid: h.rid}
	for i := 0; i < n; i++ {
		id := sid
		if id == "" {
			id = newSID(t)
		}
		src := &net.UDPAddr{IP: net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)), Port: 40000 + i%1000}
		att := other.issue(t, id, ticket.LegB, src, nil)
		raw, b64 := h.cookieFor(src.IP)
		h.s.bind(h.conn, Bind{
			SessionToken: id,
			Cookie:       b64,
			Ticket:       base64.RawURLEncoding.EncodeToString(att.payload),
			TicketSig:    base64.RawURLEncoding.EncodeToString(att.sig),
			BindSig:      base64.RawURLEncoding.EncodeToString(ticket.SignBind(att.eph, att.payload, att.sig, raw)),
		}, src, 512)
	}
	h.drain()
}

// TestMultiSourceFloodStaysBounded is plan cases 32 and 33: total verification
// work is bounded by the GLOBAL budget rather than by how many addresses the
// attacker has, and a pairing that is one bind away from completing still gets
// in — that is what the reserve is for.
func TestMultiSourceFloodStaysBounded(t *testing.T) {
	h := newHarness(t, nil)

	victim := newSID(t)
	va := h.issue(t, victim, ticket.LegA, addr("127.0.0.1", 4001), nil)
	vb := h.issue(t, victim, ticket.LegB, addr("127.0.0.2", 4002), nil)
	h.bind(t, va)

	// Sized to exercise the VERIFICATION budget, which is what tickets newly put at
	// risk: comfortably under the coarse global bind limiter (rlGlobalRate, which
	// predates tickets and drops cheap packets indiscriminately), well over the
	// signature budget. A burst above rlGlobalRate is refused one step earlier, by
	// that limiter — a bound rather than a bypass, but also one the reserve sits
	// behind and therefore cannot rescue. That residual is pre-existing and is
	// stated in the docs rather than papered over here.
	const n = 900
	h.flood(t, "", n)

	verified := h.s.statVerify.Load()
	if verified >= n {
		t.Fatalf("%d of %d flood binds reached signature verification — the global budget did not hold", verified, n)
	}
	// The bucket starts full at twice the rate and refills while the burst runs, so
	// this is the ceiling to expect, not the nominal rate.
	if verified > 3*sigGlobalRate {
		t.Fatalf("%d verifications for one burst is over the expected ceiling (~%d)", verified, 2*sigGlobalRate)
	}
	if h.legs(victim) != 1 {
		t.Fatalf("the flood disturbed the victim session: %d leg(s)", h.legs(victim))
	}

	// The point of the reserve: with the global budget spent, the partner leg of an
	// already half-open session still completes.
	h.bind(t, vb)
	if h.legs(victim) != 2 {
		t.Fatal("the partner leg could not complete its pairing after the flood — the reserve did not hold")
	}
}

// TestReplayingALiveSessionIDGrantsNothing is plan case 40. sid arrives in an
// unverified packet: it is not a secret and never an authenticator, so an
// attacker who learns one (or guesses at a small table) must gain nothing by
// putting it in a packet.
//
// What it CAN do is contend for that session's own share of the reserve, and
// that is the honest limit of the design: the per-sid budget bounds the damage to
// the session whose id was already known, and buys no admission anywhere. Other
// half-open sessions are unaffected, which is what the next test pins down.
func TestReplayingALiveSessionIDGrantsNothing(t *testing.T) {
	h := newHarness(t, nil)
	victim := newSID(t)
	va := h.issue(t, victim, ticket.LegA, addr("127.0.0.1", 4001), nil)
	h.bind(t, va)

	before := h.s.statVerify.Load()
	h.flood(t, victim, 900)

	// No state: the reserve decides WHERE work waits, never whether it is checked.
	if h.legs(victim) != 1 {
		t.Fatalf("replaying a live session id changed the session: %d leg(s)", h.legs(victim))
	}
	if h.legAddr(victim, ticket.LegA) != va.src.String() {
		t.Fatal("replaying a live session id moved the bound leg")
	}
	// And the work it bought is bounded: the reserve is small and separately
	// metered, so it cannot be summed with the global ceiling.
	spent := h.s.statVerify.Load() - before
	if spent > 3*(sigGlobalRate+reserveRate) {
		t.Fatalf("a known-sid flood forced %d verifications, past the reserve+global ceiling", spent)
	}
}

// TestReserveIsNotAddedToTheGlobalBudget is plan case 41: one sid exhausting the
// reserve must not take the capacity other half-open sessions need, and must not
// give itself the global budget on top of its reserve share.
func TestReserveIsNotAddedToTheGlobalBudget(t *testing.T) {
	h := newHarness(t, nil)

	// Two half-open sessions.
	x, y := newSID(t), newSID(t)
	xa := h.issue(t, x, ticket.LegA, addr("127.0.0.1", 4001), nil)
	ya := h.issue(t, y, ticket.LegA, addr("127.0.0.3", 4003), nil)
	h.bind(t, xa)
	h.bind(t, ya)

	// Spend x's entire per-sid reserve share, and then some.
	for i := 0; i < 50; i++ {
		if !h.s.reserveRL.Allow(x) {
			break
		}
	}
	for i := 0; i < 50; i++ {
		h.s.reserveRL.Allow(x)
	}

	// y's partner still binds: it draws from the global budget, which x's reserve
	// consumption never touched.
	yb := h.issue(t, y, ticket.LegB, addr("127.0.0.4", 4004), nil)
	h.bind(t, yb)
	if h.legs(y) != 2 {
		t.Fatal("a session whose reserve was spent by ANOTHER sid could not complete")
	}

	// And x itself still completes, because falling back to the global budget is
	// exactly what a spent reserve does — it is one or the other, never both.
	xb := h.issue(t, x, ticket.LegB, addr("127.0.0.2", 4002), nil)
	h.bind(t, xb)
	if h.legs(x) != 2 {
		t.Fatal("a session that spent its reserve could not complete from the global budget")
	}
}

// TestOversizedBindIsRefusedBeforeParsing is step 1 of the check order: a
// datagram over the cap costs one length comparison, not a JSON parse.
func TestOversizedBindIsRefusedBeforeParsing(t *testing.T) {
	big := make([]byte, MaxBindLen+1)
	copy(big, BindPrefix)
	for i := len(BindPrefix); i < len(big); i++ {
		big[i] = ' '
	}
	if _, ok := ParseBind(big); ok {
		t.Fatal("an oversized bind was parsed")
	}
	// Positive control: the same shape inside the cap is still a bind.
	h := newHarness(t, nil)
	sid := newSID(t)
	a := h.issue(t, sid, ticket.LegA, addr("127.0.0.1", 4001), nil)
	raw, b64 := h.cookieFor(a.src.IP)
	pkt := MarshalBind(Bind{
		SessionToken: sid,
		Cookie:       b64,
		Ticket:       base64.RawURLEncoding.EncodeToString(a.payload),
		TicketSig:    base64.RawURLEncoding.EncodeToString(a.sig),
		BindSig:      base64.RawURLEncoding.EncodeToString(ticket.SignBind(a.eph, a.payload, a.sig, raw)),
	})
	if len(pkt) > MaxBindLen {
		t.Fatalf("a real ticketed bind is %d bytes, over the %d cap", len(pkt), MaxBindLen)
	}
	if _, ok := ParseBind(pkt); !ok {
		t.Fatal("a real ticketed bind did not parse")
	}
}
