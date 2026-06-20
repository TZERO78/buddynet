package relay

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tzero78/buddynet/internal/ratelimit"
	"github.com/tzero78/buddynet/internal/safe"
)

// The relay is intentionally UNAUTHENTICATED: anyone who can reach it may pair
// two legs under a shared session token (that is what makes it a drop-in
// fallback for any buddy). It can never be turned into a reflector — forward
// only ever writes to an address a bind was already heard from — but it is open
// bandwidth, so the caps below are abuse ceilings, not access control. Operators
// who want a private relay should firewall it or run it only for known buddies.

// Hard caps bound memory even under spoofed source addresses (the only defense
// that works against address spoofing, since the source itself is forgeable).
const (
	maxSessions   = 4096 // concurrent relayed sessions
	maxLegsPerSes = 2    // exactly two buddies per session; reject a third
	maxLegsPerIP  = 64   // legs one source address may hold (bounds session hoarding)
)

// Rate-limit ceilings for bind CONTROL packets only — data forwarding is the
// relay's whole job and must not be throttled. A buddy sends binds ~5x/sec while
// pairing and then stops, so these are generous.
const (
	rlGlobalRate = 1000
	rlSrcRate    = 50
	rlMaxSources = 8192
)

// leg is one bound end of a session: the source address a buddy's datagrams
// arrive from, and when we last heard from it.
type leg struct {
	addr *net.UDPAddr
	seen time.Time
}

// session is the pair of legs sharing a token. Once both are bound, data from
// one leg is forwarded to the other.
type session struct {
	token  string
	legs   []*leg
	paired bool // reached two legs at some point (for the close log)
}

// Server is the blind UDP relay. It forwards datagrams between the two legs of a
// session and never inspects, decrypts, or stores payload — it sees only
// encrypted QUIC packets between two NAT-bound addresses.
type Server struct {
	ttl       time.Duration
	bindRL    *ratelimit.Limiter
	allowed   []netip.Prefix // if non-empty, only these source nets may bind a leg
	cookieKey []byte         // keys the address-validation HMAC (random per process)

	mu        sync.Mutex
	sessions  map[string]*session // token -> session
	byAddr    map[string]*session // src addr string -> its session (fast forward)
	legsPerIP map[string]int      // source IP -> legs it holds (abuse ceiling)

	done      chan struct{} // closed when Run returns, so reap stops with it
	closeOnce sync.Once

	// Audit counters (control-plane only; the data path is never counted so the hot
	// loop stays allocation- and contention-free). Summarized once per interval and
	// only when non-zero, so a quiet relay stays silent and abuse shows up.
	statPaired     atomic.Int64
	statChallenged atomic.Int64
	statRejected   atomic.Int64 // over-cap / outside allowlist / rate-limited
	statHoard      atomic.Int64 // per-IP leg cap hit (possible session hoarding)

	// hoardWarned throttles the per-IP leg-cap WARNING to once per statsInterval so
	// a source hammering the cap cannot turn each packet into a log line. Bounded
	// and pruned; the counter carries the volume into the stats line.
	hoardWarned map[string]time.Time
}

const statsInterval = 60 * time.Second

func (s *Server) statsLoop() {
	t := time.NewTicker(statsInterval)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
		}
		pa, ch := s.statPaired.Swap(0), s.statChallenged.Swap(0)
		rj, ho := s.statRejected.Swap(0), s.statHoard.Swap(0)
		if pa|ch|rj|ho == 0 {
			continue
		}
		line := fmt.Sprintf("stats (last %s): role=relay paired=%d challenged=%d rejected=%d", statsInterval, pa, ch, rj)
		if ho > 0 {
			line += fmt.Sprintf(" ALERT: leg-cap=%d", ho)
		}
		log.Print(line)
	}
}

// warnHoardLocked logs a per-IP leg-cap WARNING at most once per statsInterval,
// so a source hammering the cap cannot flood the log (the counter carries the
// volume). Caller holds s.mu.
func (s *Server) warnHoardLocked(ip string) {
	now := time.Now()
	if last, ok := s.hoardWarned[ip]; ok && now.Sub(last) < statsInterval {
		return
	}
	if len(s.hoardWarned) >= maxSessions {
		for k, t := range s.hoardWarned {
			if now.Sub(t) >= statsInterval {
				delete(s.hoardWarned, k)
			}
		}
		if len(s.hoardWarned) >= maxSessions {
			return // bounded: skip the line under extreme spread (stats still fire)
		}
	}
	s.hoardWarned[ip] = now
	log.Printf("SECURITY: event=leg-cap-hit src=%s detail=%q", ip, "one source holds the max legs; possible session hoarding")
}

// NewServer returns a relay whose bindings expire after ttl with no traffic. If
// allowed is non-empty the relay is no longer open: only sources inside one of
// those CIDRs may bind a leg (optional access control for a private relay); an
// empty allowed keeps the default open-to-all behaviour.
func NewServer(ttl time.Duration, allowed []netip.Prefix) *Server {
	// The relay holds no identity key, so the cookie HMAC is keyed by a random
	// secret minted per process: it need only be unforgeable and stable for this
	// run (a restart just re-challenges live binds, a sub-second cost). 32 bytes
	// of crypto/rand cannot realistically fail; fall back to a zero key only to
	// stay non-panicking, which still validates returns within one process.
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return &Server{
		ttl:         ttl,
		bindRL:      ratelimit.New(rlGlobalRate, rlSrcRate, rlMaxSources),
		allowed:     allowed,
		cookieKey:   key,
		sessions:    map[string]*session{},
		byAddr:      map[string]*session{},
		legsPerIP:   map[string]int{},
		hoardWarned: map[string]time.Time{},
		done:        make(chan struct{}),
	}
}

// cookieEpoch is the validity granularity of a bind address-validation cookie. A
// cookie is accepted for the current and previous epoch, so it lives 30..60s —
// long enough to complete a bind round-trip, short enough to bound replay of a
// captured cookie to its source address.
const cookieEpoch = 30 * time.Second

// computeCookie is HMAC(cookieKey, epoch || canonical-ip), truncated to CookieLen.
// Binding to the source IP is what makes it prove return-routability: only a host
// that actually received the challenge at that address can echo a matching value.
func (s *Server) computeCookie(ip net.IP, epoch int64) []byte {
	mac := hmac.New(sha256.New, s.cookieKey)
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], uint64(epoch))
	mac.Write(e[:])
	mac.Write(ip.To16())
	return mac.Sum(nil)[:CookieLen]
}

// freshCookie mints a cookie for the current epoch and source IP.
func (s *Server) freshCookie(ip net.IP) []byte {
	return s.computeCookie(ip, time.Now().UnixNano()/int64(cookieEpoch))
}

// validCookie accepts a base64 cookie matching the current or previous epoch for
// ip, compared in constant time. An empty/garbage cookie is rejected.
func (s *Server) validCookie(b64 string, ip net.IP) bool {
	if b64 == "" {
		return false
	}
	got, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil || len(got) != CookieLen {
		return false
	}
	now := time.Now().UnixNano() / int64(cookieEpoch)
	return hmac.Equal(got, s.computeCookie(ip, now)) || hmac.Equal(got, s.computeCookie(ip, now-1))
}

// cidrAllowed reports whether a source IP may bind. With no allowlist the relay
// is open (default); otherwise the IP must fall inside one of the allowed CIDRs.
// Gating at bind is sufficient: forwarding only ever reaches addresses that have
// already bound a leg.
func (s *Server) cidrAllowed(ip net.IP) bool {
	if len(s.allowed) == 0 {
		return true
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	for _, p := range s.allowed {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Run reads datagrams off conn until it is closed: bind control packets claim a
// leg (and are acked), everything else is forwarded to the session's other leg.
func (s *Server) Run(conn *net.UDPConn) {
	defer s.stop() // stop reap when the read loop exits (socket closed on shutdown)
	go s.reap()
	go s.statsLoop()
	buf := make([]byte, 1500)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return // socket closed on shutdown
		}
		pkt := buf[:n]
		// Isolate a panic to the single datagram, never the read loop / process.
		safe.Do("relay.packet", func() {
			if b, ok := ParseBind(pkt); ok {
				s.bind(conn, b, src)
				return
			}
			s.forward(conn, src, pkt)
		})
	}
}

// bind claims src as a leg of token's session and acks. The third distinct leg
// for a token is rejected (cap), so a stranger cannot hijack a pairing. A bind
// without a valid address-validation cookie is answered with a challenge and
// creates NO state, so a spoofed source can never have a leg bound for it (the
// relay's anti-reflection / anti-laundering guarantee).
func (s *Server) bind(conn *net.UDPConn, b Bind, src *net.UDPAddr) {
	token := b.SessionToken
	// Access control (optional): a source outside the allowlist may not bind a
	// leg, so it cannot use the relay at all. Checked before the rate limiter so a
	// disallowed source consumes no budget.
	if !s.cidrAllowed(src.IP) {
		s.statRejected.Add(1)
		return
	}
	// Throttle bind control packets per source so a flood cannot churn sessions;
	// data forwarding (the hot path) is never rate-limited.
	if !s.bindRL.Allow(src.IP.String()) {
		s.statRejected.Add(1)
		return
	}
	// Return-routability: an unvalidated bind only ever draws a (smaller-than-the-
	// bind) challenge, never state. A spoofed source never receives the challenge,
	// so it can never echo a valid cookie — closing reflection before any binding.
	if !s.validCookie(b.Cookie, src.IP) {
		s.statChallenged.Add(1)
		conn.WriteToUDP(MarshalChallenge(s.freshCookie(src.IP)), src)
		return
	}
	s.mu.Lock()
	ses := s.sessions[token]
	if ses == nil {
		if len(s.sessions) >= maxSessions {
			s.statRejected.Add(1)
			s.mu.Unlock()
			return // global capacity reached: drop silently
		}
		ses = &session{token: token}
		s.sessions[token] = ses
	}
	key := src.String()
	var found *leg
	for _, l := range ses.legs {
		if l.addr.String() == key {
			found = l
			break
		}
	}
	if found == nil {
		ip := src.IP.String()
		if len(ses.legs) >= maxLegsPerSes {
			s.statRejected.Add(1)
			s.mu.Unlock()
			return // a third party tried to join this session
		}
		if s.legsPerIP[ip] >= maxLegsPerIP {
			s.statRejected.Add(1)
			s.statHoard.Add(1)
			s.warnHoardLocked(ip)
			s.mu.Unlock()
			return // one source is hoarding sessions: refuse further legs
		}
		found = &leg{addr: src}
		ses.legs = append(ses.legs, found)
		s.byAddr[key] = ses
		s.legsPerIP[ip]++
		if len(ses.legs) == 2 {
			ses.paired = true
			s.statPaired.Add(1)
			log.Printf("RELAY: action=session-paired a=%s b=%s", ses.legs[0].addr, ses.legs[1].addr)
		}
	}
	found.seen = time.Now()
	s.mu.Unlock()

	// Ack the bind from the relay address so the buddy knows its leg is live and
	// the return path through NAT is open.
	conn.WriteToUDP(MarshalBind(Bind{SessionToken: token}), src)
}

// forward relays a data datagram to the other leg of the sender's session. An
// unbound source (no session, or partner not yet bound) is dropped — the relay
// never originates traffic to an address it has not heard a bind from, so it
// cannot be turned into a reflector.
func (s *Server) forward(conn *net.UDPConn, src *net.UDPAddr, pkt []byte) {
	s.mu.Lock()
	ses := s.byAddr[src.String()]
	var dst *net.UDPAddr
	if ses != nil {
		key := src.String()
		for _, l := range ses.legs {
			if l.addr.String() == key {
				l.seen = time.Now()
			} else {
				dst = l.addr
			}
		}
	}
	s.mu.Unlock()
	if dst != nil {
		conn.WriteToUDP(pkt, dst)
	}
}

// releaseIPLocked decrements the per-IP leg count for a reaped leg, dropping the
// entry at zero so the map mirrors live legs. Caller holds s.mu.
func (s *Server) releaseIPLocked(ip string) {
	if s.legsPerIP[ip] <= 1 {
		delete(s.legsPerIP, ip)
		return
	}
	s.legsPerIP[ip]--
}

// stop signals reap to exit. Idempotent; called when Run's read loop returns.
func (s *Server) stop() { s.closeOnce.Do(func() { close(s.done) }) }

// reap drops sessions whose legs have gone quiet past the TTL, so the maps can
// never grow unbounded. It runs until stop() is called (Run returning), so the
// ticker is released on shutdown instead of leaking like a bare time.Tick.
func (s *Server) reap() {
	t := time.NewTicker(s.ttl)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
		}
		now := time.Now()
		s.mu.Lock()
		for token, ses := range s.sessions {
			kept := ses.legs[:0]
			for _, l := range ses.legs {
				if now.Sub(l.seen) > s.ttl {
					delete(s.byAddr, l.addr.String())
					s.releaseIPLocked(l.addr.IP.String())
					continue
				}
				kept = append(kept, l)
			}
			ses.legs = kept
			if len(ses.legs) == 0 {
				if ses.paired {
					log.Printf("RELAY: action=session-closed detail=%q", fmt.Sprintf("idle > %s", s.ttl))
				}
				delete(s.sessions, token)
			}
		}
		// Release stale per-IP hoard-warning latches so the map mirrors recent abuse.
		for ip, t := range s.hoardWarned {
			if now.Sub(t) >= statsInterval {
				delete(s.hoardWarned, ip)
			}
		}
		s.mu.Unlock()
	}
}
