package relay

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/tzero78/buddynet/internal/ratelimit"
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
	token string
	legs  []*leg
}

// Server is the blind UDP relay. It forwards datagrams between the two legs of a
// session and never inspects, decrypts, or stores payload — it sees only
// encrypted QUIC packets between two NAT-bound addresses.
type Server struct {
	ttl    time.Duration
	bindRL *ratelimit.Limiter

	mu        sync.Mutex
	sessions  map[string]*session // token -> session
	byAddr    map[string]*session // src addr string -> its session (fast forward)
	legsPerIP map[string]int      // source IP -> legs it holds (abuse ceiling)
}

// NewServer returns a relay whose bindings expire after ttl with no traffic.
func NewServer(ttl time.Duration) *Server {
	return &Server{
		ttl:       ttl,
		bindRL:    ratelimit.New(rlGlobalRate, rlSrcRate, rlMaxSources),
		sessions:  map[string]*session{},
		byAddr:    map[string]*session{},
		legsPerIP: map[string]int{},
	}
}

// Run reads datagrams off conn until it is closed: bind control packets claim a
// leg (and are acked), everything else is forwarded to the session's other leg.
func (s *Server) Run(conn *net.UDPConn) {
	go s.reap()
	buf := make([]byte, 1500)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return // socket closed on shutdown
		}
		pkt := buf[:n]
		if b, ok := ParseBind(pkt); ok {
			s.bind(conn, b.SessionToken, src)
			continue
		}
		s.forward(conn, src, pkt)
	}
}

// bind claims src as a leg of token's session and acks. The third distinct leg
// for a token is rejected (cap), so a stranger cannot hijack a pairing.
func (s *Server) bind(conn *net.UDPConn, token string, src *net.UDPAddr) {
	// Throttle bind control packets per source so a flood cannot churn sessions;
	// data forwarding (the hot path) is never rate-limited.
	if !s.bindRL.Allow(src.IP.String()) {
		return
	}
	s.mu.Lock()
	ses := s.sessions[token]
	if ses == nil {
		if len(s.sessions) >= maxSessions {
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
			s.mu.Unlock()
			return // a third party tried to join this session
		}
		if s.legsPerIP[ip] >= maxLegsPerIP {
			s.mu.Unlock()
			return // one source is hoarding sessions: refuse further legs
		}
		found = &leg{addr: src}
		ses.legs = append(ses.legs, found)
		s.byAddr[key] = ses
		s.legsPerIP[ip]++
		if len(ses.legs) == 2 {
			log.Printf("relay: session paired (%s <-> %s)", ses.legs[0].addr, ses.legs[1].addr)
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

// reap drops sessions whose legs have gone quiet past the TTL, so the maps can
// never grow unbounded.
func (s *Server) reap() {
	for range time.Tick(s.ttl) {
		s.mu.Lock()
		for token, ses := range s.sessions {
			kept := ses.legs[:0]
			for _, l := range ses.legs {
				if time.Since(l.seen) > s.ttl {
					delete(s.byAddr, l.addr.String())
					s.releaseIPLocked(l.addr.IP.String())
					continue
				}
				kept = append(kept, l)
			}
			ses.legs = kept
			if len(ses.legs) == 0 {
				delete(s.sessions, token)
			}
		}
		s.mu.Unlock()
	}
}
