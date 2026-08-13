package relay

import (
	"crypto/ed25519"
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

	"github.com/tzero78/buddynet/internal/netkey"
	"github.com/tzero78/buddynet/internal/ratelimit"
	"github.com/tzero78/buddynet/internal/safe"
)

// A relay runs in one of two authorization modes, and refuses to start without
// one (see role.Relay):
//
//   - TICKET MODE (Config.ServerKeys + RelayID). A bind must carry a permit
//     signed by a handshake server the operator named, bound to an ephemeral key
//     the binder must prove it holds. The relay learns THAT a session was
//     authorised, never who is in it: no buddy list, no identity in the bind, no
//     picture of who talks to whom.
//   - NETWORK MODE (Config.AllowCIDRs alone). Any source inside the listed
//     networks may bind, as before. Supported but not recommended — the buddies
//     who need a relay are precisely those behind changing residential
//     addresses, which a CIDR list cannot follow.
//
// Both may be set, and then both must pass: the CIDR list is hardening on top of
// tickets, never an alternative one can bypass.
//
// The relay can never be turned into a reflector — forward only ever writes to
// an address a bind was already heard from — and the caps below remain abuse
// ceilings on top of whichever mode is in force.
//
// The session/leg ceilings default high for an open/public relay. For a private
// BuddyNet relay serving a small group (BuddyNet caps a node at 48 buddies), an
// operator may lower them with --relay-max-sessions and --relay-max-legs-per-ip
// (e.g. 256 / 16) to tighten the abuse ceiling further; the defaults below apply
// when those flags are 0.

// Default hard caps bound memory even under spoofed source addresses (the only
// defense that works against address spoofing, since the source itself is
// forgeable). maxSessions/maxLegsPerIP are overridable per server (see NewServer);
// maxLegsPerSes is fixed — a session is exactly two buddies.
const (
	defaultMaxSessions  = 4096 // concurrent relayed sessions (override: --relay-max-sessions)
	maxLegsPerSes       = 2    // exactly two buddies per session; reject a third (fixed)
	defaultMaxLegsPerIP = 64   // legs one SOURCE may hold — one IPv4 address or one
	// IPv6 /64, see internal/netkey (override: --relay-max-legs-per-ip)
)

// Rate-limit ceilings for bind CONTROL packets only — data forwarding is the
// relay's whole job and must not be throttled. A buddy sends binds ~5x/sec while
// pairing and then stops, so these are generous.
const (
	rlGlobalRate = 1000
	rlSrcRate    = 50
	rlMaxSources = 8192
)

// Ticket-mode work ceilings. A bind used to be nearly free; with tickets it costs
// TWO Ed25519 verifications, so the per-source limiter above is no longer
// sufficient on its own — an attacker with many real addresses stays under every
// per-source budget while driving the total up. These bound the total.
const (
	// sigGlobalRate is the ceiling on ticket verifications per second across ALL
	// sources. At ~50us per verification this is a low-single-digit percent of one
	// core; a real pair binds about five times a second for a few seconds, so it
	// leaves room for many simultaneous pairings.
	sigGlobalRate = 200
	// maxSigInFlight caps concurrent verifications, so a burst inside the rate
	// still cannot pile up goroutines. Verification happens off the read loop for
	// exactly this reason: two signature checks inline would let a flood stall the
	// data path the relay exists to carry.
	maxSigInFlight = 32
	// The reserve: a small fixed budget for binds whose session already holds one
	// leg, metered separately from sigGlobalRate so the two cannot be summed. Keyed
	// by sid, which bounds what one sid — real or guessed — can consume.
	reserveRate       = 20
	reservePerSIDRate = 4
	reserveMaxSIDs    = 1024
)

// pendingPairTimeout is how long a session may hold ONE leg before it is dropped,
// measured from creation and not extendable. A leg's idle timer is refreshed by
// any packet from a bound source, so without an absolute bound one leg plus a
// trickle of traffic holds a session slot forever.
const pendingPairTimeout = 60 * time.Second

// leg is one bound end of a session: the source address a buddy's datagrams
// arrive from, plus its lock-free forwarding record.
type leg struct {
	addr *net.UDPAddr
	fwd  *fwd
	// acctKey is the budget this leg was CHARGED under at bind time
	// (netkey.FromIP: exact IPv4, /64 for IPv6). Stored rather than re-derived at
	// reap, so releasing can never credit a different key than binding charged —
	// the two would drift apart the moment the rule changes again.
	acctKey string
	// name and epk are set in TICKET MODE only. name is the "a"/"b" the server
	// assigned, so a session holds exactly one of each; epk is the ephemeral public
	// key that owns this leg, which is what lets a legitimate buddy move to a new
	// address (NAT rebind) while a third party with a copied ticket cannot.
	name string
	epk  string
}

// fwd is a leg's forwarding state, read on the data HOT PATH without taking
// s.mu: peer is the other leg's address (nil until paired, and again once the
// partner leaves), seen is this leg's last-activity time (unix nanos). Both are
// written under s.mu on the slow paths (bind/reap) and read/updated atomically by
// forward, so a relayed datagram never contends on the global lock — one busy
// session can no longer stall every other.
type fwd struct {
	peer atomic.Pointer[net.UDPAddr]
	seen atomic.Int64
}

// session is the pair of legs sharing a token. Once both are bound, data from
// one leg is forwarded to the other.
type session struct {
	token  string
	legs   []*leg
	paired bool // reached two legs at some point (for the close log)
	// created is when this session first appeared, used for the ABSOLUTE
	// half-open timeout. A leg's idle timer is refreshed by any packet from a
	// bound source, so one leg plus a trickle of traffic would otherwise hold a
	// session slot forever without a partner ever arriving.
	created time.Time
}

// Server is the blind UDP relay. It forwards datagrams between the two legs of a
// session and never inspects, decrypts, or stores payload — it sees only
// encrypted QUIC packets between two NAT-bound addresses.
type Server struct {
	ttl          time.Duration
	bindRL       *ratelimit.Limiter
	allowed      []netip.Prefix // if non-empty, only these source nets may bind a leg
	cookieKey    []byte         // keys the address-validation HMAC (random per process)
	maxSessions  int            // concurrent session ceiling (abuse bound)
	maxLegsPerIP int            // per-source leg ceiling (session-hoarding bound)
	// pendingPair is the absolute half-open timeout (pendingPairTimeout). A field
	// rather than the constant so a test can drive it in milliseconds instead of
	// sleeping for a minute; nothing in production ever changes it.
	pendingPair time.Duration

	// Ticket mode (empty serverKeys = network mode). serverKeys may hold two so a
	// server key rotation can be made before-break; the relay never holds a private
	// key of its own, so a compromised relay can withhold service but never
	// authorise a session.
	serverKeys []ed25519.PublicKey
	relayID    string
	debug      bool // log source addresses too (off by default, see the note in reject)

	// sigRL is the GLOBAL ceiling on ticket verifications per second. The cookie
	// stops spoofing, not an attacker with many real addresses: they can collect
	// valid cookies and force two Ed25519 verifications per bind from each address,
	// all of it under the per-source budget. This bounds the total regardless of
	// how the load is spread.
	sigRL *ratelimit.Limiter
	// reserveRL is a small, SEPARATELY metered budget for binds naming a session
	// that already holds one leg, so a flood cannot take the last capacity from a
	// pairing that is one bind away from completing. Keyed by sid, which gives it
	// the required per-sid limit for free: the sid arrives in an unverified packet
	// and is never an authenticator, so one sid — real or guessed — must not be
	// able to consume the whole reserve. A bind draws from the reserve OR from the
	// global budget, never both, so the two cannot be summed by an attacker.
	reserveRL *ratelimit.Limiter
	// inFlight caps concurrent signature verifications, so a burst that is inside
	// the rate still cannot pile up goroutines.
	inFlight chan struct{}

	mu       sync.Mutex
	sessions map[string]*session // token -> session (under mu)
	// legsPerIP counts legs per ACCOUNTING KEY (netkey: exact IPv4, /64 for IPv6),
	// not per exact address — one IPv6 /64 is free to mint addresses in, so keying
	// per address would count nothing (finding H-01). The same key is charged to
	// bindRL, so a source cannot exhaust one budget and get a fresh other one.
	legsPerIP map[string]int // accounting key -> legs it holds (abuse ceiling, under mu)

	// byAddr maps a leg's source-address string -> *fwd. It is a sync.Map so the
	// data hot path (forward) can look up the destination without taking mu;
	// entries are added/removed under mu by bind/reap.
	byAddr sync.Map

	done      chan struct{} // closed when Run returns, so reap stops with it
	closeOnce sync.Once

	// Audit counters (control-plane only; the data path is never counted so the hot
	// loop stays allocation- and contention-free). Summarized once per interval and
	// only when non-zero, so a quiet relay stays silent and abuse shows up.
	statPaired     atomic.Int64
	statChallenged atomic.Int64
	statRejected   atomic.Int64 // over-cap / outside allowlist / rate-limited
	statHoard      atomic.Int64 // per-source leg cap hit (possible session hoarding)
	statTicket     atomic.Int64 // binds refused by a ticket check (any reason)
	// statVerify counts binds that reached the SIGNATURE VERIFICATIONS. It is the
	// number that shows how much crypto work the relay is being made to do, and the
	// one the check-order tests assert on: "an invalid cookie costs no Ed25519" is
	// only a claim until something counts it.
	statVerify atomic.Int64

	// lastPanic is the process-wide recovered-panic total at the previous stats
	// tick, so statsLoop can report the per-interval delta. Touched only by the
	// single statsLoop goroutine, so it needs no atomic.
	lastPanic int64

	// hoardWarned throttles the per-source leg-cap WARNING to once per statsInterval so
	// a source hammering the cap cannot turn each packet into a log line. Bounded
	// and pruned; the counter carries the volume into the stats line.
	hoardWarned map[string]time.Time
	// rejectWarned throttles ticket-rejection lines the same way, one per REASON
	// per interval: a flood of refusals must not be a way to fill the operator's
	// disk. The per-interval counter carries the volume.
	rejectWarned map[string]time.Time
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
		tk, vf := s.statTicket.Swap(0), s.statVerify.Swap(0)
		// Per-interval count of panics recovered by safe.Do across the process: a
		// non-zero delta means a crafted datagram reliably trips a parser, which is
		// otherwise invisible (each panic is logged only once per throttle window).
		total := safe.PanicCount()
		pan := total - s.lastPanic
		s.lastPanic = total
		if pa|ch|rj|ho|tk|vf == 0 && pan == 0 {
			continue
		}
		line := fmt.Sprintf("stats (last %s): role=relay paired=%d challenged=%d rejected=%d", statsInterval, pa, ch, rj)
		if vf > 0 || tk > 0 {
			line += fmt.Sprintf(" tickets-verified=%d ticket-refused=%d", vf, tk)
		}
		if ho > 0 || pan > 0 {
			line += fmt.Sprintf(" ALERT: leg-cap=%d panics=%d", ho, pan)
		}
		log.Print(line)
	}
}

// warnHoardLocked logs a per-source leg-cap WARNING at most once per
// statsInterval, so a source hammering the cap cannot flood the log (the counter
// carries the volume). acct is the accounting key (exact IPv4, or an IPv6 /64),
// which is what the operator needs to see — the individual address inside a /64
// is not the actor. Caller holds s.mu.
func (s *Server) warnHoardLocked(acct string) {
	now := time.Now()
	if last, ok := s.hoardWarned[acct]; ok && now.Sub(last) < statsInterval {
		return
	}
	if len(s.hoardWarned) >= s.maxSessions {
		for k, t := range s.hoardWarned {
			if now.Sub(t) >= statsInterval {
				delete(s.hoardWarned, k)
			}
		}
		if len(s.hoardWarned) >= s.maxSessions {
			return // bounded: skip the line under extreme spread (stats still fire)
		}
	}
	s.hoardWarned[acct] = now
	log.Printf("SECURITY: event=leg-cap-hit src=%s detail=%q", acct, "one source holds the max legs; possible session hoarding")
}

// Config is a relay's authorization policy and abuse ceilings. The zero value is
// deliberately NOT a usable relay: role.Relay refuses to start without either
// ServerKeys (ticket mode) or AllowCIDRs (network mode), so "open to everyone"
// cannot be reached by leaving something out.
type Config struct {
	TTL time.Duration // drop a leg after this long with no traffic
	// ServerKeys are the handshake server identity keys whose tickets this relay
	// accepts. Non-empty turns on ticket mode. Two keys are allowed so a server
	// key rotation has a grace window; they are PUBLIC keys — a relay holds no
	// signing key and therefore cannot mint a permit for itself or anyone else.
	ServerKeys []ed25519.PublicKey
	// RelayID is this relay's non-secret id, configured identically on the
	// handshake server. Required in ticket mode: it is what stops a ticket minted
	// for another relay from being replayed here.
	RelayID string
	// AllowCIDRs, if non-empty, restricts which source networks may bind. Combined
	// with ticket mode it is an AND: a bind needs a valid ticket AND an allowed
	// source address.
	AllowCIDRs []netip.Prefix
	// MaxSessions / MaxLegsPerIP override the abuse ceilings; 0 uses the defaults.
	MaxSessions  int
	MaxLegsPerIP int
	// Debug adds source addresses to rejection logs. Off by default on purpose:
	// the relay's whole claim is that it does not build a picture of who talks to
	// whom, and an address next to a session id in a shipped log undermines it.
	Debug bool
}

// New returns a relay whose bindings expire after cfg.TTL with no traffic.
func New(cfg Config) *Server {
	ttl := cfg.TTL
	maxSessions, maxLegsPerIP := cfg.MaxSessions, cfg.MaxLegsPerIP
	allowed := cfg.AllowCIDRs
	if maxSessions <= 0 {
		maxSessions = defaultMaxSessions
	}
	if maxLegsPerIP <= 0 {
		maxLegsPerIP = defaultMaxLegsPerIP
	}
	// The relay holds no identity key, so the cookie HMAC is keyed by a random
	// secret minted per process: it need only be unforgeable and stable for this
	// run (a restart just re-challenges live binds, a sub-second cost).
	//
	// A failure here is FATAL, never a zero key: an all-zero HMAC key is one every
	// attacker can reproduce, so cookies would be forgeable and the relay's
	// return-routability check — its whole anti-reflection guarantee — would be
	// gone, silently. Under Go 1.24+ crypto/rand.Read cannot fail (it crashes the
	// process itself), so this branch is unreachable; it must still not read as a
	// deliberate fall-open if that ever changes.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(fmt.Sprintf("relay: crypto/rand unavailable, refusing to run with a forgeable cookie key: %v", err))
	}
	return &Server{
		ttl:          ttl,
		bindRL:       ratelimit.New(rlGlobalRate, rlSrcRate, rlMaxSources),
		allowed:      allowed,
		cookieKey:    key,
		maxSessions:  maxSessions,
		maxLegsPerIP: maxLegsPerIP,
		pendingPair:  pendingPairTimeout,
		serverKeys:   cfg.ServerKeys,
		relayID:      cfg.RelayID,
		debug:        cfg.Debug,
		sigRL:        ratelimit.NewGlobal(sigGlobalRate),
		reserveRL:    ratelimit.New(reserveRate, reservePerSIDRate, reserveMaxSIDs),
		inFlight:     make(chan struct{}, maxSigInFlight),
		sessions:     map[string]*session{},
		legsPerIP:    map[string]int{},
		hoardWarned:  map[string]time.Time{},
		rejectWarned: map[string]time.Time{},
		done:         make(chan struct{}),
	}
}

// ticketMode reports whether this relay verifies tickets. It is decided once at
// construction: there is no per-bind fallback to "no ticket needed", because a
// fallback is exactly what an attacker would aim for.
func (s *Server) ticketMode() bool { return len(s.serverKeys) > 0 }

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
// ip, compared in constant time, and returns the RAW cookie bytes. An
// empty/garbage cookie is rejected.
//
// The bytes are returned because the ticket-mode proof of possession is signed
// over exactly this value: it is the only thing in a bind that is fresh,
// relay-chosen and bound to the source address, which is what makes a captured
// bind worthless from anywhere else or after the epoch turns.
func (s *Server) validCookie(b64 string, ip net.IP) ([]byte, bool) {
	if b64 == "" {
		return nil, false
	}
	got, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil || len(got) != CookieLen {
		return nil, false
	}
	now := time.Now().UnixNano() / int64(cookieEpoch)
	if hmac.Equal(got, s.computeCookie(ip, now)) || hmac.Equal(got, s.computeCookie(ip, now-1)) {
		return got, true
	}
	return nil, false
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
				s.bind(conn, b, src, len(pkt))
				return
			}
			s.forward(conn, src, pkt)
		})
	}
}

// bind runs the relay's FIXED check order, cheapest and most spoof-resistant
// first; nothing below the cookie runs for a packet that fails it:
//
//  1. size cap        — in ParseBind, before any field is looked at
//  2. CIDR            — before any crypto
//  3. per-source rate — a cheap map lookup
//  4. cookie          — no valid cookie: answer a challenge, create NO state
//  5. everything expensive (ticket parse, two signature verifications) and
//     only then any state allocation — see admitTicketBind
//
// The point of the order is that an unvalidated source can never make the relay
// perform an Ed25519 verification or allocate a session. The cookie already
// proves return-routability; everything costly sits behind it.
//
// A bind without a valid cookie is answered with a challenge and creates NO
// state, so a spoofed source can never have a leg bound for it (the relay's
// anti-reflection / anti-laundering guarantee).
func (s *Server) bind(conn *net.UDPConn, b Bind, src *net.UDPAddr, reqLen int) {
	token := b.SessionToken
	// Access control: a source outside the allowlist may not bind a leg, so it
	// cannot use the relay at all. Checked before the rate limiter so a disallowed
	// source consumes no budget — and it is an AND with ticket mode, never an
	// either/or: a valid ticket does not buy admission from a refused network.
	if !s.cidrAllowed(src.IP) {
		s.statRejected.Add(1)
		return
	}
	// One accounting key for BOTH per-source budgets below (rate limit and leg
	// cap). Deriving it once is what keeps them identical: charging the limiter
	// per exact address while capping legs per /64 (or vice versa) leaves whichever
	// is looser as the bypass.
	acct := netkey.FromIP(src.IP)
	// Throttle bind control packets per source so a flood cannot churn sessions;
	// data forwarding (the hot path) is never rate-limited.
	if !s.bindRL.Allow(acct) {
		s.statRejected.Add(1)
		return
	}
	// Return-routability: an unvalidated bind only ever draws a (smaller-than-the-
	// bind) challenge, never state. A spoofed source never receives the challenge,
	// so it can never echo a valid cookie — closing reflection before any binding.
	cookie, ok := s.validCookie(b.Cookie, src.IP)
	if !ok {
		s.statChallenged.Add(1)
		// Answer only when the challenge is STRICTLY SMALLER than the bind that
		// triggered it. The parser accepts a 17-byte bind (a one-character session
		// token) while the challenge is a fixed 23 bytes, so without this gate the
		// "smaller than the bind, never an amplifier" property held for realistic
		// tokens but not for the smallest accepted one. A real bind carries a
		// 22-character token (38 bytes), leaving 15 bytes of headroom.
		if chal := MarshalChallenge(s.freshCookie(src.IP)); len(chal) < reqLen {
			conn.WriteToUDP(chal, src)
		}
		return
	}
	if s.ticketMode() {
		// Everything from here is expensive, so it happens off the read loop and
		// under its own budgets. The session is named by the SERVER in the ticket,
		// so nothing a client chose reaches the map below.
		s.admitTicketBind(conn, b, src, acct, cookie)
		return
	}
	s.bindNetworkMode(conn, b, src, acct, token)
}

// bindNetworkMode is the pre-ticket behaviour, still used when the relay is
// restricted by --allow-cidr alone: legs are keyed by source address and any
// source inside the allowlist may claim one.
func (s *Server) bindNetworkMode(conn *net.UDPConn, b Bind, src *net.UDPAddr, acct, token string) {
	s.mu.Lock()
	ses := s.sessions[token]
	// created tracks whether THIS call put the session in the map. Every path that
	// then refuses the leg must take that empty session back out again — otherwise
	// a refused bind still costs a global session slot, and the per-source leg cap
	// stops being the binding constraint: a source throttled to N binds/second
	// fills the whole table with LEGLESS sessions without ever holding a leg.
	created := false
	if ses == nil {
		if len(s.sessions) >= s.maxSessions {
			s.statRejected.Add(1)
			s.mu.Unlock()
			return // global capacity reached: drop silently
		}
		ses = &session{token: token, created: time.Now()}
		s.sessions[token] = ses
		created = true
	}
	// dropIfEmptyLocked undoes the session this call created when the leg is then
	// refused. A session we did NOT create is left alone: it belongs to whoever
	// bound the other leg.
	dropIfEmptyLocked := func() {
		if created && len(ses.legs) == 0 {
			delete(s.sessions, token)
		}
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
		if len(ses.legs) >= maxLegsPerSes {
			s.statRejected.Add(1)
			dropIfEmptyLocked()
			s.mu.Unlock()
			return // a third party tried to join this session
		}
		if s.legsPerIP[acct] >= s.maxLegsPerIP {
			s.statRejected.Add(1)
			s.statHoard.Add(1)
			s.warnHoardLocked(acct)
			dropIfEmptyLocked()
			s.mu.Unlock()
			return // one source is hoarding sessions: refuse further legs
		}
		found = &leg{addr: src, fwd: &fwd{}, acctKey: acct}
		ses.legs = append(ses.legs, found)
		s.byAddr.Store(key, found.fwd)
		s.legsPerIP[acct]++
		if len(ses.legs) == 2 {
			ses.paired = true
			s.statPaired.Add(1)
			// Publish each leg's partner so forward() can route lock-free.
			ses.legs[0].fwd.peer.Store(ses.legs[1].addr)
			ses.legs[1].fwd.peer.Store(ses.legs[0].addr)
			log.Printf("RELAY: action=session-paired a=%s b=%s", ses.legs[0].addr, ses.legs[1].addr)
		}
	}
	found.fwd.seen.Store(time.Now().UnixNano())
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
	// Hot path: a single sync.Map lookup and two atomic ops, no global lock — so
	// one high-rate session can never serialise (or stall) all the others. An
	// unbound source has no entry and is dropped, so the relay never originates to
	// an address it has not heard a bind from (anti-reflection, unchanged).
	v, ok := s.byAddr.Load(src.String())
	if !ok {
		return
	}
	f := v.(*fwd)
	f.seen.Store(time.Now().UnixNano())
	if dst := f.peer.Load(); dst != nil {
		conn.WriteToUDP(pkt, dst)
	}
}

// releaseIPLocked decrements the leg count for a reaped leg's ACCOUNTING KEY
// (leg.acctKey, the value charged at bind), dropping the entry at zero so the map
// mirrors live legs. Caller holds s.mu.
func (s *Server) releaseIPLocked(acct string) {
	if s.legsPerIP[acct] <= 1 {
		delete(s.legsPerIP, acct)
		return
	}
	s.legsPerIP[acct]--
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
			// A session that has NEVER reached two legs expires an absolute
			// pendingPairTimeout after creation, whatever its traffic. Refreshing on
			// activity — which the idle timer below does — would let one leg plus a
			// trickle hold a slot indefinitely without a partner ever arriving.
			if !ses.paired && now.Sub(ses.created) > s.pendingPair {
				for _, l := range ses.legs {
					s.byAddr.Delete(l.addr.String())
					s.releaseIPLocked(l.acctKey)
				}
				delete(s.sessions, token)
				continue
			}
			kept := ses.legs[:0]
			for _, l := range ses.legs {
				if now.UnixNano()-l.fwd.seen.Load() > int64(s.ttl) {
					s.byAddr.Delete(l.addr.String())
					// Release the key this leg was CHARGED under, never a freshly
					// derived one: re-deriving here is how bind and reap drift apart.
					s.releaseIPLocked(l.acctKey)
					continue
				}
				kept = append(kept, l)
			}
			ses.legs = kept
			// A surviving lone leg must stop forwarding to its now-reaped partner
			// until a fresh bind re-pairs them.
			if len(ses.legs) == 1 {
				ses.legs[0].fwd.peer.Store(nil)
			}
			if len(ses.legs) == 0 {
				if ses.paired {
					log.Printf("RELAY: action=session-closed detail=%q", fmt.Sprintf("idle > %s", s.ttl))
				}
				delete(s.sessions, token)
			}
		}
		// Release stale per-source hoard-warning latches so the map mirrors recent abuse.
		for ip, t := range s.hoardWarned {
			if now.Sub(t) >= statsInterval {
				delete(s.hoardWarned, ip)
			}
		}
		for reason, t := range s.rejectWarned {
			if now.Sub(t) >= statsInterval {
				delete(s.rejectWarned, reason)
			}
		}
		s.mu.Unlock()
	}
}
