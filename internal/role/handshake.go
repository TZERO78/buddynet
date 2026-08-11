package role

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/hkdf"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/ratelimit"
	"github.com/tzero78/buddynet/internal/safe"
	"github.com/tzero78/buddynet/internal/tunnel"
	"github.com/tzero78/buddynet/pkg/protocol"
)

// HandshakeConfig configures the bootstrap/matchmaking server (--role=handshake).
type HandshakeConfig struct {
	Listen     string        // UDP address, e.g. "[::]:51820"
	KeyPath    string        // Ed25519 identity seed; empty = ephemeral
	Authorized string        // optional client allowlist (approval mode)
	TTL        time.Duration // liveness window for a registration
	Debug      bool          // verbose, security-sensitive logging
	QUIC       bool          // run the control plane over QUIC instead of plain UDP
	// RelayEndpoint, if set, is advertised to every paired buddy as a relay of
	// last resort — use it when this VPS also runs --role=relay (commonly on a
	// second port). Buddies fall back to it only after a direct punch fails.
	RelayEndpoint string
	// AllowCIDRs, if non-empty, drops any datagram/connection whose source is not
	// inside one of these networks BEFORE the cookie and any crypto — a cheap
	// DoS pre-filter for a private/known-fleet server. Empty keeps it open to all.
	AllowCIDRs []netip.Prefix
}

// cidrAllowed reports whether a source IP may be served. Empty allowlist = open.
func cidrAllowed(allowed []netip.Prefix, ip net.IP) bool {
	if len(allowed) == 0 {
		return true
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	for _, p := range allowed {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Hard caps bound server memory regardless of spoofed source addresses.
const (
	maxTokens       = 4096
	maxIDsPerToken  = 2
	maxCandsPerPeer = 8
	maxCodeEncLen   = 512
)

// controlIdleTimeout bounds an idle QUIC control connection. A buddy polls the
// server ~1/s while waiting for its partner, so keepalive holds the connection
// open well within this; it only fires if a client goes silent entirely.
const controlIdleTimeout = 2 * time.Minute

// regSkew is the clock-skew tolerance for a signed registration's timestamp
// (approval mode): a registration is accepted only if its ts is within ±regSkew
// of the server's clock, bounding how long a captured one stays replayable.
const regSkew = 60 * time.Second

// Rate-limit ceilings for the public UDP listener. The global rate bounds total
// per-packet crypto (signature verify + sealed-code open in approval mode) so a
// flood cannot saturate the single read loop; the per-source rate keeps one
// address from consuming the whole budget. A legitimate buddy re-registers only
// ~1/s, so the per-source allowance is generous.
const (
	rlGlobalRate = 1000 // admitted packets/sec across all sources
	rlSrcRate    = 50   // admitted packets/sec per source address
	rlMaxSources = 8192 // bound on the tracked-source map
)

// hsPeer accumulates what the server knows about one (token,id) across its v4
// and v6 registrations.
type hsPeer struct {
	id        string
	role      protocol.Role
	pubkey    string
	virtualIP string
	name      string // self-asserted .buddy name; relayed as-is, not validated by the server
	cands     map[string]protocol.Candidate
	seen      time.Time
}

func (p *hsPeer) observe(src *net.UDPAddr) {
	p.seen = time.Now()
	key := src.String()
	if _, ok := p.cands[key]; !ok && len(p.cands) >= maxCandsPerPeer {
		return // at cap: ignore further endpoints (anti spoof-bloat)
	}
	p.cands[key] = protocol.Candidate{Addr: key, V6: src.IP.To4() == nil}
}

func (p *hsPeer) candidates() []protocol.Candidate {
	out := make([]protocol.Candidate, 0, len(p.cands))
	for _, c := range p.cands {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out
}

// asProtocolPeer renders the peer as a PEER_LIST entry. relay is attached as the
// server-advised fallback (may be empty).
func (p *hsPeer) asProtocolPeer(relay string) protocol.Peer {
	return protocol.Peer{
		ID:         p.id,
		PubKey:     p.pubkey,
		VirtualIP:  p.virtualIP,
		Name:       p.name,
		Candidates: p.candidates(),
		Relay:      relay,
		LastSeen:   p.seen.Unix(),
	}
}

// hsRegistry pairs peers by token, in memory only, bounded by the caps above.
type hsRegistry struct {
	mu      sync.Mutex
	waiting map[string]map[string]*hsPeer
	// seenPKs tracks every distinct Ed25519 pubkey observed per token (capped at
	// maxIDsPerToken+1 entries to bound memory). Used for squat/intrusion detection:
	// a new pubkey on an established token fires a WARNING in the server log.
	seenPKs map[string]map[string]struct{}
	// intruderWarned records tokens for which an intrusion WARNING was already
	// emitted, so the immediate log fires AT MOST ONCE per token even under an
	// open-mode squat flood (the per-minute stats counters still carry the volume).
	// Bounded by maxTokens and released with the token in evict/reap.
	intruderWarned map[string]struct{}
	ttl            time.Duration
}

func newHSRegistry(ttl time.Duration) *hsRegistry {
	return &hsRegistry{
		waiting:        map[string]map[string]*hsPeer{},
		seenPKs:        map[string]map[string]struct{}{},
		intruderWarned: map[string]struct{}{},
		ttl:            ttl,
	}
}

// warnIntruderLocked logs an intrusion WARNING at most once per token, so a flood
// of foreign registrations on a known token cannot turn each packet into a log
// line (the codebase gates all per-packet load this way; counters carry volume).
// Caller holds r.mu.
func (r *hsRegistry) warnIntruderLocked(token, format string, args ...any) {
	if _, done := r.intruderWarned[token]; done {
		return
	}
	if len(r.intruderWarned) >= maxTokens {
		return // bounded: under extreme token spread skip the line (stats still fire)
	}
	r.intruderWarned[token] = struct{}{}
	log.Printf(format, args...)
}

func (r *hsRegistry) upsert(m protocol.Message, src *net.UDPAddr) (self, partner *hsPeer, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	bucket := r.waiting[m.Token]
	if bucket == nil {
		if len(r.waiting) >= maxTokens {
			// Table full. Hard-rejecting every new token lets a source-spoofed
			// flood of one-shot tokens lock out all legitimate pairings until the
			// reaper catches up. Instead evict the stalest bucket: a real pair
			// re-registers ~1/s and stays fresh, while a spoofed fire-and-forget
			// token has nobody refreshing it and ages into the eviction target.
			if !r.evictStalestLocked() {
				return nil, nil, false
			}
		}
		bucket = map[string]*hsPeer{}
		r.waiting[m.Token] = bucket
	}
	self = bucket[m.ID]
	if self == nil {
		if len(bucket) >= maxIDsPerToken {
			// A third distinct identity is trying to join an already-full token slot.
			// This fires when a squat succeeded (attacker took one slot) and the
			// legitimate buddy now finds no room, or when an attacker probes an
			// occupied token.
			hsStats.squatRejected.Add(1)
			r.warnIntruderLocked(m.Token, "SECURITY: event=squat-rejected token=%s src=%s key=%s id=%s detail=%q",
				logTag(m.Token), src.IP, keyTag(m.PubKey), m.ID, "third-party register on a full token slot; possible squat in progress")
			return nil, nil, false
		}
		self = &hsPeer{id: m.ID, cands: map[string]protocol.Candidate{}}
		bucket[m.ID] = self
	}
	if m.PubKey != "" {
		// Intrusion detection: track distinct pubkeys per token. A new pubkey on an
		// established token means either a legitimate new device (key rotation, fresh
		// install) or an attacker squatting the token. Either warrants attention.
		known := r.seenPKs[m.Token]
		if known == nil {
			known = map[string]struct{}{}
			r.seenPKs[m.Token] = known
		}
		// Record at most maxIDsPerToken+1 distinct pubkeys per token. Gating the
		// warning AND the insert together means a 4th+ distinct key is never inserted
		// and therefore never re-counted/re-logged — so this fires once per token, not
		// once per packet (a foreign-key flood at the cap would otherwise log forever).
		if _, seen := known[m.PubKey]; !seen && len(known) < maxIDsPerToken+1 {
			// A first or second pubkey is expected; a third is anomalous — a new device
			// on the same token, a rotated key, or an attacker squatting with a foreign
			// key. Either way it warrants attention.
			if len(known) >= maxIDsPerToken {
				hsStats.newPubKey.Add(1)
				r.warnIntruderLocked(m.Token, "SECURITY: event=new-pubkey token=%s src=%s key=%s id=%s detail=%q",
					logTag(m.Token), src.IP, keyTag(m.PubKey), m.ID,
					"new pubkey on an established token; possible squat, key rotation, or new device")
			}
			known[m.PubKey] = struct{}{}
		}
		self.pubkey = m.PubKey
	}
	if m.VirtualIP != "" {
		self.virtualIP = m.VirtualIP
	}
	if m.Role != "" {
		self.role = m.Role
	}
	// Accept the name only if it passes the DNS-label rules. The server relays it
	// verbatim and trusts the receiving buddy to apply TOFU pinning; we just
	// reject garbage so the wire stays clean.
	if m.Name != "" && protocol.ValidName(m.Name) {
		self.name = m.Name
	}
	self.observe(src)

	for otherID, p := range bucket {
		if otherID == m.ID {
			continue
		}
		if time.Since(p.seen) > r.ttl {
			delete(bucket, otherID)
			continue
		}
		partner = p
		break
	}
	return self, partner, true
}

// evictStalestLocked frees one slot by removing the token bucket whose most
// recent activity is oldest. Caller holds r.mu; returns false only if the table
// is empty (nothing to evict).
func (r *hsRegistry) evictStalestLocked() bool {
	var victim string
	var oldest time.Time
	found := false
	for token, bucket := range r.waiting {
		seen := bucketSeen(bucket)
		if !found || seen.Before(oldest) {
			victim, oldest, found = token, seen, true
		}
	}
	if !found {
		return false
	}
	delete(r.waiting, victim)
	delete(r.seenPKs, victim)
	delete(r.intruderWarned, victim)
	return true
}

// bucketSeen is the freshest sighting across a bucket's peers — how recently the
// token saw any activity, used to pick the stalest bucket to evict.
func bucketSeen(bucket map[string]*hsPeer) time.Time {
	var newest time.Time
	for _, p := range bucket {
		if p.seen.After(newest) {
			newest = p.seen
		}
	}
	return newest
}

func (r *hsRegistry) reap(ctx context.Context) {
	t := time.NewTicker(r.ttl)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		r.mu.Lock()
		for token, bucket := range r.waiting {
			for id, p := range bucket {
				if time.Since(p.seen) > r.ttl {
					delete(bucket, id)
				}
			}
			if len(bucket) == 0 {
				delete(r.waiting, token)
				delete(r.seenPKs, token)        // release pubkey history when the session is gone
				delete(r.intruderWarned, token) // and its one-shot warning latch
			}
		}
		r.mu.Unlock()
	}
}

// Handshake runs the matchmaking server until ctx is cancelled. It learns each
// peer's public endpoints, pairs the two peers sharing a token, and replies to
// each — and only to the sender — with a server-signed PEER_LIST naming the
// partner. No tunnel data ever flows through it.
func Handshake(ctx context.Context, cfg HandshakeConfig) error {
	if cfg.TTL == 0 {
		cfg.TTL = 10 * time.Second
	}
	priv, created, err := bcrypto.LoadOrCreateKey(cfg.KeyPath)
	if err != nil {
		return err
	}
	tokenLogKey = deriveSubkey(priv.Seed(), "buddynet-logtag-v1")
	cookieKey = deriveSubkey(priv.Seed(), "buddynet-cookie-v1")
	pub := bcrypto.PubKeyB64(priv.Public().(ed25519.PublicKey))
	switch {
	case cfg.KeyPath == "":
		log.Printf("WARNING: ephemeral identity %s — pass --key to persist it (buddies pin this)", pub)
	case created:
		log.Printf("WARNING: generated a NEW identity at %s — buddies must pin the new key (print it: buddynet --role=handshake --key %s identity)", cfg.KeyPath, cfg.KeyPath)
	default:
		log.Printf("identity loaded from %s (print the public key: buddynet --role=handshake --key %s identity)", cfg.KeyPath, cfg.KeyPath)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Printf("HANDSHAKE: action=listening addr=%s transport=udp", conn.LocalAddr())
	go func() { <-ctx.Done(); conn.Close() }()

	var authz *authorizer
	if cfg.Authorized != "" {
		authz, err = newAuthorizer(cfg.Authorized, priv)
		if err != nil {
			return err
		}
		log.Printf("approval mode ON: only allowlisted clients may pair (%d approved)", authz.count())
		if authz.count() == 0 {
			// Fail-closed, and say so: --authorized decides the mode, the file's
			// existence decides only WHO is allowed. Zero entries means nobody pairs
			// until a key is approved — never a silent fallback to open mode.
			log.Printf("WARNING: the allowlist %s is empty or missing — NO client can pair yet. "+
				"Approve one with: buddynet --role=handshake --authorized %s approve <CLIENT_KEY> "+
				"(or --authorized %s allowclient <CODE> for code-based enrollment)",
				cfg.Authorized, cfg.Authorized, cfg.Authorized)
		}
		go authz.watch(ctx)
	} else {
		log.Print("approval mode OFF: any client that knows a token may pair. A token-holder can " +
			"thereby harvest the partner's endpoints from the signed PEER_LIST, and (only against a buddy " +
			"run with --lab) MITM it. Restrict with --authorized, and/or use --quic-handshake so the " +
			"token never travels in cleartext; always pin buddies with --peer-key.")
	}

	reg := newHSRegistry(cfg.TTL)
	go reg.reap(ctx)
	go hsStats.logLoop(ctx)
	rl := ratelimit.New(rlGlobalRate, rlSrcRate, rlMaxSources)
	hsDebug = cfg.Debug
	if len(cfg.AllowCIDRs) > 0 {
		log.Printf("source allowlist ON: only %v may register", cfg.AllowCIDRs)
	}

	// Transport choice: QUIC validates the source address in its handshake (and, in
	// approval mode, pins clients to the allowlist at the TLS handshake), plain UDP
	// gets source validation from the address-validation cookie. Both reuse the same
	// pairing core.
	if cfg.QUIC {
		log.Print("handshake control plane: QUIC (source address validated by the QUIC handshake)")
		return serveControlQUIC(ctx, conn, reg, priv, authz, cfg.RelayEndpoint, rl, cfg.AllowCIDRs)
	}
	log.Print("handshake control plane: UDP (source address validated by cookie)")
	log.Print("WARNING: plain UDP is the LEGACY control plane (you opted out of the secure default with " +
		"--quic-handshake=false): the REGISTER (incl. the pairing token) travels in CLEARTEXT — an on-path " +
		"observer can learn it and squat/DoS a pairing (and MITM a buddy that runs --lab). Drop " +
		"--quic-handshake=false on the server AND every buddy to restore encryption; always pin buddies with --peer-key.")

	buf := make([]byte, 1500)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				log.Print("shutting down")
				return nil
			}
			log.Printf("read: %v", err)
			continue
		}
		// Source allowlist (optional): drop a disallowed source before anything,
		// even the rate limiter — a private server need not spend a cycle on it.
		if !cidrAllowed(cfg.AllowCIDRs, src.IP) {
			continue
		}
		// Gate before any parsing or crypto so a flood is dropped cheaply and the
		// expensive per-packet work stays bounded (DoS / reflection defense).
		if !rl.Allow(src.IP.String()) {
			hsStats.rateLimited.Add(1)
			hsDebugf("rate-limited %s", src)
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		// One malformed datagram must drop that packet, never the read loop /
		// process (panic isolation for a 24/7 public server).
		safe.Do("handshake.register", func() {
			handleRegister(conn, reg, priv, authz, cfg.RelayEndpoint, src, raw)
		})
	}
}

// serveControlQUIC runs the handshake control plane over QUIC: each accepted
// stream is one REGISTER, answered with a signed PEER_LIST (empty until paired,
// so a polling buddy makes progress). QUIC's handshake already validated the
// source address, so no cookie is needed; the rate limiter still bounds load.
func serveControlQUIC(ctx context.Context, conn *net.UDPConn, reg *hsRegistry, priv ed25519.PrivateKey, authz *authorizer, relayEndpoint string, rl *ratelimit.Limiter, allowed []netip.Prefix) error {
	// The TLS handshake AUTHENTICATES every client (Ed25519 client certificate,
	// proof of possession) but authorizes none: enrollment needs an unknown key to
	// be able to deliver its sealed code, which a TLS-layer allowlist gate makes
	// impossible. The allowlist decision happens in pairRegister instead.
	if authz != nil {
		log.Print("approval mode: QUIC control authenticates every client by key at the TLS handshake; " +
			"the allowlist decision (allow / enroll with a code / refuse) is made per REGISTER")
	}
	cs, err := tunnel.ListenControl(conn, priv, controlIdleTimeout)
	if err != nil {
		return err
	}
	defer cs.Close()
	go func() { <-ctx.Done(); cs.Close() }()
	for {
		req, err := cs.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				log.Print("shutting down")
				return nil
			}
			return err
		}
		safe.Go("handshake.control", func() {
			handleControlReq(req, reg, priv, authz, relayEndpoint, rl, allowed)
		})
	}
}

// handleControlReq processes one QUIC control request and replies on its stream.
func handleControlReq(req *tunnel.ControlRequest, reg *hsRegistry, priv ed25519.PrivateKey, authz *authorizer, relayEndpoint string, rl *ratelimit.Limiter, allowed []netip.Prefix) {
	src, _ := req.Remote.(*net.UDPAddr)
	if src == nil || !cidrAllowed(allowed, src.IP) {
		req.Reply(nil)
		return
	}
	if !rl.Allow(src.IP.String()) {
		hsStats.rateLimited.Add(1)
		req.Reply(nil)
		return
	}
	m, ok := parseRegister(req.Payload)
	if !ok {
		hsStats.dropped.Add(1)
		req.Reply(nil)
		return
	}
	// Bind the registration to the identity the TLS handshake actually proved. A
	// REGISTER claiming any other public key is not a failed authorization, it is a
	// forgery attempt: drop the connection and store NOTHING — no pending
	// enrollment, no peer, no roster entry.
	if !registrationMatchesTLSKey(m, req.ClientKey) {
		hsStats.keyMismatch.Add(1)
		hsDebugf("closing control conn from %s: REGISTER claims key %s but the TLS handshake authenticated %s",
			src, keyTag(m.PubKey), keyTag(bcrypto.PubKeyB64(req.ClientKey)))
		req.Drop("registration key does not match the authenticated client key")
		return
	}
	// QUIC validated the source address in its own handshake, so an incompatible
	// client can be told so directly.
	if m.Ver != protocol.Version {
		hsStats.dropped.Add(1)
		if b, err := json.Marshal(replyIncompatible()); err == nil {
			req.Reply(b)
		} else {
			req.Reply(nil)
		}
		return
	}
	// Same order as the UDP path: the key-ownership fields are required once the
	// version agreed, and before the sealed token costs an X25519 open.
	if !requireV7Fields(m) {
		hsStats.dropped.Add(1)
		hsDebugf("drop register without a v7 key-ownership proof id=%s from %s", m.ID, src)
		req.Reply(nil)
		return
	}
	if !resolveToken(&m, priv) {
		hsStats.dropped.Add(1)
		req.Reply(nil)
		return
	}
	peers, ok := pairRegister(reg, authz, relayEndpoint, src, m)
	if !ok {
		req.Reply(nil)
		return
	}
	// Reply even when parked (empty peers) so the polling buddy retries.
	if b, err := json.Marshal(signedPeerList(priv, m.Token, peers)); err == nil {
		req.Reply(b)
	}
}

var hsDebug bool

func hsDebugf(format string, args ...any) {
	if hsDebug {
		log.Printf("debug: "+format, args...)
	}
}

// hsCounters are lightweight audit counters for the handshake server: they make
// floods, mass-registration attempts and cookie challenges visible WITHOUT
// logging per-packet (which a flood would weaponize to fill the disk). They are
// summarized once per statsInterval and only when something happened, so a quiet
// server stays silent and an attack shows up as a periodic spike line.
type hsCounters struct {
	paired        atomic.Int64
	challenged    atomic.Int64 // sent an address-validation cookie (unvalidated source)
	rateLimited   atomic.Int64
	dropped       atomic.Int64 // malformed / over-cap / failed proof
	newPubKey     atomic.Int64 // new pubkey on established token (possible squat / new device)
	squatRejected atomic.Int64 // 3rd-party register rejected on full slot (slot already squatted)
	replay        atomic.Int64 // approval-mode registration replayed (key+nonce reused)
	keyMismatch   atomic.Int64 // REGISTER claimed a key other than the TLS-authenticated one
	enrollLimited atomic.Int64 // unknown-key enrollment attempt refused by the enrollment rate limit

	// lastPanic is the process-wide recovered-panic total observed at the previous
	// stats tick, so logLoop can report the per-interval delta. Touched only by the
	// single logLoop goroutine, so it needs no atomic.
	lastPanic int64
}

var hsStats hsCounters

const statsInterval = 60 * time.Second

func (c *hsCounters) logLoop(ctx context.Context) {
	t := time.NewTicker(statsInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pa, ch := c.paired.Swap(0), c.challenged.Swap(0)
		rl, dr := c.rateLimited.Swap(0), c.dropped.Swap(0)
		npk, sq, rp := c.newPubKey.Swap(0), c.squatRejected.Swap(0), c.replay.Swap(0)
		km, el := c.keyMismatch.Swap(0), c.enrollLimited.Swap(0)
		// Per-interval count of panics recovered by safe.Do/Go across the process. A
		// non-zero delta means a crafted input reliably trips a parser (ours or a
		// dependency's) — invisible otherwise, since each panic is only logged once
		// per throttle window. Surfacing it here turns it into a standing signal.
		total := safe.PanicCount()
		pan := total - c.lastPanic
		c.lastPanic = total
		if pa|ch|rl|dr|npk|sq|rp|km|el == 0 && pan == 0 {
			continue // idle interval: stay quiet
		}
		line := fmt.Sprintf("stats (last %s): role=handshake paired=%d challenged=%d rate-limited=%d dropped=%d",
			statsInterval, pa, ch, rl, dr)
		if el > 0 {
			line += fmt.Sprintf(" enroll-limited=%d", el)
		}
		if npk > 0 || sq > 0 || rp > 0 || km > 0 || pan > 0 {
			line += fmt.Sprintf(" ALERT: new-pubkey=%d squat-rejected=%d replay=%d key-mismatch=%d panics=%d", npk, sq, rp, km, pan)
		}
		log.Print(line)
	}
}

// handleRegister handles one UDP datagram. It enforces the address-validation
// cookie (UDP-only — QUIC validates the address in its handshake), then pairs;
// when a partner is found it replies to the sender (only) with a signed
// PEER_LIST. A parked registration draws no reply, exactly as before.
func handleRegister(conn *net.UDPConn, reg *hsRegistry, priv ed25519.PrivateKey, authz *authorizer, relayEndpoint string, src *net.UDPAddr, raw []byte) {
	m, ok := parseRegister(raw)
	if !ok {
		hsStats.dropped.Add(1)
		hsDebugf("drop invalid datagram from %s", src)
		return
	}
	// A REGISTER without a valid cookie gets only a (smaller) challenge and no
	// further work. A spoofed source never receives the cookie, so it can never
	// complete this step — closing reflection before any crypto or PEER_LIST.
	//
	// This check comes FIRST, before the sealed token is opened. Unsealing runs
	// X25519 + NaCl box, orders of magnitude more expensive than an HMAC compare,
	// and it must not be reachable from an unvalidated (and therefore spoofable)
	// source: otherwise a flood of garbage TokenEnc blobs buys an attacker a full
	// asymmetric operation per packet. Everything downstream of here — unsealing,
	// signature verification, the sealed enrollment code — is only reached by a
	// source that has proven return-routability.
	if !validCookie(m.Cookie, src.IP) {
		hsStats.challenged.Add(1)
		sendCookie(conn, src, len(raw))
		hsDebugf("challenged unvalidated register id=%s from %s", m.ID, src)
		return
	}
	// Source validated: an incompatible client now gets a clear answer rather than
	// silence. Nothing else is done with the message.
	if m.Ver != protocol.Version {
		hsStats.dropped.Add(1)
		if b, err := json.Marshal(replyIncompatible()); err == nil {
			conn.WriteToUDP(b, src)
		}
		return
	}
	// Version agreed, so the key-ownership fields must be there. Checked before the
	// sealed token is opened: a registration that cannot carry a valid proof must
	// not buy an asymmetric operation.
	if !requireV7Fields(m) {
		hsStats.dropped.Add(1)
		hsDebugf("drop register without a v7 key-ownership proof id=%s from %s", m.ID, src)
		return
	}
	// Source validated and version agreed: only now is it worth an asymmetric
	// operation to recover the sealed pairing token.
	if !resolveToken(&m, priv) {
		hsStats.dropped.Add(1)
		hsDebugf("drop register with undecryptable sealed token from %s", src)
		return
	}
	peers, ok := pairRegister(reg, authz, relayEndpoint, src, m)
	if !ok || len(peers) == 0 {
		return // dropped, or parked (UDP sends nothing until paired)
	}
	if b, err := json.Marshal(signedPeerList(priv, m.Token, peers)); err == nil {
		conn.WriteToUDP(b, src)
	}
}

// parseRegister unmarshals and structurally validates a REGISTER datagram,
// shared by the UDP and QUIC transports.
func parseRegister(raw []byte) (protocol.Message, bool) {
	var m protocol.Message
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, false
	}
	if m.Type != protocol.TypeRegister || !validField(m.ID) ||
		len(m.PubKey) > protocol.MaxFieldLen || len(m.CodeEnc) > maxCodeEncLen ||
		len(m.Nonce) > protocol.MaxFieldLen {
		return m, false
	}
	// The pairing token arrives sealed (TokenEnc, preferred — keeps it off a
	// cleartext UDP wire) or plaintext (Token, legacy). Require exactly one and
	// bound the sealed blob; resolveToken unseals and re-validates it before use.
	switch {
	case m.TokenEnc != "":
		if m.Token != "" || len(m.TokenEnc) > maxCodeEncLen {
			return m, false
		}
	case !validField(m.Token):
		return m, false
	}
	// NOTE: the protocol version is deliberately NOT checked here. A mismatched
	// client is answered with an explicit incompatibility reply (see
	// replyIncompatible) instead of being dropped in silence, so the operator sees
	// "update buddynet" rather than an unexplained failure to pair. Callers check
	// it only once the source address is validated.
	//
	// For the same reason the v7 key-ownership fields (PubKey/Nonce/RegSig) are
	// only LENGTH-bounded here, never required: a v6 message carries no nonce at
	// all, and rejecting it structurally would replace that diagnostic with a
	// silent timeout. requireV7Fields enforces them AFTER the version check.
	return m, true
}

// requireV7Fields rejects a registration that does not carry the three fields a
// v7 key-ownership proof is made of. It is the cheap structural gate that makes
// the proof MANDATORY: under v7 every buddy signs (buildRegister always sets all
// three, and nothing but a buddy ever registers), so anything missing them is
// either a forgery attempt or a client that must be told to update.
//
// Placement matters twice over. It runs AFTER the version check, so a v6 client
// still gets "update buddynet" instead of silence; and BEFORE resolveToken, so a
// message that can never produce a valid proof does not first earn a sealed-token
// X25519 open. Cheap checks gate expensive ones, as everywhere else on this path.
func requireV7Fields(m protocol.Message) bool {
	if !protocol.ValidNonce(m.Nonce) {
		return false
	}
	pub, err := base64.StdEncoding.DecodeString(m.PubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(m.RegSig)
	return err == nil && len(sig) == ed25519.SignatureSize
}

// replyIncompatible answers a client speaking a different protocol version with a
// version-stamped, EMPTY PEER_LIST. Both buddy transports compare Ver before they
// look at the roster or its signature, so this surfaces as
// "server speaks vN, we speak vM — update buddynet" instead of a silent timeout.
//
// v7 is a breaking change (the registration signature covers new fields), and an
// older client is NOT served under the old rules — this reply is a diagnostic, not
// a compatibility path. It is emitted only after the source address has been
// validated (cookie on UDP, the handshake itself on QUIC), and it is smaller than
// the REGISTER that triggered it, so it is never a reflector or an amplifier.
func replyIncompatible() protocol.Message {
	return protocol.Message{Type: protocol.TypePeerList, Ver: protocol.Version}
}

// resolveToken unseals a sealed pairing token (TokenEnc) into m.Token using the
// server's identity key, so all downstream logic (cookie, signature, bucket key)
// works on the cleartext value exactly as before. A plaintext Token (legacy
// buddy) passes through untouched. Returns false if the sealed token does not
// decrypt or is malformed.
func resolveToken(m *protocol.Message, priv ed25519.PrivateKey) bool {
	if m.TokenEnc == "" {
		return true // plaintext Token already validated in parseRegister
	}
	tok, err := bcrypto.OpenCode(m.TokenEnc, priv)
	if err != nil || !validField(tok) {
		return false
	}
	m.Token = tok
	m.TokenEnc = ""
	return true
}

// pairRegister runs the transport-independent core: approval-mode checks, then
// pairing. It returns the partner roster to sign, or empty when parked, and
// ok=false to drop (over-cap, or not allowed). The caller signs and sends.
func pairRegister(reg *hsRegistry, authz *authorizer, relayEndpoint string, src *net.UDPAddr, m protocol.Message) (peers []protocol.Peer, ok bool) {
	// KEY-OWNERSHIP PROOF FIRST, IN EVERY MODE. Under v7 there is no such thing as
	// an unsigned client: buildRegister always signs, and nothing but a buddy ever
	// registers. Verifying only "when a signature happens to be present" made the
	// check optional for whoever left the field out — a registration could then
	// claim SOMEONE ELSE'S public key (identity squat in the signed roster), or no
	// key at all, in which case deriveVIP waved a made-up virtual IP through and
	// the token's slots filled with something that cost no cryptography at all.
	// requireV7Fields has already established that the three fields are structurally
	// there; this is the actual proof.
	if !verifyRegistration(m, regSkew) {
		hsDebugf("drop register with an invalid key-ownership proof token=%s from %s", logTag(m.Token), src)
		return nil, false
	}
	if authz != nil {
		// AUTHORIZATION BEFORE THE REPLAY CACHE. The cache is bounded and evicts its
		// oldest entry when full (it must never fail open), so whoever can put
		// entries in it can push others out. Checking the allowlist first means only
		// APPROVED keys ever occupy a slot: an outsider — who can mint unlimited
		// self-signed, perfectly valid registrations — can no longer flush the cache
		// and thereby re-open the replay window on a real buddy. It also puts the
		// tight enrollment limiter ahead of that work rather than behind it.
		if !authz.allowed(m.PubKey) {
			// Unknown key. It authenticated (its signature verified, and on QUIC its
			// TLS certificate matched), which is exactly what lets an enrolling client
			// deliver its sealed code — but it is NOT authorized, so it never pairs
			// here. With a valid code it becomes a pending enrollment awaiting the
			// operator; without one it is only noted.
			//
			// Both branches cost real work (an X25519 open, a map insert, a file
			// rewrite, a log line), so gate them behind the tight enrollment limiter
			// first: a stranger flood must not be able to spend an approved buddy's
			// budget, fill the disk with pending entries, or fill the log.
			if !authz.allowEnroll(src.IP.String()) {
				hsStats.enrollLimited.Add(1)
				return nil, false
			}
			// Remember the nonce in the SEPARATE pre-auth cache. If the operator
			// approves this key in a moment, whatever was sent beforehand must not
			// suddenly become replayable — and no timestamp comparison can decide that,
			// because the timestamp is the sender's to choose and may legitimately sit
			// up to regSkew in the future, i.e. after the approval. Only a record of
			// the nonce itself is sound. The separate cache is what keeps this from
			// handing outsiders an eviction lever over approved buddies.
			authz.recordPreAuth(m.PubKey, m.Nonce)
			if m.CodeEnc != "" {
				authz.recordPending(m.CodeEnc, m.PubKey)
			} else {
				authz.logPending(m.PubKey, logTag(m.Token))
			}
			return nil, false
		}
		// Second line of defence at the approval transition, behind the pre-auth
		// nonce cache: refuse registrations whose timestamp predates the approval.
		// On its own this would NOT be sound — the timestamp is the sender's to
		// choose and may sit up to regSkew in the future — so it only catches what
		// the nonce cache may have aged out or evicted. The nonce cache is the lock;
		// this is the bolt.
		if !authz.freshSinceApproval(m.PubKey, m.Ts) {
			hsStats.replay.Add(1)
			log.Printf("SECURITY: event=replay-detected token=%s src=%s key=%s id=%s detail=%q",
				logTag(m.Token), src.IP, keyTag(m.PubKey), m.ID, "registration predates the key's approval")
			return nil, false
		}
		if authz.replayed(m.PubKey, m.Nonce) {
			// An APPROVED key reused a nonce inside the freshness window. A polling
			// buddy draws a fresh one every attempt, so this is a genuine replay of a
			// captured registration, not ordinary re-registration.
			hsStats.replay.Add(1)
			log.Printf("SECURITY: event=replay-detected token=%s src=%s key=%s id=%s detail=%q",
				logTag(m.Token), src.IP, keyTag(m.PubKey), m.ID, "registration nonce reused by the same key")
			return nil, false
		}
	}
	// In OPEN mode the proof above is all there is: it stops a party who learned
	// the token from registering under someone else's public key, but it cannot
	// stop that same party from registering under its own fresh key — only token
	// confidentiality does, which is the documented residual of a bearer-token
	// rendezvous (the impersonation is still caught downstream by --peer-key /
	// TOFU+SAS).
	// Identity is address: derive the virtual IP from the key rather than trusting
	// the claim. Runs AFTER signature verification, so the value the client signed
	// is the value that was checked.
	if !deriveVIP(&m, src) {
		return nil, false
	}
	self, partner, ok := reg.upsert(m, src)
	if !ok {
		hsStats.dropped.Add(1)
		hsDebugf("reject over-cap register token=%s id=%s from %s", logTag(m.Token), m.ID, src)
		return nil, false
	}
	if partner == nil {
		hsDebugf("parked token=%s id=%s from %s, awaiting partner", logTag(m.Token), self.id, src)
		return nil, true // ok, but no partner yet
	}
	hsStats.paired.Add(1)
	log.Printf("PAIRED: token=%s a=%s/%s b=%s/%s cands=%d/%d",
		logTag(m.Token), self.id, keyTag(self.pubkey), partner.id, keyTag(partner.pubkey),
		len(self.cands), len(partner.cands))
	return []protocol.Peer{partner.asProtocolPeer(relayEndpoint)}, true
}

// signedPeerList builds a server-signed PEER_LIST over (token, ts, peers). An
// empty peers slice yields a signed "not paired yet" reply, which the QUIC
// transport sends so a polling client retries (the UDP transport stays silent).
func signedPeerList(priv ed25519.PrivateKey, token string, peers []protocol.Peer) protocol.Message {
	ts := time.Now().Unix()
	sig := ed25519.Sign(priv, protocol.PeerListPayload(token, ts, peers))
	return protocol.Message{
		Type:  protocol.TypePeerList,
		Ver:   protocol.Version,
		Peers: peers,
		Ts:    ts,
		Sig:   base64.StdEncoding.EncodeToString(sig),
	}
}

// validField rejects empty and oversized strings before they become map keys.
func validField(s string) bool { return s != "" && len(s) <= protocol.MaxFieldLen }

// verifyRegistration checks a client's key-ownership proof. m must already carry
// the PLAINTEXT token (resolveToken ran), because that is what the client signed.
//
// The nonce is validated here rather than in parseRegister because it is only
// meaningful together with the signature: it is covered by RegistrationPayload,
// so a malformed or attacker-chosen nonce cannot be swapped in, and its strict
// fixed length keeps the replay-cache key bounded.
func verifyRegistration(m protocol.Message, skew time.Duration) bool {
	if !protocol.ValidNonce(m.Nonce) {
		return false
	}
	// The nonce is only replay-relevant while the registration is fresh, so the
	// same ±skew window bounds both.
	if d := time.Since(time.Unix(m.Ts, 0)); d > skew || d < -skew {
		return false
	}
	pub, err := base64.StdEncoding.DecodeString(m.PubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(m.RegSig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), protocol.RegistrationPayload(m), sig)
}

// registrationMatchesTLSKey reports whether a REGISTER claims exactly the
// identity its QUIC/TLS connection authenticated with. Compared on the raw key
// bytes, so an alternative base64 spelling of the same key cannot slip past.
//
// This is what makes app-layer enrollment safe: an unknown client is allowed to
// complete the TLS handshake so it can deliver its sealed enrollment code, but it
// can only ever enroll the key it proved possession of — it cannot bind a code
// (its own or a captured one) to somebody else's public key.
func registrationMatchesTLSKey(m protocol.Message, clientKey ed25519.PublicKey) bool {
	if len(clientKey) != ed25519.PublicKeySize {
		return false
	}
	claimed, err := base64.StdEncoding.DecodeString(m.PubKey)
	if err != nil || len(claimed) != ed25519.PublicKeySize {
		return false
	}
	return clientKey.Equal(ed25519.PublicKey(claimed))
}

// deriveVIP enforces the project's core invariant server-side: the virtual IP is
// a pure function of the public key, so the server never takes the client's word
// for it. A registration claiming an inconsistent VIP is rejected (it is signed,
// so this is a deliberately crafted client, not a wire error); one that omits it
// gets the derived value filled in, so the roster the server signs always carries
// the address the key actually derives.
func deriveVIP(m *protocol.Message, src *net.UDPAddr) bool {
	if m.PubKey == "" {
		// Unreachable on the live paths since requireV7Fields — a keyless registration
		// is refused long before this. Kept as a defensive no-op for direct callers
		// (tests); it must never be the door it once was, when a keyless message
		// skipped the derivation below and had its CLAIMED virtual IP signed into the
		// roster.
		return true
	}
	pub, err := bcrypto.DecodePubKey(m.PubKey)
	if err != nil {
		return false
	}
	want := bcrypto.VirtualIPString(pub)
	if m.VirtualIP != "" && m.VirtualIP != want {
		hsStats.dropped.Add(1)
		hsDebugf("drop register token=%s from %s: claims vip %s but its key derives %s",
			logTag(m.Token), src, m.VirtualIP, want)
		return false
	}
	m.VirtualIP = want
	return true
}

// shortHash returns a non-reversible 8-hex tag for a secret token, used as the
// stable, server-independent id in the allowlist/pending DB.
func shortHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:4])
}

// tokenLogKey keys the HMAC used by logTag; derived from the server identity
// seed so only this server can reproduce a tag (no offline guessing oracle).
var tokenLogKey []byte

// cookieEpoch is the validity granularity of an address-validation cookie. A
// cookie is accepted for the current and the previous epoch, so it lives
// 30..60s — long enough to survive a registration's first round-trip, short
// enough to bound replay of a captured cookie to its source address.
const cookieEpoch = 30 * time.Second

// cookieKey keys the address-validation HMAC; HKDF-derived from the identity so
// only this server can mint/verify cookies and they need no per-source state.
var cookieKey []byte

// computeCookie is HMAC(cookieKey, epoch || canonical-ip), truncated. Binding to
// the source IP is what makes it prove return-routability: only a host that
// actually received the challenge at that address can echo a matching value.
func computeCookie(ip net.IP, epoch int64) string {
	mac := hmac.New(sha256.New, cookieKey)
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], uint64(epoch))
	mac.Write(e[:])
	mac.Write(ip.To16())
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}

// freshCookie mints a cookie for the current epoch and source IP.
func freshCookie(ip net.IP) string {
	return computeCookie(ip, time.Now().UnixNano()/int64(cookieEpoch))
}

// validCookie accepts a cookie matching the current or previous epoch for ip,
// compared in constant time.
func validCookie(c string, ip net.IP) bool {
	if c == "" {
		return false
	}
	now := time.Now().UnixNano() / int64(cookieEpoch)
	return hmac.Equal([]byte(c), []byte(computeCookie(ip, now))) ||
		hmac.Equal([]byte(c), []byte(computeCookie(ip, now-1)))
}

// sendCookie replies with an address-validation challenge, but only when the
// reply is STRICTLY SMALLER than the datagram that triggered it (reqLen is the
// raw datagram, not the parsed message — otherwise the property would hang off
// the field layout again).
//
// Without that gate the challenge is a small amplifier: the parser accepts a
// 40-byte REGISTER (`{"type":"REGISTER","token":"x","id":"x"}`) and answers it
// with 59 bytes — 1.48x, or 1.28x once IP/UDP headers are counted. Tiny, and the
// per-source rate limit bounds it further, but "never an amplifier" was written
// as an absolute and has to hold as one. Comparing the two lengths makes it true
// by construction rather than by the current encoding happening to be favourable.
//
// A real buddy sends ~410 bytes, so the gate has ~350 bytes of headroom and never
// fires on legitimate traffic.
func sendCookie(conn *net.UDPConn, src *net.UDPAddr, reqLen int) {
	reply := protocol.Message{Type: protocol.TypeCookie, Ver: protocol.Version, Cookie: freshCookie(src.IP)}
	b, err := json.Marshal(reply)
	if err != nil || len(b) >= reqLen {
		return
	}
	conn.WriteToUDP(b, src)
}

// deriveSubkey derives a purpose-specific 32-byte key from the identity seed via
// HKDF: key separation, so the same secret never serves two primitives. HKDF
// cannot fail for these fixed sizes.
func deriveSubkey(seed []byte, label string) []byte {
	out := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, seed, nil, []byte(label)), out); err != nil {
		panic(err) // only on a broken hash, which cannot happen for sha256
	}
	return out
}

// logTag returns a server-keyed 10-hex tag for a secret token, safe to log.
func logTag(token string) string {
	mac := hmac.New(sha256.New, tokenLogKey)
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil)[:5])
}
