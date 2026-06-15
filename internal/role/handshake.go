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
	"io"
	"log"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/ratelimit"
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
		Candidates: p.candidates(),
		Relay:      relay,
		LastSeen:   p.seen.Unix(),
	}
}

// hsRegistry pairs peers by token, in memory only, bounded by the caps above.
type hsRegistry struct {
	mu      sync.Mutex
	waiting map[string]map[string]*hsPeer
	ttl     time.Duration
}

func newHSRegistry(ttl time.Duration) *hsRegistry {
	return &hsRegistry{waiting: map[string]map[string]*hsPeer{}, ttl: ttl}
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
			return nil, nil, false // third party tried to join this token
		}
		self = &hsPeer{id: m.ID, cands: map[string]protocol.Candidate{}}
		bucket[m.ID] = self
	}
	if m.PubKey != "" {
		self.pubkey = m.PubKey
	}
	if m.VirtualIP != "" {
		self.virtualIP = m.VirtualIP
	}
	if m.Role != "" {
		self.role = m.Role
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
	log.Printf("buddynet handshake listening on %s (udp, dual-stack)", conn.LocalAddr())
	go func() { <-ctx.Done(); conn.Close() }()

	var authz *authorizer
	if cfg.Authorized != "" {
		authz, err = newAuthorizer(cfg.Authorized, priv)
		if err != nil {
			return err
		}
		log.Printf("approval mode ON: only allowlisted clients may pair (%d approved)", authz.count())
		go authz.watch(ctx)
	} else {
		log.Print("approval mode OFF: any client with a valid token may pair (set --authorized to restrict)")
	}

	reg := newHSRegistry(cfg.TTL)
	go reg.reap(ctx)
	rl := ratelimit.New(rlGlobalRate, rlSrcRate, rlMaxSources)
	hsDebug = cfg.Debug
	if len(cfg.AllowCIDRs) > 0 {
		log.Printf("source allowlist ON: only %v may register", cfg.AllowCIDRs)
	}

	// Transport choice: QUIC validates the source address in its handshake
	// (structural anti-reflection), plain UDP gets the same property from the
	// address-validation cookie. Both reuse the same pairing core.
	if cfg.QUIC {
		log.Print("handshake control plane: QUIC (source address validated by the QUIC handshake)")
		return serveControlQUIC(ctx, conn, reg, priv, authz, cfg.RelayEndpoint, rl, cfg.AllowCIDRs)
	}
	log.Print("handshake control plane: UDP (source address validated by cookie)")

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
			hsDebugf("rate-limited %s", src)
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		handleRegister(conn, reg, priv, authz, cfg.RelayEndpoint, src, raw)
	}
}

// serveControlQUIC runs the handshake control plane over QUIC: each accepted
// stream is one REGISTER, answered with a signed PEER_LIST (empty until paired,
// so a polling buddy makes progress). QUIC's handshake already validated the
// source address, so no cookie is needed; the rate limiter still bounds load.
func serveControlQUIC(ctx context.Context, conn *net.UDPConn, reg *hsRegistry, priv ed25519.PrivateKey, authz *authorizer, relayEndpoint string, rl *ratelimit.Limiter, allowed []netip.Prefix) error {
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
		go handleControlReq(req, reg, priv, authz, relayEndpoint, rl, allowed)
	}
}

// handleControlReq processes one QUIC control request and replies on its stream.
func handleControlReq(req *tunnel.ControlRequest, reg *hsRegistry, priv ed25519.PrivateKey, authz *authorizer, relayEndpoint string, rl *ratelimit.Limiter, allowed []netip.Prefix) {
	src, _ := req.Remote.(*net.UDPAddr)
	if src == nil || !cidrAllowed(allowed, src.IP) || !rl.Allow(src.IP.String()) {
		req.Reply(nil)
		return
	}
	m, ok := parseRegister(req.Payload)
	if !ok {
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

// handleRegister handles one UDP datagram. It enforces the address-validation
// cookie (UDP-only — QUIC validates the address in its handshake), then pairs;
// when a partner is found it replies to the sender (only) with a signed
// PEER_LIST. A parked registration draws no reply, exactly as before.
func handleRegister(conn *net.UDPConn, reg *hsRegistry, priv ed25519.PrivateKey, authz *authorizer, relayEndpoint string, src *net.UDPAddr, raw []byte) {
	m, ok := parseRegister(raw)
	if !ok {
		hsDebugf("drop invalid datagram from %s", src)
		return
	}
	// A REGISTER without a valid cookie gets only a (smaller) challenge and no
	// further work. A spoofed source never receives the cookie, so it can never
	// complete this step — closing reflection before any crypto or PEER_LIST.
	if !validCookie(m.Cookie, src.IP) {
		sendCookie(conn, src)
		hsDebugf("challenged unvalidated register token=%s from %s", logTag(m.Token), src)
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
	if m.Type != protocol.TypeRegister || !validField(m.Token) || !validField(m.ID) ||
		len(m.PubKey) > protocol.MaxFieldLen || len(m.CodeEnc) > maxCodeEncLen {
		return m, false
	}
	if m.Ver != protocol.Version {
		return m, false
	}
	return m, true
}

// pairRegister runs the transport-independent core: approval-mode checks, then
// pairing. It returns the partner roster to sign, or empty when parked, and
// ok=false to drop (over-cap, or not allowed). The caller signs and sends.
func pairRegister(reg *hsRegistry, authz *authorizer, relayEndpoint string, src *net.UDPAddr, m protocol.Message) (peers []protocol.Peer, ok bool) {
	if authz != nil {
		if !verifyRegistration(m, regSkew) {
			hsDebugf("drop unsigned/stale register token=%s from %s", logTag(m.Token), src)
			return nil, false
		}
		if authz.replayed(m.RegSig) {
			hsDebugf("drop replayed register token=%s from %s", logTag(m.Token), src)
			return nil, false
		}
		if !authz.allowed(m.PubKey) {
			if m.CodeEnc != "" {
				authz.recordPending(m.CodeEnc, m.PubKey)
			} else {
				authz.logPending(m.PubKey, shortHash(m.Token))
			}
			return nil, false
		}
	}
	self, partner, ok := reg.upsert(m, src)
	if !ok {
		hsDebugf("reject over-cap register token=%s id=%s from %s", logTag(m.Token), m.ID, src)
		return nil, false
	}
	if partner == nil {
		hsDebugf("parked token=%s id=%s from %s, awaiting partner", logTag(m.Token), self.id, src)
		return nil, true // ok, but no partner yet
	}
	log.Printf("paired token=%s: %s(%d cand) <-> %s(%d cand)",
		logTag(m.Token), self.id, len(self.cands), partner.id, len(partner.cands))
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

// verifyRegistration checks a client's key-ownership proof (approval mode).
func verifyRegistration(m protocol.Message, skew time.Duration) bool {
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
	return ed25519.Verify(ed25519.PublicKey(pub), protocol.RegistrationPayload(m.Token, m.ID, m.PubKey, m.Ts), sig)
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

// sendCookie replies with an address-validation challenge. The reply is smaller
// than the REGISTER that triggered it, so it is never a useful amplifier.
func sendCookie(conn *net.UDPConn, src *net.UDPAddr) {
	reply := protocol.Message{Type: protocol.TypeCookie, Ver: protocol.Version, Cookie: freshCookie(src.IP)}
	if b, err := json.Marshal(reply); err == nil {
		conn.WriteToUDP(b, src)
	}
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
