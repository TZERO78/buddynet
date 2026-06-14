package role

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/pkg/protocol"
)

// HandshakeConfig configures the bootstrap/matchmaking server (--role=handshake).
type HandshakeConfig struct {
	Listen     string        // UDP address, e.g. "[::]:51820"
	KeyPath    string        // Ed25519 identity seed; empty = ephemeral
	Authorized string        // optional client allowlist (approval mode)
	TTL        time.Duration // liveness window for a registration
	Debug      bool          // verbose, security-sensitive logging
	// RelayEndpoint, if set, is advertised to every paired buddy as a relay of
	// last resort — use it when this VPS also runs --role=relay (commonly on a
	// second port). Buddies fall back to it only after a direct punch fails.
	RelayEndpoint string
}

// Hard caps bound server memory regardless of spoofed source addresses.
const (
	maxTokens       = 4096
	maxIDsPerToken  = 2
	maxCandsPerPeer = 8
	maxCodeEncLen   = 512
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

func (r *hsRegistry) reap() {
	for range time.Tick(r.ttl) {
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
	tokenLogKey = priv.Seed()
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
		go authz.watch()
	} else {
		log.Print("approval mode OFF: any client with a valid token may pair (set --authorized to restrict)")
	}

	reg := newHSRegistry(cfg.TTL)
	go reg.reap()

	hsDebug = cfg.Debug
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
		raw := make([]byte, n)
		copy(raw, buf[:n])
		handleRegister(conn, reg, priv, authz, cfg.RelayEndpoint, src, raw)
	}
}

var hsDebug bool

func hsDebugf(format string, args ...any) {
	if hsDebug {
		log.Printf("debug: "+format, args...)
	}
}

// handleRegister parses one datagram. If it completes a pair, it replies to the
// sender (only) with a signed PEER_LIST naming the partner.
func handleRegister(conn *net.UDPConn, reg *hsRegistry, priv ed25519.PrivateKey, authz *authorizer, relayEndpoint string, src *net.UDPAddr, raw []byte) {
	var m protocol.Message
	if err := json.Unmarshal(raw, &m); err != nil {
		return
	}
	if m.Type != protocol.TypeRegister || !validField(m.Token) || !validField(m.ID) ||
		len(m.PubKey) > protocol.MaxFieldLen || len(m.CodeEnc) > maxCodeEncLen {
		hsDebugf("drop invalid datagram from %s", src)
		return
	}
	if m.Ver != protocol.Version {
		hsDebugf("drop register with protocol v%d (we speak v%d) from %s", m.Ver, protocol.Version, src)
		return
	}

	if authz != nil {
		if !verifyRegistration(m, 60*time.Second) {
			hsDebugf("drop unsigned/stale register token=%s from %s", logTag(m.Token), src)
			return
		}
		if !authz.allowed(m.PubKey) {
			if m.CodeEnc != "" {
				authz.recordPending(m.CodeEnc, m.PubKey)
			} else {
				authz.logPending(m.PubKey, shortHash(m.Token))
			}
			return
		}
	}

	self, partner, ok := reg.upsert(m, src)
	if !ok {
		hsDebugf("reject over-cap register token=%s id=%s from %s", logTag(m.Token), m.ID, src)
		return
	}
	if partner == nil {
		hsDebugf("parked token=%s id=%s from %s, awaiting partner", logTag(m.Token), self.id, src)
		return
	}

	log.Printf("paired token=%s: %s(%d cand) <-> %s(%d cand)",
		logTag(m.Token), self.id, len(self.cands), partner.id, len(partner.cands))

	peers := []protocol.Peer{partner.asProtocolPeer(relayEndpoint)}
	ts := time.Now().Unix()
	sig := ed25519.Sign(priv, protocol.PeerListPayload(m.Token, ts, peers))
	reply := protocol.Message{
		Type:  protocol.TypePeerList,
		Ver:   protocol.Version,
		Peers: peers,
		Ts:    ts,
		Sig:   base64.StdEncoding.EncodeToString(sig),
	}
	if b, err := json.Marshal(reply); err == nil {
		conn.WriteToUDP(b, src)
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

// logTag returns a server-keyed 10-hex tag for a secret token, safe to log.
func logTag(token string) string {
	mac := hmac.New(sha256.New, tokenLogKey)
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil)[:5])
}
