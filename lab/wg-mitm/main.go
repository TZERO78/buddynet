// Command wg-mitm is an AUTHORIZED pentest attacker for a LOCAL BuddyNet lab. It
// proves WG-1: on the WireGuard data plane there is no TLS exporter, so the
// first-contact SAS is bound to an ephemeral-DH + hash-commitment exchange
// (internal/role/binding.go, the RFC 6189 / ZRTP construction). This tool shows
// that a man in the middle is caught because the two ends derive DIFFERENT SAS
// strings.
//
// It impersonates a blind relay (the address a handshake server advertises via
// --relay-endpoint): it answers the relay bind/cookie handshake so both buddies
// bind a leg, but instead of splicing the BNBIND1 binding frames between the legs
// it TERMINATES the binding separately with each side using its own ephemeral
// material. Each buddy therefore binds against the attacker, not its real partner,
// so buddy A and buddy B compute and display different SAS codes — which a human
// comparing them out of band detects, and the connection is refused.
//
// The attacker never learns any plaintext: WireGuard is end-to-end on the two
// identities' X25519 keys and the attacker holds neither. The only thing it
// breaks is SAS agreement — which is precisely the property WG-1 asserts.
//
// Usage (inside the lab netns): wg-mitm -listen 0.0.0.0:51821
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"log"
	"net"
	"sync"

	"github.com/tzero78/buddynet/internal/relay"
)

// bindFramePrefix mirrors internal/role.bindFramePrefix — the tag on the SAS
// binding datagrams (distinct from the relay's own BNRELAY1 control framing).
const bindFramePrefix = "BNBIND1"

func isBindFrame(p []byte) bool {
	return len(p) >= len(bindFramePrefix) && string(p[:len(bindFramePrefix)]) == bindFramePrefix
}

func frame(b []byte) []byte { return append([]byte(bindFramePrefix), b...) }

type leg struct {
	addr  *net.UDPAddr
	token string
}

// session holds the per-token binding-interposition state.
type session struct {
	committer   string // src key of the committer leg (first to send a BNBIND1 frame)
	reveal      []byte // 32-byte value M revealed to the non-committer (commit = SHA-256(M))
	drivenC     bool   // we have answered the committer leg
	revealedToN bool   // we have sent the reveal to the non-committer leg
}

func main() {
	listen := flag.String("listen", "0.0.0.0:51821", "attacker relay listen address")
	flag.Parse()

	la, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatalf("wg-mitm: resolve %s: %v", *listen, err)
	}
	c, err := net.ListenUDP("udp", la)
	if err != nil {
		log.Fatalf("wg-mitm: listen %s: %v", *listen, err)
	}
	defer c.Close()
	log.Printf("wg-mitm: malicious relay listening on %s — will TERMINATE the SAS binding per leg", *listen)

	var mu sync.Mutex
	cookies := map[string][]byte{}   // src -> issued cookie (trivial; we are the attacker)
	legs := map[string]*leg{}        // src -> leg
	byToken := map[string][]string{} // token -> []src
	sess := map[string]*session{}    // token -> binding state

	partnerOf := func(src string) *leg {
		l := legs[src]
		if l == nil {
			return nil
		}
		for _, s := range byToken[l.token] {
			if s != src {
				return legs[s]
			}
		}
		return nil
	}

	buf := make([]byte, 2048)
	for {
		n, src, err := c.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		key := src.String()

		// 1) Relay bind handshake (cookie dance). We accept everything — return
		//    routability is irrelevant to the attacker; we only need both legs bound.
		if b, ok := relay.ParseBind(pkt); ok {
			mu.Lock()
			if b.Cookie == "" {
				ck := cookies[key]
				if ck == nil {
					ck = make([]byte, relay.CookieLen)
					rand.Read(ck)
					cookies[key] = ck
				}
				c.WriteToUDP(relay.MarshalChallenge(ck), src)
				mu.Unlock()
				continue
			}
			if legs[key] == nil {
				legs[key] = &leg{addr: src, token: b.SessionToken}
				byToken[b.SessionToken] = append(byToken[b.SessionToken], key)
				log.Printf("wg-mitm: leg bound src=%s token=%s (%d legs)", key, b.SessionToken, len(byToken[b.SessionToken]))
			}
			c.WriteToUDP(relay.MarshalBind(relay.Bind{SessionToken: b.SessionToken}), src)
			mu.Unlock()
			continue
		}

		// 2) SAS binding frames (BNBIND1): TERMINATE per leg instead of splicing.
		if isBindFrame(pkt) {
			mu.Lock()
			l := legs[key]
			if l == nil {
				mu.Unlock()
				continue
			}
			tok := l.token
			s := sess[tok]
			if s == nil {
				// First BNBIND1 frame on this token comes from the COMMITTER (the
				// non-committer stays silent until it receives a commit). Pick a
				// reveal value M and drive both legs.
				m := make([]byte, 32)
				rand.Read(m)
				s = &session{committer: key, reveal: m}
				sess[tok] = s
				log.Printf("wg-mitm: token=%s committer=%s — terminating binding on BOTH legs (SAS will diverge)", tok, key)

				// Drive the NON-committer (the other leg) as the committer would:
				// send commit = SHA-256(M), then the reveal M.
				if other := partnerOf(key); other != nil {
					commit := sha256.Sum256(m)
					c.WriteToUDP(frame(commit[:]), other.addr)
					c.WriteToUDP(frame(m), other.addr)
					s.revealedToN = true
				}
			}

			if key == s.committer {
				// We are the non-committer toward the committer leg: answer with a
				// 32-byte "peer ephemeral". The committer does not check a commitment,
				// so any 32 bytes complete its exchange against OUR key, not its peer's.
				if !s.drivenC {
					peer := make([]byte, 32)
					rand.Read(peer)
					c.WriteToUDP(frame(peer), src)
					s.drivenC = true
				}
			} else if !s.revealedToN {
				// Non-committer leg spoke before we drove it (race): drive it now.
				commit := sha256.Sum256(s.reveal)
				c.WriteToUDP(frame(commit[:]), src)
				c.WriteToUDP(frame(s.reveal), src)
				s.revealedToN = true
			}
			mu.Unlock()
			continue
		}

		// 3) Anything else (WireGuard data): blindly splice — we cannot read it.
		mu.Lock()
		p := partnerOf(key)
		mu.Unlock()
		if p != nil {
			c.WriteToUDP(pkt, p.addr)
		}
	}
}
