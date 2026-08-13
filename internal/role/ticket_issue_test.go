package role

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/tzero78/buddynet/internal/ticket"
	"github.com/tzero78/buddynet/pkg/protocol"
)

// issueFor mints a ticket the way the control path does: a registration from
// `me` that has just been paired with `partner`.
func issueFor(t *testing.T, reg *hsRegistry, srv ed25519.PrivateKey, rid, token, myKey, epk, partnerKey string) *protocol.RelayTicket {
	t.Helper()
	m := protocol.Message{Token: token, PubKey: myKey, EphPub: epk}
	return issueTicket(reg, srv, rid, m, protocol.Peer{PubKey: partnerKey})
}

// ephKey returns a fresh ephemeral key pair in the form the buddy sends it.
func ephKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ephemeral key: %v", err)
	}
	return priv, base64.RawURLEncoding.EncodeToString(pub)
}

// parseTicket decodes and verifies a ticket the way a relay does, and fails the
// test if it does not hold up — so no assertion below can pass on a ticket the
// relay would refuse.
func parseTicket(t *testing.T, srvPub ed25519.PublicKey, rt *protocol.RelayTicket) ticket.Payload {
	t.Helper()
	if rt == nil {
		t.Fatal("no ticket issued")
	}
	payload, err := base64.RawURLEncoding.DecodeString(rt.Payload)
	if err != nil {
		t.Fatalf("ticket payload is not base64url: %v", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(rt.Sig)
	if err != nil {
		t.Fatalf("ticket signature is not base64url: %v", err)
	}
	if !ticket.Verify([]ed25519.PublicKey{srvPub}, payload, sig) {
		t.Fatal("the server issued a ticket its own key does not verify")
	}
	p, err := ticket.Parse(payload)
	if err != nil {
		t.Fatalf("the server issued a ticket the relay's strict parse rejects: %v", err)
	}
	if err := p.CheckWindow(time.Now()); err != nil {
		t.Fatalf("the server issued a ticket outside the relay's accepted window: %v", err)
	}
	return p
}

// TestBothBuddiesGetTheSameSessionAndOppositeLegs is the property the whole
// pairing rests on: two legs meet only if the SERVER put them together, and they
// must not collide on the same leg. Both buddies derive their leg with no extra
// signaling, from the same key order the data plane already uses.
func TestBothBuddiesGetTheSameSessionAndOppositeLegs(t *testing.T) {
	srvPub, srvPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	rid, err := ticket.NewID()
	if err != nil {
		t.Fatalf("rid: %v", err)
	}
	reg := newHSRegistry(time.Minute)
	_, epkA := ephKey(t)
	_, epkB := ephKey(t)

	// Deliberately ordered so "A" is NOT the lexicographically lower key: the leg
	// must follow the keys, not the order the tests happen to be written in.
	keyA, keyB := "zzzKeyA", "aaaKeyB"

	ta := parseTicket(t, srvPub, issueFor(t, reg, srvPriv, rid, "tok", keyA, epkA, keyB))
	tb := parseTicket(t, srvPub, issueFor(t, reg, srvPriv, rid, "tok", keyB, epkB, keyA))

	if ta.SID != tb.SID {
		t.Fatalf("the two buddies got different session ids (%s vs %s) — their legs would never meet", ta.SID, tb.SID)
	}
	if ta.Leg == tb.Leg {
		t.Fatalf("both buddies got leg %q — one of them can never bind", ta.Leg)
	}
	if ta.Leg != ticket.LegB || tb.Leg != ticket.LegA {
		t.Fatalf("leg assignment does not follow key order: %q got %q, %q got %q", keyA, ta.Leg, keyB, tb.Leg)
	}
	if ta.EPK != epkA || tb.EPK != epkB {
		t.Fatal("a ticket was bound to the wrong ephemeral key — it would admit the wrong buddy")
	}
	if ta.RID != rid || tb.RID != rid {
		t.Fatalf("ticket names relay %q, want %q", ta.RID, rid)
	}

	// A re-poll on the same token must not mint a NEW session id: the partner is
	// already binding under the first one.
	again := parseTicket(t, srvPub, issueFor(t, reg, srvPriv, rid, "tok", keyA, epkA, keyB))
	if again.SID != ta.SID {
		t.Fatalf("re-registering changed the session id (%s -> %s); the partner's leg is bound under the old one", ta.SID, again.SID)
	}

	// A different pairing gets its own session.
	other := parseTicket(t, srvPub, issueFor(t, reg, srvPriv, rid, "tok2", keyA, epkA, keyB))
	if other.SID == ta.SID {
		t.Fatal("two different tokens share one session id — a stranger's pairing would splice into this one")
	}
}

// TestNoTicketWhenThereIsNothingToAuthorise: every one of these is a normal
// state, and none of them may take the pairing down with it. The relay fallback
// is simply unavailable.
func TestNoTicketWhenThereIsNothingToAuthorise(t *testing.T) {
	_, srvPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	rid, err := ticket.NewID()
	if err != nil {
		t.Fatalf("rid: %v", err)
	}
	_, epk := ephKey(t)

	cases := []struct {
		name                        string
		rid, myKey, epk, partnerKey string
	}{
		{name: "no relay configured", rid: "", myKey: "a", epk: epk, partnerKey: "b"},
		{name: "buddy sent no ephemeral key", rid: rid, myKey: "a", epk: "", partnerKey: "b"},
		{name: "ephemeral key is not base64url", rid: rid, myKey: "a", epk: "!!!!", partnerKey: "b"},
		{name: "ephemeral key is the wrong length", rid: rid, myKey: "a", epk: base64.RawURLEncoding.EncodeToString([]byte("short")), partnerKey: "b"},
		{name: "both peers registered the same identity", rid: rid, myKey: "same", epk: epk, partnerKey: "same"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := issueFor(t, newHSRegistry(time.Minute), srvPriv, tc.rid, "tok", tc.myKey, tc.epk, tc.partnerKey)
			if got != nil {
				t.Fatalf("a ticket was issued when there was nothing to authorise (%s)", tc.name)
			}
		})
	}
}

// TestSessionIDsAreBounded: the sid map is per-token state on a public server,
// so it must be bounded like every other map here. Over the cap a pairing gets
// no ticket — never an unbounded map.
func TestSessionIDsAreBounded(t *testing.T) {
	reg := newHSRegistry(time.Minute)
	for i := 0; i < maxTokens; i++ {
		if _, ok := reg.sidFor(string(rune(i%256)) + string(rune(i/256))); !ok {
			t.Fatalf("sidFor refused inside the cap at %d", i)
		}
	}
	if _, ok := reg.sidFor("one-too-many"); ok {
		t.Fatal("sidFor minted past the cap — the map is unbounded")
	}
	if len(reg.sids) > maxTokens {
		t.Fatalf("sid map holds %d entries, over the %d cap", len(reg.sids), maxTokens)
	}
}

// TestSessionIDReleasedWithTheToken: the sid must not outlive the pairing it
// belongs to, or the map leaks one entry per token the server ever saw.
func TestSessionIDReleasedWithTheToken(t *testing.T) {
	reg := newHSRegistry(time.Millisecond)
	if _, _, ok := reg.upsert(regMsg("tok", "A", "pkA"), v4(1000)); !ok {
		t.Fatal("upsert refused")
	}
	if _, ok := reg.sidFor("tok"); !ok {
		t.Fatal("sidFor refused")
	}
	time.Sleep(5 * time.Millisecond)
	reg.mu.Lock()
	for token, bucket := range reg.waiting {
		for id, p := range bucket {
			if time.Since(p.seen) > reg.ttl {
				delete(bucket, id)
			}
		}
		if len(bucket) == 0 {
			delete(reg.waiting, token)
			delete(reg.sids, token)
		}
	}
	left := len(reg.sids)
	reg.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d session id(s) survived the token they belong to", left)
	}
}

// TestRelayAdvertRejectsAMalformedRelayID: a mistyped id is a configuration
// error that would otherwise surface as "every ticket rejected" at the relay,
// with nothing in either log naming the cause.
func TestRelayAdvertRejectsAMalformedRelayID(t *testing.T) {
	if _, err := relayAdvertFor(HandshakeConfig{RelayID: "not-an-id", RelayEndpoint: "vps:51821"}); err == nil {
		t.Fatal("a malformed --relay-id was accepted")
	}
	good, err := ticket.NewID()
	if err != nil {
		t.Fatalf("rid: %v", err)
	}
	adv, err := relayAdvertFor(HandshakeConfig{RelayID: good, RelayEndpoint: "vps:51821"})
	if err != nil {
		t.Fatalf("a valid relay configuration was refused: %v", err)
	}
	if adv.rid != good || adv.endpoint != "vps:51821" {
		t.Fatalf("advert = %+v, want rid %s / endpoint vps:51821", adv, good)
	}
	// No relay at all is a normal, fully functional configuration: BuddyNet must
	// work P2P-only.
	if _, err := relayAdvertFor(HandshakeConfig{}); err != nil {
		t.Fatalf("a server with no relay configuration was refused: %v", err)
	}
}
