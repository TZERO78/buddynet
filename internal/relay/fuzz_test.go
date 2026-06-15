package relay

import (
	"testing"

	"github.com/tzero78/buddynet/pkg/protocol"
)

// FuzzParseBind throws arbitrary bytes at the relay's bind-control parser — the
// relay must distinguish a bind from the QUIC data it forwards on every datagram.
// Invariant: never panic, and an accepted bind always carries a non-empty,
// length-bounded session token and a length-bounded cookie.
func FuzzParseBind(f *testing.F) {
	f.Add(MarshalBind(Bind{SessionToken: "sess"}))
	f.Add(MarshalBind(Bind{SessionToken: "sess", Cookie: "AAAAAAAAAAAAAAAAAAAAAA"}))
	f.Add([]byte(BindPrefix + "{}"))
	f.Add([]byte(BindPrefix + `{"s":""}`))
	f.Add([]byte("BNRELAY1 not json"))
	f.Add([]byte("random QUIC-looking bytes \x00\x01\x02"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, pkt []byte) {
		b, ok := ParseBind(pkt)
		if !ok {
			return
		}
		if b.SessionToken == "" || len(b.SessionToken) > protocol.MaxFieldLen {
			t.Fatalf("accepted bad session token len=%d", len(b.SessionToken))
		}
		if len(b.Cookie) > protocol.MaxFieldLen {
			t.Fatalf("accepted oversized cookie len=%d", len(b.Cookie))
		}
	})
}

// FuzzParseChallenge throws arbitrary bytes at the relay-challenge parser the
// buddy runs on relay replies. Invariant: never panic, and an accepted challenge
// always yields exactly CookieLen bytes. A bind must never parse as a challenge.
func FuzzParseChallenge(f *testing.F) {
	f.Add(MarshalChallenge(make([]byte, CookieLen)))
	f.Add([]byte(ChallengePrefix))
	f.Add([]byte(ChallengePrefix + "short"))
	f.Add(MarshalBind(Bind{SessionToken: "sess"}))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, pkt []byte) {
		cookie, ok := ParseChallenge(pkt)
		if !ok {
			return
		}
		if len(cookie) != CookieLen {
			t.Fatalf("accepted challenge with cookie len=%d, want %d", len(cookie), CookieLen)
		}
	})
}
