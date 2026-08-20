package role

// AUDIT 2026-08-20, finding A-03 (measurement first): hsRegistry.upsert calls
// evictStalestLocked once the token table is full, and that helper is an O(n)
// scan over ALL maxTokens buckets (each one itself scanned by bucketSeen) while
// the single registry mutex r.mu is held.
//
// This file MEASURES the cost before anything is claimed about it: a full table
// plus a stream of fresh tokens is exactly what an attacker produces, and the
// question is how much wall-clock time each such packet spends inside the global
// lock that every legitimate registration also has to take.

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"testing"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/pkg/protocol"
)

func auditRegMsg(t testing.TB, token, id string) protocol.Message {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return protocol.Message{
		Type:      protocol.TypeRegister,
		Ver:       protocol.Version,
		Token:     token,
		ID:        id,
		PubKey:    bcrypto.PubKeyB64(pub),
		VirtualIP: bcrypto.VirtualIPString(pub),
	}
}

func auditSrc(i int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)), Port: 40000 + i%1000}
}

// TestAuditEvictStalestScanCost fills the registry to maxTokens and then times
// how long further upserts with fresh tokens take — the per-packet cost an
// attacker controls, spent under the global lock.
func TestAuditEvictStalestScanCost(t *testing.T) {
	reg := newHSRegistry(time.Minute)
	for i := 0; i < maxTokens; i++ {
		tok := fmt.Sprintf("tok-%06d", i)
		if _, _, ok := reg.upsert(auditRegMsg(t, tok, fmt.Sprintf("id-%06d", i)), auditSrc(i)); !ok {
			t.Fatalf("setup: upsert %d refused", i)
		}
	}
	if len(reg.waiting) != maxTokens {
		t.Fatalf("setup: table holds %d tokens, want %d", len(reg.waiting), maxTokens)
	}

	// Time a run of fresh-token upserts; each one is now on the eviction path.
	// Messages are built up front so key generation is not in the measurement.
	const n = 200
	msgs := make([]protocol.Message, n)
	for i := range msgs {
		msgs[i] = auditRegMsg(t, fmt.Sprintf("flood-%06d", i), fmt.Sprintf("fid-%06d", i))
	}
	start := time.Now()
	for i := range msgs {
		reg.upsert(msgs[i], auditSrc(100000+i))
	}
	perPacket := time.Since(start) / n

	// Baseline: the same call on an EMPTY table, which takes no eviction path.
	empty := newHSRegistry(time.Minute)
	base := make([]protocol.Message, n)
	for i := range base {
		base[i] = auditRegMsg(t, fmt.Sprintf("base-%06d", i), fmt.Sprintf("bid-%06d", i))
	}
	bstart := time.Now()
	for i := range base {
		empty.upsert(base[i], auditSrc(200000+i))
	}
	basePerPacket := time.Since(bstart) / n

	t.Logf("A-03 measurement: upsert on a FULL table = %v/packet, on an EMPTY table = %v/packet (factor %.0fx)",
		perPacket, basePerPacket, float64(perPacket)/float64(basePerPacket))

	// The handshake server admits up to rlGlobalRate packets/sec. What share of a
	// second does the eviction scan alone occupy inside the global lock at that rate?
	lockShare := float64(perPacket) * rlGlobalRate / float64(time.Second)
	t.Logf("A-03: at the admitted global rate of %d packets/sec this is %.0f%% of one second spent inside r.mu",
		int(rlGlobalRate), lockShare*100)

	if lockShare < 0.25 {
		t.Logf("cost is below a quarter of the lock's wall-clock budget — NOT reported as a finding")
		return
	}
	t.Fatalf(`A-03 CONFIRMED — evictStalestLocked is a lock-contention DoS lever.

Once the token table is full, EVERY registration carrying a fresh token makes
hsRegistry.upsert scan all %d buckets (evictStalestLocked -> bucketSeen) while
holding r.mu, the single mutex every registration needs.

Measured: %v per packet on a full table vs %v on an empty one.
At the server's own admitted ceiling of %d packets/sec that is %.0f%% of one
second of pure scanning inside the global lock — time in which no legitimate
buddy's registration can make progress.

Filling the table is not rate-limited away: maxTokens is %d, the per-source
limit is %d/sec, so about %d source addresses reach the global ceiling and hold
it there.`,
		maxTokens, perPacket, basePerPacket, int(rlGlobalRate), lockShare*100,
		maxTokens, int(rlSrcRate), int(rlGlobalRate/rlSrcRate))
}
