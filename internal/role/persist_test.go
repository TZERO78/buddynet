package role

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/peer"
	"github.com/tzero78/buddynet/pkg/protocol"
)

// buddySide builds a node for one end of a loopback pairing, with its own peer
// cache at cachePath.
func buddySide(t *testing.T, serverKeyB64, knownPeers, cachePath string) *node {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverPub, err := bcrypto.DecodePubKey(serverKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := peer.Open(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	return &node{
		id:        randomID(),
		pub:       bcrypto.PubKeyB64(pub),
		vip:       bcrypto.VirtualIPString(pub),
		priv:      priv,
		serverPub: serverPub,
		trust:     &trustPolicy{storePath: knownPeers},
		reg:       reg,
	}
}

// runSide starts one buddy attempt in the background and reports its error.
func runSide(ctx context.Context, cfg BuddyConfig, att attempt, nd *node) <-chan error {
	out := make(chan error, 1)
	go func() { out <- buddyRun(ctx, cfg, att, nd, nil) }()
	return out
}

// readCache loads a peers.json written by a buddy. A missing file means nothing
// was ever persisted, which several of these tests are asserting.
func readCache(t *testing.T, path string) []protocol.Peer {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []protocol.Peer
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("corrupt peer cache %s: %v", path, err)
	}
	return out
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// A peer reaches peers.json only once the tunnel is actually up — and then it
// does, so the offline fallback still gets what it needs.
func TestPeerIsCachedAfterAConfirmedConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in -short mode")
	}
	srvAddr, srvKey := inProcHandshake(t)
	dir := t.TempDir()
	cacheA := filepath.Join(dir, "a-peers.json")
	cacheB := filepath.Join(dir, "b-peers.json")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const token = "cache-token"
	base := BuddyConfig{
		Server: srvAddr, ServerKey: srvKey, Token: token,
		Insecure: true, PunchDur: 3 * time.Second, IdleTimeout: 60 * time.Second,
	}
	a, b := buddySide(t, srvKey, "", cacheA), buddySide(t, srvKey, "", cacheB)
	a.trust.insecure, b.trust.insecure = true, true

	cfgA := base
	cfgA.Forward = echoServer(t)
	cfgA.PeersPath = cacheA
	cfgB := base
	cfgB.LocalListen = freeTCPAddr(t)
	cfgB.PeersPath = cacheB

	runSide(ctx, cfgA, attempt{rendezvous: token, inviteToken: token}, a)
	runSide(ctx, cfgB, attempt{rendezvous: token, inviteToken: token}, b)

	if !waitFor(t, 25*time.Second, func() bool {
		return len(readCache(t, cacheA)) > 0 && len(readCache(t, cacheB)) > 0
	}) {
		t.Fatal("a confirmed connection did not populate the peer cache — the offline fallback would be broken")
	}
	got := readCache(t, cacheA)
	if got[0].PubKey != b.pub {
		t.Fatalf("cached peer %q, want the partner %q", got[0].PubKey, b.pub)
	}
	// What the offline fallback consumes must be usable straight away.
	if !peer.Fresh(got[0], 24*time.Hour) {
		t.Fatal("the cached peer is not fresh — the offline fallback would skip it")
	}
	if len(got[0].Candidates) == 0 {
		t.Fatal("the cached peer carries no endpoint, so there is nothing to fall back to")
	}
}

// Trust-on-first-use with no way to run the SAS: the tunnel comes up, but the
// identity is never confirmed, so NOTHING may be persisted — not the peer and
// not its self-asserted .buddy name.
func TestUnconfirmedIdentityIsNotPersisted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in -short mode")
	}
	srvAddr, srvKey := inProcHandshake(t)
	dir := t.TempDir()
	cacheA := filepath.Join(dir, "a-peers.json")
	cacheB := filepath.Join(dir, "b-peers.json")
	knownB := filepath.Join(dir, "b-known_peers")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const token = "sas-token"
	base := BuddyConfig{
		Server: srvAddr, ServerKey: srvKey, Token: token,
		PunchDur: 3 * time.Second, IdleTimeout: 60 * time.Second,
	}

	// A is in --lab so it needs no SAS and will happily hold the tunnel open.
	a := buddySide(t, srvKey, "", cacheA)
	a.trust.insecure = true
	cfgA := base
	cfgA.Insecure = true
	cfgA.Forward = echoServer(t)
	cfgA.PeersPath = cacheA
	cfgA.Name = "impostor"

	// B does trust-on-first-use but is NOT interactive: the partner key is unknown
	// and there is no human to confirm the SAS, so buddyRun must refuse.
	b := buddySide(t, srvKey, knownB, cacheB)
	cfgB := base
	cfgB.KnownPeers = knownB
	cfgB.PeersPath = cacheB
	cfgB.Interactive = false
	cfgB.LocalListen = freeTCPAddr(t)

	runSide(ctx, cfgA, attempt{rendezvous: token, inviteToken: token}, a)
	errB := runSide(ctx, cfgB, attempt{rendezvous: token, inviteToken: token}, b)

	select {
	case err := <-errB:
		if err == nil {
			t.Fatal("an unverifiable first contact must not succeed")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("B neither connected nor refused within the deadline")
	}

	if got := readCache(t, cacheB); len(got) != 0 {
		t.Fatalf("an unconfirmed partner was persisted anyway: %+v", got)
	}
	// The trust store must be untouched too: no key learned without an SAS.
	if data, err := os.ReadFile(knownB); err == nil && len(data) > 0 {
		t.Fatalf("an unconfirmed key was written to the trust store: %q", data)
	}
	// And no .buddy name may have been pinned from the unverified roster.
	reg, err := peer.Open(cacheB)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range reg.List() {
		if p.Name != "" {
			t.Fatalf("pinned the name %q of an unconfirmed peer", p.Name)
		}
	}
}

// An already-pinned peer is REFRESHED after a successful authenticated
// connection: a stale cached endpoint must not survive a live sighting.
func TestPinnedPeerIsRefreshedAfterConnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in -short mode")
	}
	srvAddr, srvKey := inProcHandshake(t)
	dir := t.TempDir()
	cacheA := filepath.Join(dir, "a-peers.json")
	cacheB := filepath.Join(dir, "b-peers.json")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const token = "pin-token"
	base := BuddyConfig{
		Server: srvAddr, ServerKey: srvKey, Token: token,
		PunchDur: 3 * time.Second, IdleTimeout: 60 * time.Second,
	}
	a := buddySide(t, srvKey, "", cacheA)
	b := buddySide(t, srvKey, "", cacheB)
	a.trust.pinned = b.priv.Public().(ed25519.PublicKey)
	b.trust.pinned = a.priv.Public().(ed25519.PublicKey)

	// Seed A's cache with a stale view of B: right key, wrong endpoint, old sighting.
	stale := protocol.Peer{
		ID:         "old-run",
		PubKey:     b.pub,
		VirtualIP:  b.vip,
		Candidates: []protocol.Candidate{{Addr: "192.0.2.1:1"}},
		LastSeen:   time.Now().Add(-12 * time.Hour).Unix(),
	}
	if err := a.reg.Upsert(stale); err != nil {
		t.Fatal(err)
	}

	cfgA := base
	cfgA.Forward = echoServer(t)
	cfgA.PeersPath = cacheA
	cfgB := base
	cfgB.LocalListen = freeTCPAddr(t)
	cfgB.PeersPath = cacheB

	runSide(ctx, cfgA, attempt{rendezvous: token, inviteToken: token, pin: a.trust.pinned}, a)
	runSide(ctx, cfgB, attempt{rendezvous: token, inviteToken: token, pin: b.trust.pinned}, b)

	if !waitFor(t, 25*time.Second, func() bool {
		for _, p := range readCache(t, cacheA) {
			if p.PubKey == b.pub && p.ID != "old-run" {
				return true
			}
		}
		return false
	}) {
		t.Fatalf("a pinned peer was not refreshed after an authenticated connection: %+v", readCache(t, cacheA))
	}
	for _, p := range readCache(t, cacheA) {
		if p.PubKey != b.pub {
			continue
		}
		if p.LastSeen <= stale.LastSeen {
			t.Fatalf("LastSeen not refreshed: %d <= %d", p.LastSeen, stale.LastSeen)
		}
		for _, c := range p.Candidates {
			if c.Addr == "192.0.2.1:1" {
				t.Fatal("the stale endpoint survived a live sighting")
			}
		}
	}
}
