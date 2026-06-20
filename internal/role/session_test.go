package role

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net"
	"path/filepath"
	"testing"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/tunnel"
)

// fakeSession is a minimal tunnel.Session whose ExportKeyingMaterial is a
// deterministic stand-in for the real TLS channel binding: it depends on the
// label and context, so the derivation's key-sorting and binding behaviour can
// be tested without a live QUIC connection.
type fakeSession struct{ ekm []byte }

func (f fakeSession) ExportKeyingMaterial(label string, ctx []byte, length int) ([]byte, error) {
	h := sha256.Sum256(append(append([]byte(label), '|'), append(ctx, f.ekm...)...))
	out := make([]byte, length)
	copy(out, h[:])
	return out, nil
}
func (fakeSession) OpenStream(context.Context) (tunnel.Stream, error)   { return nil, nil }
func (fakeSession) AcceptStream(context.Context) (tunnel.Stream, error) { return nil, nil }
func (fakeSession) RemoteAddr() net.Addr                                { return nil }
func (fakeSession) Done() <-chan struct{}                               { return nil }
func (fakeSession) Close() error                                        { return nil }

func TestDeriveSessionSecretSymmetricAndBound(t *testing.T) {
	a := genKey(t)
	b := genKey(t)
	sess := fakeSession{ekm: []byte("session-1")}

	sa, err := deriveSessionSecret(sess, a, b)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	sb, err := deriveSessionSecret(sess, b, a) // other side, keys swapped
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if sa != sb {
		t.Fatalf("both ends must derive the same secret: %q != %q", sa, sb)
	}
	if sa == "" {
		t.Fatal("empty secret")
	}

	// A different session (channel binding) yields a different secret.
	other, _ := deriveSessionSecret(fakeSession{ekm: []byte("session-2")}, a, b)
	if other == sa {
		t.Fatal("secret must change with the channel binding")
	}
	// A different partner yields a different secret.
	c := genKey(t)
	diff, _ := deriveSessionSecret(sess, a, c)
	if diff == sa {
		t.Fatal("secret must change with the partner key")
	}
}

func TestSessionStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_peers")
	partner, _, _ := ed25519.GenerateKey(rand.Reader)
	partnerB64 := bcrypto.PubKeyB64(partner)

	// A legacy trust-on-first-use line must survive a session write untouched.
	if err := learnPeer(path, "legacy-token", "AAAAlegacykeyAAAA"); err != nil {
		t.Fatalf("seed legacy line: %v", err)
	}

	if err := saveSession(path, "invite-tok", partnerB64, "secret-one"); err != nil {
		t.Fatalf("saveSession: %v", err)
	}
	gotPub, gotSecret, ok, err := loadSession(path)
	if err != nil || !ok {
		t.Fatalf("loadSession: ok=%v err=%v", ok, err)
	}
	if !gotPub.Equal(partner) {
		t.Fatal("loaded partner key mismatch")
	}
	if gotSecret != "secret-one" {
		t.Fatalf("loaded secret = %q, want secret-one", gotSecret)
	}
	// Legacy lookup still works after the session write.
	if known, _ := loadKnownPeer(path, "legacy-token"); known != "AAAAlegacykeyAAAA" {
		t.Fatalf("legacy TOFU line was clobbered: %q", known)
	}

	// Re-pairing replaces the single session (BuddyPeer), not appends.
	if err := saveSession(path, "invite-tok2", partnerB64, "secret-two"); err != nil {
		t.Fatalf("saveSession 2: %v", err)
	}
	_, gotSecret, ok, _ = loadSession(path)
	if !ok || gotSecret != "secret-two" {
		t.Fatalf("re-pair should replace session: ok=%v secret=%q", ok, gotSecret)
	}
}

func TestLoadSessionNoneYet(t *testing.T) {
	_, _, ok, err := loadSession(filepath.Join(t.TempDir(), "absent"))
	if err != nil || ok {
		t.Fatalf("absent store: ok=%v err=%v", ok, err)
	}
}

// Multi-peer: the store keeps one session line per partner. Saving a second
// partner must not clobber the first, and re-pairing one partner replaces only
// that partner's line.
func TestSessionStoreMultiPeer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_peers")
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	b, _, _ := ed25519.GenerateKey(rand.Reader)
	aB64, bB64 := bcrypto.PubKeyB64(a), bcrypto.PubKeyB64(b)

	if err := saveSession(path, "tok-a", aB64, "secret-a"); err != nil {
		t.Fatalf("saveSession a: %v", err)
	}
	if err := saveSession(path, "tok-b", bB64, "secret-b"); err != nil {
		t.Fatalf("saveSession b: %v", err)
	}

	sessions, err := loadSessions(path)
	if err != nil {
		t.Fatalf("loadSessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("want 2 sessions, got %d", len(sessions))
	}
	got := map[string]string{}
	for _, s := range sessions {
		got[bcrypto.PubKeyB64(s.pin)] = s.secret
	}
	if got[aB64] != "secret-a" || got[bB64] != "secret-b" {
		t.Fatalf("multi-peer secrets mismatch: %v", got)
	}

	// Re-pair partner A only: A's secret changes, B's is untouched.
	if err := saveSession(path, "tok-a2", aB64, "secret-a2"); err != nil {
		t.Fatalf("re-pair a: %v", err)
	}
	sessions, _ = loadSessions(path)
	if len(sessions) != 2 {
		t.Fatalf("re-pair must not change session count, got %d", len(sessions))
	}
	got = map[string]string{}
	for _, s := range sessions {
		got[bcrypto.PubKeyB64(s.pin)] = s.secret
	}
	if got[aB64] != "secret-a2" {
		t.Fatalf("re-pair should update A: %q", got[aB64])
	}
	if got[bB64] != "secret-b" {
		t.Fatalf("re-pair of A clobbered B: %q", got[bB64])
	}
}
