package role

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
)

// TestDirectPartnerDerivesEverythingFromTheKey is the core invariant of direct
// mode: with no server and no roster, nothing about the partner is taken on
// anyone's word. In particular the virtual IP must be DERIVED from the pinned
// key (identity is address), never configured — otherwise a peer could be
// pointed at an address that contradicts its identity, which is exactly what the
// signed roster prevents in server mode.
func TestDirectPartnerDerivesEverythingFromTheKey(t *testing.T) {
	priv, _, err := bcrypto.LoadOrCreateKey(t.TempDir() + "/peer.key")
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	keyB64 := bcrypto.PubKeyB64(pub)

	got, err := directPartner(BuddyConfig{PeerKey: keyB64, PeerEndpoint: "example.org:51820"})
	if err != nil {
		t.Fatalf("directPartner: %v", err)
	}
	if got.PubKey != keyB64 {
		t.Fatalf("PubKey = %q, want %q", got.PubKey, keyB64)
	}
	if want := bcrypto.VirtualIPString(pub); got.VirtualIP != want {
		t.Fatalf("VirtualIP = %q, want %q (must be derived from the key, not configured)", got.VirtualIP, want)
	}
	// The endpoint is route-finding only and must not leak into identity.
	if strings.Contains(got.VirtualIP, "example.org") || got.PubKey == "example.org:51820" {
		t.Fatal("the configured endpoint leaked into the partner identity")
	}
}

// TestDirectPartnerRefusesWithoutPin guards the rule that makes direct mode safe
// at all: no pin, no connection. There is no rendezvous channel here to run a
// SAS over, so an unpinned partner is not a weaker mode — it is none.
func TestDirectPartnerRefusesWithoutPin(t *testing.T) {
	if _, err := directPartner(BuddyConfig{PeerEndpoint: "example.org:51820"}); !errors.Is(err, errDirectNoKey) {
		t.Fatalf("directPartner without --peer-key: err = %v, want errDirectNoKey", err)
	}
	if _, err := directPartner(BuddyConfig{PeerKey: "not-base64!!"}); err == nil {
		t.Fatal("a malformed --peer-key was accepted")
	}
}

// TestDirectListening pins the role split. Both ends compute this from local
// configuration ALONE — there is no server to arrange a simultaneous connect —
// so if the two sides ever disagreed, both would listen (or both dial) and no
// tunnel could form.
func TestDirectListening(t *testing.T) {
	const lo, hi = "AAAA", "ZZZZ" // lower key listens when both could do either
	for _, tc := range []struct {
		name     string
		cfg      BuddyConfig
		my, peer string
		want     bool
	}{
		{"only a fixed port: must listen", BuddyConfig{ListenPort: 51820}, hi, lo, true},
		{"only an endpoint: must dial", BuddyConfig{PeerEndpoint: "p:1"}, lo, hi, false},
		{"both, lower key listens", BuddyConfig{ListenPort: 51820, PeerEndpoint: "p:1"}, lo, hi, true},
		{"both, higher key dials", BuddyConfig{ListenPort: 51820, PeerEndpoint: "p:1"}, hi, lo, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := directListening(tc.cfg, tc.my, tc.peer); got != tc.want {
				t.Fatalf("directListening = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestDirectListeningIsComplementary is the property the test above only samples:
// for any pair of distinct keys, exactly ONE side listens. Checked for the
// symmetric case (both ends fully configured), which is the only one where the
// two sides could disagree.
func TestDirectListeningIsComplementary(t *testing.T) {
	cfg := BuddyConfig{ListenPort: 51820, PeerEndpoint: "p:1"}
	for _, pair := range [][2]string{{"a", "b"}, {"b", "a"}, {"AA", "AB"}, {"zz", "az"}} {
		mine, theirs := pair[0], pair[1]
		if directListening(cfg, mine, theirs) == directListening(cfg, theirs, mine) {
			t.Fatalf("both ends agreed on the same role for %q/%q — no tunnel could form", mine, theirs)
		}
	}
}

// TestValidateDirect covers the startup checks. Each of these would otherwise
// surface as a reconnect loop that never lands, which is the worst way to learn
// about a typo.
func TestValidateDirect(t *testing.T) {
	key := "0LqJ6b1CEyjKU6jaaq+ZIo9K89xnRbxQXLuVn0iYEZ0="
	for _, tc := range []struct {
		name    string
		cfg     BuddyConfig
		wantErr bool
	}{
		{"not direct: nothing to check", BuddyConfig{}, false},
		{"ok: dials", BuddyConfig{Direct: true, PeerKey: key, PeerEndpoint: "h:51820"}, false},
		{"ok: is dialled", BuddyConfig{Direct: true, PeerKey: key, ListenPort: 51820}, false},
		{"ok: both", BuddyConfig{Direct: true, PeerKey: key, PeerEndpoint: "h:1", ListenPort: 2}, false},
		{"no pin", BuddyConfig{Direct: true, PeerEndpoint: "h:51820"}, true},
		{"no way to meet", BuddyConfig{Direct: true, PeerKey: key}, true},
		{"endpoint without port", BuddyConfig{Direct: true, PeerKey: key, PeerEndpoint: "h"}, true},
		{"endpoint without host", BuddyConfig{Direct: true, PeerKey: key, PeerEndpoint: ":51820"}, true},
		{"endpoint with bad port", BuddyConfig{Direct: true, PeerKey: key, PeerEndpoint: "h:nope"}, true},
		{"bad relay", BuddyConfig{Direct: true, PeerKey: key, ListenPort: 1, PeerRelay: "h"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDirect(tc.cfg)
			if tc.wantErr != (err != nil) {
				t.Fatalf("validateDirect = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestValidateDirectDoesNotResolve: a dynamic-DNS name legitimately may not
// resolve when the process starts (the updater has not run yet, the record is
// mid-change). Startup validation must therefore check the SHAPE of the address
// and never its resolvability, or a buddy would refuse to boot for a reason that
// fixes itself a minute later.
func TestValidateDirectDoesNotResolve(t *testing.T) {
	cfg := BuddyConfig{
		Direct:       true,
		PeerKey:      "0LqJ6b1CEyjKU6jaaq+ZIo9K89xnRbxQXLuVn0iYEZ0=",
		PeerEndpoint: "definitely-does-not-exist.invalid:51820",
	}
	if err := validateDirect(cfg); err != nil {
		t.Fatalf("a name that does not resolve must still pass startup validation: %v", err)
	}
}
