package role

// Tests for the A-03 fix: a stored session pin no longer displaces --peer-key.
// The fix has two halves and each is tested on its own:
//
//  1. nextAttempt refuses a configured pin that contradicts the stored one,
//     before anything registers (audit_peerkey_bypass_test.go, plus the
//     positive control below that a MATCHING pin still connects).
//  2. enforcePins checks the partner key the server named against BOTH pins,
//     for the case where the server answers with a third key.

import (
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"
)

// POSITIVE CONTROL for the early refusal: a --peer-key that AGREES with the
// stored session pin must still produce a normal reconnect attempt. Without
// this, "nextAttempt returns an error" would also be satisfied by a fix that
// simply broke every pinned reconnect.
func TestNextAttemptPeerKeyMatchingStoredPinStillConnects(t *testing.T) {
	pub, b64 := mustKey(t)

	known := filepath.Join(t.TempDir(), "known_peers")
	if err := saveSession(known, "invite-tok", b64, "stored-secret"); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	att, err := nextAttempt(BuddyConfig{KnownPeers: known, PeerKey: b64, Token: "invite-tok"})
	if err != nil {
		t.Fatalf("matching --peer-key must not block the reconnect: %v", err)
	}
	if att.rendezvous != "stored-secret" {
		t.Fatalf("expected the stored session secret as rendezvous, got %q", att.rendezvous)
	}
	if att.pin == nil || !att.pin.Equal(pub) {
		t.Fatal("stored pin not carried into the attempt")
	}
	if att.cfgPin == nil || !att.cfgPin.Equal(pub) {
		t.Fatal("--peer-key not carried into the attempt (connect.go could not enforce it)")
	}
}

// The stored pin must keep working on its own: no --peer-key set means no
// configured pin to check, and the reconnect proceeds exactly as before.
func TestNextAttemptWithoutPeerKeyIsUnchanged(t *testing.T) {
	pub, b64 := mustKey(t)
	known := filepath.Join(t.TempDir(), "known_peers")
	if err := saveSession(known, "invite-tok", b64, "stored-secret"); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	att, err := nextAttempt(BuddyConfig{KnownPeers: known, Token: "invite-tok"})
	if err != nil {
		t.Fatalf("nextAttempt: %v", err)
	}
	if att.cfgPin != nil {
		t.Fatal("no --peer-key was set, so no configured pin may appear in the attempt")
	}
	if att.pin == nil || !att.pin.Equal(pub) {
		t.Fatal("stored pin lost")
	}
}

// enforcePins is the late check, for a server that names a partner neither pin
// allows. All combinations, so neither pin can quietly stop being checked.
func TestEnforcePinsChecksBothPins(t *testing.T) {
	stored, _ := mustKey(t)
	configured, _ := mustKey(t)
	stranger, _ := mustKey(t)

	cases := []struct {
		name    string
		att     attempt
		partner ed25519.PublicKey
		wantErr string // "" = must be accepted
	}{
		{
			name:    "both pins agree with the partner",
			att:     attempt{pin: stored, cfgPin: stored},
			partner: stored,
		},
		{
			name:    "no configured pin, partner matches the stored one",
			att:     attempt{pin: stored},
			partner: stored,
		},
		{
			name:    "partner matches the stored pin but not --peer-key",
			att:     attempt{pin: stored, cfgPin: configured},
			partner: stored,
			wantErr: "--peer-key",
		},
		{
			name:    "partner matches --peer-key but not the stored pin",
			att:     attempt{pin: stored, cfgPin: configured},
			partner: configured,
			wantErr: "stored session pin",
		},
		{
			name:    "partner matches neither",
			att:     attempt{pin: stored, cfgPin: configured},
			partner: stranger,
			wantErr: "stored session pin",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := enforcePins(tc.att, tc.partner, "partner key")
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("expected acceptance, got %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("expected refusal mentioning %q, got acceptance", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("refusal should name %q, got %v", tc.wantErr, err)
			}
		})
	}
}
