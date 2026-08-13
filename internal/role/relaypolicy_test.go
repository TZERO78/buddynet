package role

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tzero78/buddynet/internal/ticket"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return p.Masked()
}

func serverKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return pub
}

func relayID(t *testing.T) string {
	t.Helper()
	id, err := ticket.NewID()
	if err != nil {
		t.Fatalf("rid: %v", err)
	}
	return id
}

// TestRelayRefusesToStartWithoutAPolicy is plan cases 23 and 24. A relay carries
// the operator's bandwidth, so "who may use it" is not something that can be left
// unanswered — and an allow-everything CIDR is not an answer, it is the open
// relay this design exists to prevent, spelled differently.
func TestRelayRefusesToStartWithoutAPolicy(t *testing.T) {
	rid := relayID(t)
	keys := []ed25519.PublicKey{serverKey(t)}

	t.Run("neither policy", func(t *testing.T) {
		err := RelayConfig{}.checkPolicy()
		if !errors.Is(err, ErrNoRelayPolicy) {
			t.Fatalf("a relay with no policy started (err=%v)", err)
		}
		// The message has to be actionable, not just correct.
		for _, want := range []string{"--server-key", "--relay-id", "--allow-cidr"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("the refusal does not tell the operator about %s:\n%v", want, err)
			}
		}
	})

	for _, all := range []string{"0.0.0.0/0", "::/0"} {
		t.Run("allow-everything "+all, func(t *testing.T) {
			err := RelayConfig{AllowCIDRs: []netip.Prefix{mustPrefix(t, all)}}.checkPolicy()
			if err == nil {
				t.Fatalf("--allow-cidr %s was accepted as a policy — that is an open relay", all)
			}
			if errors.Is(err, ErrNoRelayPolicy) {
				t.Fatal("an allow-everything prefix must have its OWN message, not the generic one")
			}
		})
	}

	t.Run("tickets without a relay id", func(t *testing.T) {
		if err := (RelayConfig{ServerKeys: keys}).checkPolicy(); err == nil {
			t.Fatal("a ticket-mode relay with no --relay-id started; it would reject every ticket it is handed")
		}
		if err := (RelayConfig{ServerKeys: keys, RelayID: "not-an-id"}).checkPolicy(); err == nil {
			t.Fatal("a malformed --relay-id was accepted")
		}
	})

	t.Run("too many server keys", func(t *testing.T) {
		three := []ed25519.PublicKey{serverKey(t), serverKey(t), serverKey(t)}
		if err := (RelayConfig{ServerKeys: three, RelayID: rid}).checkPolicy(); err == nil {
			t.Fatal("three server keys were accepted; the rotation window is two")
		}
	})

	// Positive controls: without these, every assertion above would be satisfied by
	// a check that refuses everything.
	for name, cfg := range map[string]RelayConfig{
		"tickets":          {ServerKeys: keys, RelayID: rid},
		"network":          {AllowCIDRs: []netip.Prefix{mustPrefix(t, "203.0.113.0/24")}},
		"both":             {ServerKeys: keys, RelayID: rid, AllowCIDRs: []netip.Prefix{mustPrefix(t, "203.0.113.0/24")}},
		"rotation, 2 keys": {ServerKeys: []ed25519.PublicKey{serverKey(t), serverKey(t)}, RelayID: rid},
	} {
		t.Run("accepted: "+name, func(t *testing.T) {
			if err := cfg.checkPolicy(); err != nil {
				t.Fatalf("a valid relay policy was refused: %v", err)
			}
		})
	}
}

// TestRelayStartupRefusalIsNotAPortBind: the refusal must happen BEFORE a socket
// is opened, so a misconfigured relay cannot sit on the port half-alive.
func TestRelayStartupRefusalIsNotAPortBind(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Port 1 would need privileges; reaching the bind at all is the failure here.
	err := Relay(ctx, RelayConfig{Listen: "127.0.0.1:1"})
	if !errors.Is(err, ErrNoRelayPolicy) {
		t.Fatalf("expected the policy refusal before any bind, got %v", err)
	}
}

// TestBuddyRefusesAnOverlongPunch is plan case 38: refused AT STARTUP, not
// silently clipped. A punch longer than the cap would leave a relay ticket that
// can expire while the punch it was issued for is still running.
func TestBuddyRefusesAnOverlongPunch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := Buddy(ctx, BuddyConfig{PunchDur: PunchDurMax + time.Second})
	if err == nil {
		t.Fatal("an over-long --punch was accepted")
	}
	if !strings.Contains(err.Error(), "--punch") {
		t.Fatalf("the refusal does not name the flag that caused it: %v", err)
	}
	if PunchDurMax+ticket.MaxTTL/2 > ticket.MaxTTL {
		// Stated as an assertion so the two constants cannot drift apart silently:
		// the cap must leave at least half the ticket for the bind that follows.
		t.Fatalf("PunchDurMax %s leaves less than half of a %s ticket for binding", PunchDurMax, ticket.MaxTTL)
	}
}
