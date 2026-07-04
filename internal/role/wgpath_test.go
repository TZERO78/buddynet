package role

import (
	"bytes"
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"github.com/tzero78/buddynet/internal/nft"
)

// runBindingOverConn over a real local UDP socket pair (no root): both ends must
// derive the same session binding and therefore the same SAS — exercising the
// BNBIND1 framing + retransmit on top of the ephemeral-DH exchange.
func TestRunBindingOverConn(t *testing.T) {
	a, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	aAddr := a.LocalAddr().(*net.UDPAddr)
	bAddr := b.LocalAddr().(*net.UDPAddr)

	type res struct {
		sid []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		sid, err := runBindingOverConn(b, aAddr, false, 5*time.Second) // initiator
		ch <- res{sid, err}
	}()
	sidA, errA := runBindingOverConn(a, bAddr, true, 5*time.Second) // committer
	if errA != nil {
		t.Fatalf("committer: %v", errA)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("initiator: %v", r.err)
	}
	if !bytes.Equal(sidA, r.sid) {
		t.Fatalf("bindings differ:\n a=%x\n b=%x", sidA, r.sid)
	}

	pubA, _, _ := ed25519.GenerateKey(nil)
	pubB, _, _ := ed25519.GenerateKey(nil)
	if ComputeSAS(pubA, pubB, sidA) != ComputeSAS(pubB, pubA, r.sid) {
		t.Fatal("SAS mismatch over the connected binding")
	}
}

// Precedence: per-buddy manifest expose > global --expose > fail-closed.
func TestEffectiveScopePrecedence(t *testing.T) {
	perBuddy, _ := nft.ParseScope("873")
	global, _ := nft.ParseScope("8080")

	if got := effectiveScope(BuddyConfig{}, attempt{}); got.All || len(got.Ports) != 0 {
		t.Fatalf("no config must be fail-closed, got %s", got)
	}
	if got := effectiveScope(BuddyConfig{Expose: &global}, attempt{}); got.String() != "tcp/8080" {
		t.Fatalf("global flag not applied: %s", got)
	}
	if got := effectiveScope(BuddyConfig{Expose: &global}, attempt{expose: &perBuddy}); got.String() != "tcp/873" {
		t.Fatalf("per-buddy scope must win over the flag: %s", got)
	}
	all := nft.Scope{All: true}
	if got := effectiveScope(BuddyConfig{Expose: &global}, attempt{expose: &all}); !got.All {
		t.Fatalf("per-buddy 'all' must win: %s", got)
	}
}
