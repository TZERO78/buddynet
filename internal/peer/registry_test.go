package peer

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/tzero78/buddynet/pkg/protocol"
)

func TestRegistryPersistAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	want := protocol.Peer{ID: "x", PubKey: "pk", VirtualIP: "10.66.0.9"}
	if err := r.Upsert(want); err != nil {
		t.Fatal(err)
	}
	// Reopen from disk: the cache must survive a restart (the offline fallback).
	r2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := r2.Get("pk")
	if !ok || got.ID != "x" || got.VirtualIP != "10.66.0.9" {
		t.Fatalf("peer not persisted: %+v ok=%v", got, ok)
	}
	if got.LastSeen == 0 {
		t.Fatal("LastSeen should have been stamped")
	}
}

// TestNamePinningTOFU verifies that the first name claimed by a key is kept
// on subsequent upserts, even if the peer later sends a different name.
func TestNamePinningTOFU(t *testing.T) {
	r, _ := Open("")
	if err := r.Upsert(protocol.Peer{PubKey: "keyA", VirtualIP: "10.66.0.1", Name: "alice"}); err != nil {
		t.Fatal(err)
	}
	// Same key, different name — pinned name must survive.
	if err := r.Upsert(protocol.Peer{PubKey: "keyA", VirtualIP: "10.66.0.1", Name: "mallory"}); err != nil {
		t.Fatal(err)
	}
	got, _ := r.Get("keyA")
	if got.Name != "alice" {
		t.Fatalf("TOFU: name changed from alice to %q; should stay pinned", got.Name)
	}
}

// TestNameUniqueness verifies that two keys cannot claim the same name:
// the second key gets an empty name (fingerprint-only reachability).
func TestNameUniqueness(t *testing.T) {
	r, _ := Open("")
	if err := r.Upsert(protocol.Peer{PubKey: "keyA", VirtualIP: "10.66.0.1", Name: "bob"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Upsert(protocol.Peer{PubKey: "keyB", VirtualIP: "10.66.0.2", Name: "bob"}); err != nil {
		t.Fatal(err)
	}
	a, _ := r.Get("keyA")
	b, _ := r.Get("keyB")
	if a.Name != "bob" {
		t.Fatalf("first claimer should keep name bob, got %q", a.Name)
	}
	if b.Name != "" {
		t.Fatalf("second claimer should have empty name, got %q", b.Name)
	}
}

// TestNamePersistsAcrossReopen verifies that pinned names survive a registry
// reload from disk (peers.json).
func TestNamePersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	r, _ := Open(path)
	if err := r.Upsert(protocol.Peer{PubKey: "keyA", VirtualIP: "10.66.0.1", Name: "carol"}); err != nil {
		t.Fatal(err)
	}
	r2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := r2.Get("keyA")
	if !ok || got.Name != "carol" {
		t.Fatalf("name not persisted after reopen: got %q ok=%v", got.Name, ok)
	}
}

func TestFresh(t *testing.T) {
	now := protocol.Peer{LastSeen: time.Now().Unix()}
	old := protocol.Peer{LastSeen: time.Now().Add(-2 * time.Hour).Unix()}
	if !Fresh(now, time.Hour) {
		t.Fatal("recent peer should be fresh")
	}
	if Fresh(old, time.Hour) {
		t.Fatal("stale peer should not be fresh")
	}
	if Fresh(protocol.Peer{}, time.Hour) {
		t.Fatal("never-seen peer should not be fresh")
	}
}
