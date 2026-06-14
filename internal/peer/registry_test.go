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

func TestMergeSkipsSelf(t *testing.T) {
	r, _ := Open("")
	merged := r.Merge("me", []protocol.Peer{
		{PubKey: "me"}, // ourselves: skipped
		{ID: "p", PubKey: "p"},
	})
	if len(merged) != 1 || merged[0].PubKey != "p" {
		t.Fatalf("merge should skip self: %+v", merged)
	}
	if _, ok := r.Get("me"); ok {
		t.Fatal("self should not be cached")
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
