//go:build linux

package nft

import (
	"os"
	"testing"
)

// TestKernelSmoke exercises Apply/Remove against the real kernel. It needs
// root (CAP_NET_ADMIN) and is skipped otherwise, so `go test ./...` stays
// green for unprivileged runs; the lab script runs it under sudo.
func TestKernelSmoke(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (run via lab/test-wg-expose.sh)")
	}
	s, err := ParseScope("tcp/873,udp/51820")
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply("bnet-t0", s); err != nil {
		t.Fatalf("apply bnet-t0: %v", err)
	}
	s2, _ := ParseScope("8080")
	if err := Apply("bnet-t1", s2); err != nil {
		t.Fatalf("apply bnet-t1: %v", err)
	}
	// Reprogram an existing interface (rebuild path).
	s3, _ := ParseScope("9000")
	if err := Apply("bnet-t0", s3); err != nil {
		t.Fatalf("reapply bnet-t0: %v", err)
	}
	if err := Remove("bnet-t0"); err != nil {
		t.Fatalf("remove bnet-t0: %v", err)
	}
	if err := Remove("bnet-t1"); err != nil {
		t.Fatalf("remove bnet-t1 (last — drops the table): %v", err)
	}
	// Idempotent: removing an unknown interface is a no-op.
	if err := Remove("bnet-t9"); err != nil {
		t.Fatalf("remove unknown: %v", err)
	}
}
