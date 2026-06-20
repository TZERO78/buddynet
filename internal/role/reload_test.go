//go:build !windows

package role

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// supervise must catch SIGHUP, reconcile against the (here empty) manifest
// without deadlocking or terminating, and still return cleanly on ctx cancel.
// Network-free: with no specs there are no workers to dial.
func TestSuperviseReloadOnSIGHUP(t *testing.T) {
	dir := t.TempDir()
	cfg := BuddyConfig{
		PeersFile:  filepath.Join(dir, "peers"),       // absent → empty manifest
		KnownPeers: filepath.Join(dir, "known_peers"), // absent → no sessions
	}

	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { done <- supervise(ctx, cfg, &node{}, nil) }()

	// Let supervise register its SIGHUP handler before we send one — otherwise the
	// default action (terminate) could race the signal.Notify call.
	time.Sleep(150 * time.Millisecond)

	// Fire SIGHUP a couple of times; supervise should keep running and reconcile.
	for i := 0; i < 2; i++ {
		if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
			t.Fatalf("send SIGHUP: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	select {
	case err := <-done:
		t.Fatalf("supervise returned early (SIGHUP should not terminate it): %v", err)
	default:
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("supervise: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("supervise did not return after ctx cancel")
	}
}
