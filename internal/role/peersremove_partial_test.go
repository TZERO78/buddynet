package role

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPeersRemovePartialFailureReportsWhatIsAlreadyInEffect pins the reporting
// half of the revocation transaction.
//
// PeersRemove writes in a load-bearing order — tombstone, then session, then
// manifest — so that an abort leaves the SAFE state: revoked, possibly still
// configured. That part was already right. What was wrong was what the operator
// was told about it: a failure in the last step returned the bare I/O error, so
// `peers remove` printed
//
//	error: rename /peers.tmp.82.3 -> /peers: device or resource busy
//
// and nothing else. An operator reading that concludes the revocation did not
// happen and that the buddy still has access — the dangerous direction to be
// wrong in, because the truth is the opposite: the key is already refused at
// every reconnect.
//
// Found in the lab, where the manifest is a bind-mounted FILE and an atomic
// rename over it cannot work. Any read-only or otherwise unrenameable manifest
// path reproduces it.
func TestPeersRemovePartialFailureReportsWhatIsAlreadyInEffect(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: directory permissions would not stop the write")
	}

	// The manifest and the trust state must live in DIFFERENT directories: the
	// tombstone has to succeed (that is the premise) while the manifest rewrite
	// fails. That is exactly the lab's shape — trust state on a writable volume,
	// manifest on a read-only mount.
	manifestDir := t.TempDir()
	trustDir := t.TempDir()
	peersFile := filepath.Join(manifestDir, "peers")
	knownPeers := filepath.Join(trustDir, "known_peers")

	key := "1u67KlQUxr6FWTPLtEVFZruDZB5dJj28Q3RHuiqcG5c="
	manifest := "buddies:\n  - key: " + key + "\n    token: t\n"
	if err := os.WriteFile(peersFile, []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	// Make the manifest's DIRECTORY unwritable: the temp file cannot be created
	// and the rename cannot land, while the tombstone still succeeds.
	if err := os.Chmod(manifestDir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(manifestDir, 0o700) })

	err := PeersRemove(peersFile, knownPeers, key)
	if err == nil {
		t.Fatal("PeersRemove succeeded although the manifest could not be rewritten — " +
			"if this now works, the premise of this test is stale, not the requirement")
	}

	// The message must lead with what is TRUE NOW, not with the failed step.
	got := err.Error()
	for _, want := range []string{"ALREADY IN EFFECT", "revocation list", "peers allow"} {
		if !strings.Contains(got, want) {
			t.Errorf("the error does not tell the operator the revocation already holds:\n"+
				"  missing %q\n  got: %s", want, got)
		}
	}

	// And it must be true: the tombstone is on disk, so the buddy really is
	// refused. A reassuring message that was not backed by state would be worse
	// than the bare I/O error.
	revoked, rerr := os.ReadFile(trustBase(knownPeers, peersFile) + ".revoked")
	if rerr != nil {
		t.Fatalf("no revocation list was written, so the message would be a lie: %v", rerr)
	}
	if !strings.Contains(string(revoked), key) {
		t.Fatalf("the revocation list does not contain the key:\n%s", revoked)
	}
}
