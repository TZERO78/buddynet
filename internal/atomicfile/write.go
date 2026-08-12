// Package atomicfile writes a file so that a reader — or a crash — never sees a
// half-written one. Every piece of BuddyNet's on-disk state goes through it: the
// allowlist and its pending enrollments, the peer cache, the session store. They
// share one failure mode worth avoiding once rather than three times: a torn or
// empty file means "nobody is authorised" or "no peers are known", which is a
// silent outage rather than an error anyone sees.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
)

// Write replaces path with data as atomically as a filesystem allows:
// write a UNIQUE temp file next to it, fsync the file, rename it over the target,
// then fsync the directory.
//
// Every step earns its place:
//
//   - A unique temp name (pid + a counter) rather than a fixed path+".tmp". Two
//     processes sharing a state file — the server and an operator's approve/revoke,
//     or two servers during a side-by-side protocol migration — would otherwise
//     write the SAME temp file and rename each other's half-finished content into
//     place.
//   - fsync on the file before the rename. Without it the rename can be durable
//     while the bytes are not, so a crash leaves a correctly-named EMPTY file:
//     an allowlist that authorises nobody, a peer cache with no peers.
//   - fsync on the directory after the rename, or the rename itself may not
//     survive a power cut and the old content comes back.
//
// The caller is responsible for serialising writers; this only makes one write
// indivisible to readers.
//
// TRUST DOMAIN (gosec flags the two variable-path opens below as G304). Every
// path reaching this function is an operator-supplied flag or a value derived
// from one — --authorized and its ".pending" sibling, --peers, --known-peers, or
// the XDG defaults behind them. No component of any path comes from the network:
// the control plane influences the CONTENT of these files (a pending entry, a
// cached peer), never their location. A caller who can choose the path is already
// the operator, and holds --key as well.
//
// The two opens are also symlink-safe by construction rather than by check:
// O_CREATE|O_EXCL refuses to follow (or reuse) an existing symlink at the temp
// path, and rename(2) replaces a symlink at the target instead of writing through
// it. The directory open is read-only and used solely for fsync.
// Write replaces path with data.
func Write(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp := path + ".tmp." + strconv.Itoa(os.Getpid()) + "." + strconv.FormatUint(nextWriteSeq(), 10)

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	// From here on every failure must take the temp file with it, or a crashing
	// writer litters the state directory with half-written copies of a secret.
	cleanup := func(e error) error {
		f.Close()
		_ = os.Remove(tmp)
		return e
	}
	if _, err := f.Write(data); err != nil {
		return cleanup(fmt.Errorf("write %s: %w", tmp, err))
	}
	if err := f.Sync(); err != nil {
		return cleanup(fmt.Errorf("fsync %s: %w", tmp, err))
	}
	if err := f.Close(); err != nil {
		return cleanup(fmt.Errorf("close %s: %w", tmp, err))
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
	}
	// Directory fsync: best-effort, because some filesystems (and some test
	// environments) refuse to open a directory for sync. The rename is already
	// atomic for readers; this only bounds how far back a power cut can take it.
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// writeSeq makes temp names unique WITHIN a process, as the pid does between
// processes. Two goroutines writing different files at the same microsecond would
// otherwise be able to collide.
var writeSeq atomic.Uint64

func nextWriteSeq() uint64 { return writeSeq.Add(1) }
