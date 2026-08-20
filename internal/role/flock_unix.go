//go:build !windows

package role

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock on path+".lock" so that the server
// and the operator's `approve`/`revoke` invocations, or the buddy and a `peers
// remove` — separate
// processes — serialise their read-modify-write of a state file and never lose an
// update.
//
// It FAILS CLOSED. The earlier version returned a no-op unlock when the lock
// could not be taken, so the caller wrote anyway: the one situation the lock
// exists for (another process is mid-update) was the one where it silently did
// nothing. A caller that cannot lock must not write.
//
// The lock file is derived from the target path, so every process guarding the
// same file agrees on the same lock without any further coordination.
func lockFile(path string) (unlock func(), err error) {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock %s.lock: %w", path, err)
	}
	// EINTR is retried, not reported. A blocking flock() sits in the kernel, and
	// the Go runtime's asynchronous preemption delivers SIGURG to running threads
	// — so under load an unrelated preemption can interrupt the wait and return
	// EINTR. Treating that as "cannot lock" would, with the fail-closed policy
	// above, turn a scheduling event into a refused write. It surfaced as a
	// flaky refusal in the trust-state tests once every writer of known_peers
	// started going through this lock.
	for {
		lerr := syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if lerr == nil {
			break
		}
		if errors.Is(lerr, syscall.EINTR) {
			continue
		}
		f.Close()
		return nil, fmt.Errorf("lock %s.lock: %w", path, lerr)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
