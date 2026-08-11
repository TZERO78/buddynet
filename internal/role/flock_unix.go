//go:build !windows

package role

import (
	"fmt"
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock on path+".lock" so that the server
// and the operator's `approve`/`revoke`/`allowclient` invocations — separate
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
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock %s.lock: %w", path, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
