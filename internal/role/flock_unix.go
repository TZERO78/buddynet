//go:build !windows

package role

import (
	"os"
	"syscall"
)

// lockAllowlist takes an exclusive advisory lock on path+".lock" so that
// concurrent `buddynet approve`/`revoke` invocations (separate processes)
// serialise their read-modify-write of the allowlist file and never lose an
// update. Best-effort: if the lock cannot be acquired the caller still proceeds
// (these are operator-side, manual, rare operations). Returns the unlock func.
func lockAllowlist(path string) (unlock func()) {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return func() {}
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}
}
