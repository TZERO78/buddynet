//go:build !windows

package role

import (
	"sync"
	"syscall"
)

// umaskMu serialises the umask dance below. umask is a PROCESS-wide setting, so
// two goroutines doing this at once could restore each other's value; the lock
// makes the pair atomic with respect to this package.
var umaskMu sync.Mutex

// withTightUmask runs fn with the process umask set so that anything fn creates
// is owner-only (0600 for files, 0700 for directories), then restores the
// previous value.
//
// This exists because a Unix socket cannot be created private: net.Listen makes
// the socket file with 0777 &^ umask and the listener starts accepting
// immediately, so a chmod afterwards closes the door on a room somebody may
// already be standing in. On a -L socket that matters more than usual: the
// forwarder has no authentication of its own — the file mode IS the access
// control, and whoever connects is spliced onto the tunnel to the partner.
//
// The window was measured, not assumed: an observer polling the path saw the
// socket group/world-accessible in 127 of 200 rounds before the chmod landed.
//
// The umask is process-wide for the moments this holds it, which is why the
// window is kept to exactly one syscall and why the lock is here.
func withTightUmask(fn func() error) error {
	umaskMu.Lock()
	old := syscall.Umask(0o177)
	defer func() {
		syscall.Umask(old)
		umaskMu.Unlock()
	}()
	return fn()
}
