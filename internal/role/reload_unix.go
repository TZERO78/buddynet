//go:build !windows

package role

import (
	"os"
	"os/signal"
	"syscall"
)

// reloadSignal returns a channel that fires on SIGHUP, the conventional "re-read
// your config" signal. The multi-buddy supervisor reconciles its worker set
// against the manifest each time it fires, so `peers add`/`remove` take effect on
// a running daemon without a restart (send `kill -HUP <pid>`). Catching SIGHUP
// also stops it from terminating the process by default.
func reloadSignal() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	return ch
}
