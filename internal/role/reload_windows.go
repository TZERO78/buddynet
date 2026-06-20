//go:build windows

package role

import "os"

// reloadSignal is a no-op on Windows, which has no SIGHUP: the returned nil
// channel never fires, so the supervisor simply never live-reloads (a restart
// re-reads the manifest). Keeps the buddy role buildable cross-platform.
func reloadSignal() <-chan os.Signal { return nil }
