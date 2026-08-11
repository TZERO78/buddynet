//go:build windows

package role

// lockFile is a no-op on Windows (no flock); the admin
// subcommands are not expected to run concurrently there.
func lockFile(path string) (unlock func(), err error) { return func() {}, nil }
