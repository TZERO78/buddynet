//go:build windows

package role

// lockAllowlist is a no-op on Windows (no flock); the allowlist admin
// subcommands are not expected to run concurrently there.
func lockAllowlist(path string) (unlock func()) { return func() {} }
