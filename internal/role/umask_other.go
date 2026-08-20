//go:build windows

package role

// withTightUmask has nothing to do where there is no umask and no Unix domain
// socket path to protect; the caller's chmod remains the only step.
func withTightUmask(fn func() error) error { return fn() }
