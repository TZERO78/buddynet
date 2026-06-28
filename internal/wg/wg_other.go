//go:build !linux

package wg

// Up is unavailable off Linux: there is no kernel WireGuard netlink interface.
// Callers degrade gracefully (errors.Is(err, ErrUnsupported)). A future Windows
// port would live in wg_windows.go (userspace wireguard-go + Wintun).
func Up(cfg Config) (down func() error, err error) {
	return nil, ErrUnsupported
}

// Available reports false off Linux: no kernel WireGuard.
func Available() bool { return false }
