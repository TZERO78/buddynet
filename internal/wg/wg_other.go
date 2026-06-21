//go:build !linux

package wg

// Up is unavailable off Linux: there is no kernel WireGuard netlink interface.
// Callers degrade gracefully (errors.Is(err, ErrUnsupported)).
func Up(cfg Config) (down func() error, err error) {
	return nil, ErrUnsupported
}
