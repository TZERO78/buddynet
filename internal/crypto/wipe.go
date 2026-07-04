package crypto

import "runtime"

// wipe best-effort zeroes secret key material once it has been consumed. Go gives
// NO hard guarantee here — the garbage collector may already have copied the bytes
// elsewhere, and without mlock they can be paged to disk — so this is defence in
// depth, not a promise. What it does buy: a derived scalar or shared secret does
// not linger in the heap for the whole process lifetime, shrinking the window in
// which a memory disclosure (core dump, /proc/pid/mem, swap) could recover it.
// runtime.KeepAlive keeps the store from being reordered before the last real use.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
