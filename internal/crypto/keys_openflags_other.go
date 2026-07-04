//go:build !unix

package crypto

// Platforms without O_NOFOLLOW (notably Windows): fall back to no extra open flag.
// The Lstat symlink pre-check in LoadOrCreateKey is the guard there — it matches
// the pre-existing cross-platform behaviour; only the atomic close of the
// check-to-open race (via O_NOFOLLOW above) is Unix-specific.
const oNoFollow = 0

// symlinkRefused is always false here: without O_NOFOLLOW an open never fails
// specifically because the path was a symlink.
func symlinkRefused(error) bool { return false }
