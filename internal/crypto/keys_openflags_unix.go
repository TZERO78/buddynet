//go:build unix

package crypto

import (
	"errors"
	"syscall"
)

// oNoFollow makes an open fail rather than follow a final-component symlink, so a
// key path swapped to a symlink cannot redirect the open (and the fd-based perm
// check / chmod that follow) to another file. Unix only; the non-Unix fallback in
// keys_openflags_other.go is 0, where the Lstat pre-check is the symlink guard.
const oNoFollow = syscall.O_NOFOLLOW

// symlinkRefused reports whether an open failed because O_NOFOLLOW refused to
// follow a symlink at the final path component (ELOOP) — i.e. a symlink was
// swapped in between the Lstat pre-check and the open.
func symlinkRefused(err error) bool { return errors.Is(err, syscall.ELOOP) }
