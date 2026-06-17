package protocol

import "regexp"

// MaxNameLen is the maximum byte length of a BuddyNet node name — one DNS label.
const MaxNameLen = 63

// nameRE accepts DNS-label-safe names: 1–63 lowercase letters/digits/hyphens,
// starting and ending with a letter or digit. Uppercase is rejected here; callers
// that receive names over the wire must lowercase before calling ValidName.
var nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// ValidName reports whether s is an acceptable node name for the .buddy TLD:
// 1–63 lowercase letters, digits, or hyphens; must begin and end with a letter
// or digit (standard DNS label rules). Empty string is invalid.
func ValidName(s string) bool {
	return len(s) >= 1 && len(s) <= MaxNameLen && nameRE.MatchString(s)
}
