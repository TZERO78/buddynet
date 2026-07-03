package protocol

import "regexp"

// MaxNameLen is the maximum byte length of a BuddyNet node name — one DNS label.
const MaxNameLen = 63

// nameRE accepts DNS-label-safe names: 1–63 lowercase letters/digits/hyphens,
// starting and ending with a letter or digit. Uppercase is rejected here; callers
// that receive names over the wire must lowercase before calling ValidName.
var nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// fpAliasRE matches the reserved fingerprint-alias shape: exactly 8 lowercase
// hex characters. The BuddyDNS resolver gives every peer a "<fp8>.buddy" alias
// (the first 8 hex of SHA-256(pubkey)) so unnamed peers stay reachable, and
// names + fingerprint aliases share one flat .buddy label space. A self-asserted
// name of exactly this shape could collide with — and shadow — another peer's
// fingerprint alias in that table (last writer wins). Reserving the shape for
// fingerprints keeps the two namespaces disjoint, so a name can never hijack an
// alias. The cost is that an 8-hex-character vanity name (e.g. "deadbeef") is
// disallowed — an acceptable trade for an unambiguous overlay namespace.
var fpAliasRE = regexp.MustCompile(`^[0-9a-f]{8}$`)

// ValidName reports whether s is an acceptable node name for the .buddy TLD:
// 1–63 lowercase letters, digits, or hyphens; must begin and end with a letter
// or digit (standard DNS label rules). Empty string is invalid, and a name whose
// shape is reserved for a fingerprint alias (exactly 8 hex chars) is rejected so
// it cannot shadow another peer's "<fp8>.buddy" entry.
func ValidName(s string) bool {
	return len(s) >= 1 && len(s) <= MaxNameLen && nameRE.MatchString(s) && !fpAliasRE.MatchString(s)
}
