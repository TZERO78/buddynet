package protocol

import "testing"

func TestValidName(t *testing.T) {
	valid := []string{
		"a", "alice", "bob2", "web-01", "a-b-c",
		"x23456789012345678901234567890123456789012345678901234567890123", // 63 chars
		"deadbeefx", // 9 chars: fingerprint-shaped prefix but not the reserved 8-hex shape
		"g1234567",  // 8 chars but 'g' is not hex, so not a fingerprint alias
		"12345",     // short numeric label, not 8 hex
	}
	for _, s := range valid {
		if !ValidName(s) {
			t.Errorf("ValidName(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"",            // empty
		"-abc",        // leading hyphen
		"abc-",        // trailing hyphen
		"Alice",       // uppercase (callers must lowercase first)
		"a.b",         // dot: names are a single label
		"under_score", // underscore not allowed
		"space bar",   // space
		"x2345678901234567890123456789012345678901234567890123456789012345", // 64 chars, over MaxNameLen
	}
	for _, s := range invalid {
		if ValidName(s) {
			t.Errorf("ValidName(%q) = true, want false", s)
		}
	}
}

// TestValidNameRejectsFingerprintShape is the regression test for the DNS
// alias-shadowing finding: a self-asserted name must not be able to take the
// exact shape of a peer's "<fp8>.buddy" fingerprint alias (8 lowercase hex),
// or it could overwrite that alias in the resolver's flat label table and
// misdirect name.buddy traffic to a different peer.
func TestValidNameRejectsFingerprintShape(t *testing.T) {
	fpShaped := []string{
		"deadbeef", // classic 8-hex
		"00000000",
		"ffffffff",
		"0a1b2c3d",
		"cafebabe",
	}
	for _, s := range fpShaped {
		if ValidName(s) {
			t.Errorf("ValidName(%q) = true, want false: 8-hex names are reserved for fingerprint aliases", s)
		}
	}
}
