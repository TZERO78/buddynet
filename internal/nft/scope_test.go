package nft

import "testing"

func TestParseScope(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"all", "all"},
		{"ALL", "all"},
		{"873", "tcp/873"},
		{"tcp/873", "tcp/873"},
		{"873,8080", "tcp/873,tcp/8080"},
		{"udp/51820,tcp/873", "tcp/873,udp/51820"}, // normalized order
		{" 873 , udp/53 ", "tcp/873,udp/53"},
		{"873,873,tcp/873", "tcp/873"}, // duplicates folded
	}
	for _, c := range cases {
		s, err := ParseScope(c.in)
		if err != nil {
			t.Fatalf("ParseScope(%q): %v", c.in, err)
		}
		if got := s.String(); got != c.want {
			t.Fatalf("ParseScope(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseScopeRejectsBadInput(t *testing.T) {
	for _, in := range []string{"", "0", "65536", "abc", "tcp/", "icmp/8", "tcp/873/9", "873;22", "-1"} {
		if _, err := ParseScope(in); err == nil {
			t.Fatalf("ParseScope(%q): expected an error", in)
		}
	}
}

func TestScopeStringZeroValue(t *testing.T) {
	var s Scope
	if got := s.String(); got != "NONE" {
		t.Fatalf("zero Scope = %q, want NONE (fail-closed)", got)
	}
}
