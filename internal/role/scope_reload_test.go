package role

import (
	"testing"

	"github.com/tzero78/buddynet/internal/nft"
)

func TestSameScope(t *testing.T) {
	p873a, _ := nft.ParseScope("873")
	p873b, _ := nft.ParseScope("tcp/873")     // same as 873
	p873ord, _ := nft.ParseScope("udp/9,873") // different set
	all := nft.Scope{All: true}

	cases := []struct {
		name string
		a, b *nft.Scope
		want bool
	}{
		{"both nil (inherit)", nil, nil, true},
		{"nil vs set", nil, &p873a, false},
		{"set vs nil", &p873a, nil, false},
		{"same ports different spelling", &p873a, &p873b, true},
		{"different ports", &p873a, &p873ord, false},
		{"all vs ports", &all, &p873a, false},
		{"all vs all", &all, &all, true},
	}
	for _, c := range cases {
		if got := sameScope(c.a, c.b); got != c.want {
			t.Errorf("%s: sameScope = %v, want %v", c.name, got, c.want)
		}
	}
}

// The scope cell is the cross-goroutine handoff the supervisor uses to push a
// SIGHUP scope edit to the worker's next bring-up: a set is observed by get.
func TestScopeCell(t *testing.T) {
	c := newScopeCell(nil)
	if c.get() != nil {
		t.Fatal("fresh cell must be nil (inherit)")
	}
	s, _ := nft.ParseScope("2222")
	c.set(&s)
	got := c.get()
	if got == nil || got.String() != "tcp/2222" {
		t.Fatalf("after set: got %v", got)
	}
	c.set(nil)
	if c.get() != nil {
		t.Fatal("after set(nil): expected inherit again")
	}
}
