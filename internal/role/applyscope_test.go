package role

// Regression tests for the gap that made the M-1 forward drop unreachable under
// `--expose all`.
//
// The rules themselves were right: nft.buildBatch emits the forward-hook drop for
// Scope{All} too, and both the unit tests and the netns lab confirmed that. What
// neither of them touched was applyScope — the one function between the rule
// builder and the kernel — which returned early for `all` and so never called
// nft.Apply at all. Correct rules, never installed.
//
// The lesson these tests encode: assert at the layer that DECIDES, not only at the
// layer that COMPUTES. Everything below is about what applyScope does, not about
// what the ruleset looks like.

import (
	"errors"
	"testing"

	"github.com/tzero78/buddynet/internal/nft"
)

// withFakeNFT swaps the nft indirections for the duration of a test and records
// what applyScope asked the kernel to do.
func withFakeNFT(t *testing.T, applyErr error) (applied *[]nft.Scope, removed *[]string) {
	t.Helper()
	var gotApply []nft.Scope
	var gotRemove []string
	savedApply, savedRemove := applyNFT, removeNFT
	applyNFT = func(ifName string, s nft.Scope) error {
		gotApply = append(gotApply, s)
		return applyErr
	}
	removeNFT = func(ifName string) error {
		gotRemove = append(gotRemove, ifName)
		return nil
	}
	t.Cleanup(func() { applyNFT, removeNFT = savedApply, savedRemove })
	return &gotApply, &gotRemove
}

// TestApplyScopeProgramsRulesForEveryScope is the gate. `all` is the case that
// regressed, but a scope that installs nothing would be just as broken, so all
// three shapes are checked the same way.
func TestApplyScopeProgramsRulesForEveryScope(t *testing.T) {
	ports, err := nft.ParseScope("tcp/445")
	if err != nil {
		t.Fatal(err)
	}
	all, err := nft.ParseScope("all")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		scope nft.Scope
	}{
		{"named ports", ports},
		{"expose all", all},
		{"fail-closed (nothing exposed)", nft.Scope{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			applied, _ := withFakeNFT(t, nil)
			teardown, err := applyScope("bnet0", tc.scope)
			if err != nil {
				t.Fatalf("applyScope: %v", err)
			}
			if teardown == nil {
				t.Fatal("applyScope returned no teardown")
			}
			if len(*applied) != 1 {
				t.Fatalf(`applyScope called nft.Apply %d times, want exactly 1.

With 0, the ruleset is computed correctly and never reaches the kernel — which is
how the forward-hook drop went missing under --expose all while every test that
drives buildBatch or nft.Apply directly stayed green.`, len(*applied))
			}
			if (*applied)[0].All != tc.scope.All || len((*applied)[0].Ports) != len(tc.scope.Ports) {
				t.Fatalf("applyScope passed a different scope than it was given: %+v vs %+v", (*applied)[0], tc.scope)
			}
		})
	}
}

// TestApplyScopeFailsClosed: if the kernel will not take the rules, the tunnel
// must not come up — for `all` as much as for a port list, since `all` also has a
// rule to install now (the forward drop).
func TestApplyScopeFailsClosed(t *testing.T) {
	boom := errors.New("no nftables support")
	all, _ := nft.ParseScope("all")
	for _, tc := range []struct {
		name  string
		scope nft.Scope
	}{
		{"named ports", func() nft.Scope { s, _ := nft.ParseScope("tcp/445"); return s }()},
		{"expose all", all},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withFakeNFT(t, boom)
			teardown, err := applyScope("bnet0", tc.scope)
			if err == nil {
				t.Fatal("applyScope succeeded although the ruleset could not be programmed — the tunnel would come up unprotected")
			}
			if teardown != nil {
				t.Fatal("applyScope returned a teardown alongside its error")
			}
			if !errors.Is(err, boom) {
				t.Fatalf("the underlying cause is not wrapped: %v", err)
			}
		})
	}
}

// TestApplyScopeTeardownRemovesTheRules: the returned closure must clean up, or a
// reconnect leaves stale rules for an interface that no longer exists.
func TestApplyScopeTeardownRemovesTheRules(t *testing.T) {
	_, removed := withFakeNFT(t, nil)
	teardown, err := applyScope("bnet0", nft.Scope{})
	if err != nil {
		t.Fatal(err)
	}
	teardown()
	if len(*removed) != 1 || (*removed)[0] != "bnet0" {
		t.Fatalf("teardown removed %v, want exactly [bnet0]", *removed)
	}
}
