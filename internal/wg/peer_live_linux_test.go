//go:build linux

package wg

import (
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Live test of the bnet0 adapter model (one device, peers added/removed
// dynamically). Run as root:
//
//	WG_LIVE=1 go test -run TestLiveAddRemovePeer -v -exec 'sudo -E' ./internal/wg/
func TestLiveAddRemovePeer(t *testing.T) {
	if os.Getenv("WG_LIVE") == "" {
		t.Skip("set WG_LIVE=1 and run as root")
	}
	const dev = "bnetlt0"
	_ = delLinkByName(dev)

	down, err := Up(Config{
		IfName:     dev,
		PrivateKey: [32]byte{1},
		ListenPort: 51999,
		Address:    netip.MustParsePrefix("10.66.0.1/16"),
		Peer: Peer{
			PublicKey:  [32]byte{2},
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.66.0.2/32")},
		},
	})
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	defer down()

	peerCount := func() int {
		out, e := exec.Command("wg", "show", dev, "peers").Output()
		if e != nil {
			t.Fatalf("wg show: %v", e)
		}
		s := strings.TrimSpace(string(out))
		if s == "" {
			return 0
		}
		return len(strings.Split(s, "\n"))
	}

	if got := peerCount(); got != 1 {
		t.Fatalf("after Up: want 1 peer, got %d", got)
	}

	// Add a second peer — the first must remain (no REPLACE_PEERS).
	if err := AddPeer(dev, Peer{PublicKey: [32]byte{3}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.66.0.3/32")}}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if got := peerCount(); got != 2 {
		t.Fatalf("after AddPeer: want 2 peers, got %d", got)
	}

	// Remove the second peer — the first must remain.
	if err := RemovePeer(dev, [32]byte{3}); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if got := peerCount(); got != 1 {
		t.Fatalf("after RemovePeer: want 1 peer, got %d", got)
	}
	t.Log("bnet0 adapter model verified: one device, peers add/remove dynamically")
}
