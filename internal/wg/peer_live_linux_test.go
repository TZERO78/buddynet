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

// TestLivePeerEndpoint proves PeerEndpoint reads back the peer's underlay endpoint
// from the kernel (the primitive the WG handshake uses to recover a buddy's
// punchable address). The kernel stores a configured endpoint immediately, so no
// real handshake is needed. Run as root:
//
//	WG_LIVE=1 go test -run TestLivePeerEndpoint -v -exec 'sudo -E' ./internal/wg/
func TestLivePeerEndpoint(t *testing.T) {
	if os.Getenv("WG_LIVE") == "" {
		t.Skip("set WG_LIVE=1 and run as root")
	}
	const dev = "bnetep0"
	_ = delLinkByName(dev)

	want := netip.MustParseAddrPort("203.0.113.7:51820")
	peerPub := [32]byte{9}
	down, err := Up(Config{
		IfName:     dev,
		PrivateKey: [32]byte{1},
		ListenPort: 51998,
		Address:    netip.MustParsePrefix("10.66.0.1/16"),
		Peer: Peer{
			PublicKey:  peerPub,
			Endpoint:   want,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.66.0.9/32")},
		},
	})
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	defer down()

	got, ok, err := PeerEndpoint(dev, peerPub)
	if err != nil {
		t.Fatalf("PeerEndpoint: %v", err)
	}
	if !ok || got != want {
		t.Fatalf("PeerEndpoint: want %v (ok), got %v ok=%v", want, got, ok)
	}

	// An unknown peer key reports ok=false, no error.
	if _, ok, err := PeerEndpoint(dev, [32]byte{42}); err != nil || ok {
		t.Fatalf("PeerEndpoint(unknown): want ok=false,nil err; got ok=%v err=%v", ok, err)
	}
	t.Logf("PeerEndpoint read back %v from the kernel", got)
}
