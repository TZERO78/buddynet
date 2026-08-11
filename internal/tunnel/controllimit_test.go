package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

// controlTestServer starts a control listener that echoes every request.
func controlTestServer(t *testing.T) (*ControlServer, *net.UDPAddr, ed25519.PublicKey) {
	t.Helper()
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	srvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := ListenControl(srvConn, srvPriv, 30*time.Second)
	if err != nil {
		srvConn.Close()
		t.Fatalf("ListenControl: %v", err)
	}
	t.Cleanup(func() { srv.Close(); srvConn.Close() })
	go func() {
		for {
			req, err := srv.Accept(context.Background())
			if err != nil {
				return
			}
			req.Reply([]byte("ok"))
		}
	}()
	return srv, srvConn.LocalAddr().(*net.UDPAddr), srvPriv.Public().(ed25519.PublicKey)
}

// openConns dials n control connections from fresh sockets and returns them.
func openConns(t *testing.T, srvAddr *net.UDPAddr, srvPub ed25519.PublicKey, n int) []*ControlClient {
	t.Helper()
	var out []*ControlClient
	for i := 0; i < n; i++ {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cli, err := DialControl(ctx, c, srvAddr, srvPub, priv, 30*time.Second)
		cancel()
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		// A connection only occupies a slot once the server has accepted it, and the
		// server counts it at accept time — so drive one request through to be sure
		// the accounting has happened before the next dial.
		rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = cli.Roundtrip(rctx, []byte("hi"))
		rcancel()
		if err != nil {
			cli.Close()
			t.Fatalf("roundtrip %d: %v", i, err)
		}
		out = append(out, cli)
	}
	return out
}

// One source may not hold more than maxCtrlConnsPerIP control connections, and
// the slots come back when those connections close.
func TestPerIPConnectionLimit(t *testing.T) {
	srv, srvAddr, srvPub := controlTestServer(t)

	clients := openConns(t, srvAddr, srvPub, maxCtrlConnsPerIP)
	srv.connMu.Lock()
	held := srv.perIP[ipKey(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})]
	srv.connMu.Unlock()
	if held != maxCtrlConnsPerIP {
		t.Fatalf("server counts %d connections from 127.0.0.1, want %d", held, maxCtrlConnsPerIP)
	}

	// One more from the same source must be refused: the dial may still complete
	// (the server closes it right after accepting), but no request gets served.
	extra, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if cli, derr := DialControl(ctx, extra, srvAddr, srvPub, priv, 30*time.Second); derr == nil {
		defer cli.Close()
		rctx, rcancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer rcancel()
		if resp, rerr := cli.Roundtrip(rctx, []byte("hi")); rerr == nil && len(resp) > 0 {
			t.Fatal("a connection past the per-source limit was served")
		}
	}

	// Closing the held connections must give every slot back.
	for _, c := range clients {
		c.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		srv.connMu.Lock()
		n := srv.conns
		srv.connMu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	srv.connMu.Lock()
	n, entries := srv.conns, len(srv.perIP)
	srv.connMu.Unlock()
	t.Fatalf("after closing every connection the server still holds %d slots (%d source entries) — slots leak", n, entries)
}

// The per-source limit must not starve other sources: with one source at its cap,
// a different source still gets served.
func TestOtherSourcesStillAdmittedAtPerIPCap(t *testing.T) {
	srv, srvAddr, srvPub := controlTestServer(t)
	defer srv.Close()

	clients := openConns(t, srvAddr, srvPub, maxCtrlConnsPerIP)
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()

	// A second loopback address is a distinct source for the accounting key.
	other, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
	if err != nil {
		t.Skipf("no second loopback address available: %v", err)
	}
	defer other.Close()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cli, err := DialControl(ctx, other, srvAddr, srvPub, priv, 30*time.Second)
	if err != nil {
		t.Fatalf("a different source was refused while another was at its cap: %v", err)
	}
	defer cli.Close()
	rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer rcancel()
	if _, err := cli.Roundtrip(rctx, []byte("hi")); err != nil {
		t.Fatalf("a different source was not served while another was at its cap: %v", err)
	}
}

// IPv4, IPv6 and IPv4-mapped IPv6 forms of one address must share a key,
// otherwise a peer doubles its allowance by switching representation.
func TestIPKeyNormalizesAddressFamilies(t *testing.T) {
	v4 := ipKey(&net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 1})
	mapped := ipKey(&net.UDPAddr{IP: net.ParseIP("::ffff:198.51.100.7"), Port: 2})
	if v4 != mapped {
		t.Fatalf("ipKey(v4)=%q but ipKey(v4-mapped)=%q — an IPv4-mapped source would get its own budget", v4, mapped)
	}
	if got := ipKey(&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 3}); got == v4 {
		t.Fatal("distinct addresses collapsed onto one key")
	}
	// The port must not be part of the key: the limit is per host.
	if a, b := ipKey(&net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 1}),
		ipKey(&net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 9999}); a != b {
		t.Fatalf("port affects the key: %q vs %q", a, b)
	}
}

// A connection that completes the handshake and then never opens a stream must
// be closed on the first-stream deadline, and its slot released.
func TestConnectionWithoutFirstStreamTimesOut(t *testing.T) {
	srv, srvAddr, srvPub := controlTestServer(t)

	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cli, err := DialControl(ctx, c, srvAddr, srvPub, priv, 30*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cli.Close()

	// The slot must first actually be TAKEN — otherwise "released" is trivially
	// true simply because the server has not accepted the connection yet.
	waitSlots(t, srv, 1, 5*time.Second)
	// Never open a stream. Well before the 30 s idle timeout, the slot must be gone.
	waitSlots(t, srv, 0, firstStreamTimeout+5*time.Second)
}

// A stream that dribbles bytes and never half-closes must hit the read deadline
// and be closed, rather than pinning a goroutine and a stream slot.
func TestIncompleteRequestTimesOut(t *testing.T) {
	_, srvAddr, srvPub := controlTestServer(t)

	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cli, err := DialControl(ctx, c, srvAddr, srvPub, priv, 30*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cli.Close()

	st, err := cli.conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("{partial")); err != nil {
		t.Fatal(err)
	}
	// Deliberately no Close(): the server must not wait forever for the rest.
	st.SetReadDeadline(time.Now().Add(controlReadTimeout + 5*time.Second))
	buf := make([]byte, 16)
	if _, err := st.Read(buf); err == nil {
		t.Fatal("an incomplete request was answered instead of being timed out")
	}
}

// slotsHeld reports the server's current global connection count.
func slotsHeld(s *ControlServer) int {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return s.conns
}

// waitSlots waits for the global counter to reach want.
func waitSlots(t *testing.T, s *ControlServer, want int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if slotsHeld(s) == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	s.connMu.Lock()
	got, entries := s.conns, len(s.perIP)
	s.connMu.Unlock()
	t.Fatalf("connection slots = %d (%d source entries), want %d — a slot leaked", got, entries, want)
}

// Every way a connection can end must give its slot back, and the per-source map
// must not retain an entry for a source with no live connections.
func TestSlotsAreReleasedOnEveryExitPath(t *testing.T) {
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	srvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srvConn.Close()
	srv, err := ListenControl(srvConn, srvPriv, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srvPub := srvPriv.Public().(ed25519.PublicKey)
	srvAddr := srvConn.LocalAddr().(*net.UDPAddr)

	// The handler drops the connection outright (the key-mismatch path in the
	// handshake server) instead of replying.
	drop := make(chan struct{}, 1)
	go func() {
		for {
			req, err := srv.Accept(context.Background())
			if err != nil {
				return
			}
			select {
			case <-drop:
				req.Drop("test drop")
			default:
				req.Reply([]byte("ok"))
			}
		}
	}()

	dial := func() *ControlClient {
		t.Helper()
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cli, err := DialControl(ctx, c, srvAddr, srvPub, priv, 30*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		return cli
	}
	roundtrip := func(cli *ControlClient) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cli.Roundtrip(ctx, []byte("hi")) //nolint:errcheck // the outcome differs per path; the slot is what matters
	}

	t.Run("client closes cleanly", func(t *testing.T) {
		cli := dial()
		roundtrip(cli)
		waitSlots(t, srv, 1, 5*time.Second)
		cli.Close()
		waitSlots(t, srv, 0, 5*time.Second)
	})

	t.Run("server drops the connection", func(t *testing.T) {
		cli := dial()
		defer cli.Close()
		drop <- struct{}{}
		roundtrip(cli) // reaching the handler proves the slot was taken
		waitSlots(t, srv, 0, 5*time.Second)
	})

	t.Run("no first stream", func(t *testing.T) {
		cli := dial()
		defer cli.Close()
		// Wait for the slot to actually be TAKEN first — otherwise "released" is
		// trivially true because the server has not accepted the connection yet.
		waitSlots(t, srv, 1, 5*time.Second)
		waitSlots(t, srv, 0, firstStreamTimeout+5*time.Second)
	})

	t.Run("incomplete request", func(t *testing.T) {
		cli := dial()
		defer cli.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		st, err := cli.conn.OpenStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		st.Write([]byte("{partial")) //nolint:errcheck // deliberately never completed
		waitSlots(t, srv, 1, 5*time.Second)
		cli.Close()
		waitSlots(t, srv, 0, 5*time.Second)
	})

	// After everything, the per-source map must be empty too — entries are keyed by
	// source and would otherwise accumulate one per address forever.
	srv.connMu.Lock()
	entries := len(srv.perIP)
	srv.connMu.Unlock()
	if entries != 0 {
		t.Fatalf("per-source map still holds %d entries with no live connections", entries)
	}
}

// A REFUSED connection must not consume a slot: the counters are taken only on
// admission, so shedding load may never itself exhaust the table.
func TestRefusedConnectionConsumesNoSlot(t *testing.T) {
	srv, srvAddr, srvPub := controlTestServer(t)

	clients := openConns(t, srvAddr, srvPub, maxCtrlConnsPerIP)
	before := slotsHeld(srv)
	if before != maxCtrlConnsPerIP {
		t.Fatalf("held %d slots, want %d", before, maxCtrlConnsPerIP)
	}
	// Several refusals in a row.
	for i := 0; i < 5; i++ {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if cli, derr := DialControl(ctx, c, srvAddr, srvPub, priv, 30*time.Second); derr == nil {
			rctx, rcancel := context.WithTimeout(context.Background(), 2*time.Second)
			cli.Roundtrip(rctx, []byte("hi")) //nolint:errcheck // expected to be refused
			rcancel()
			cli.Close()
		}
		cancel()
		c.Close()
	}
	if after := slotsHeld(srv); after != before {
		t.Fatalf("refused connections changed the slot count: %d -> %d", before, after)
	}
	for _, c := range clients {
		c.Close()
	}
	waitSlots(t, srv, 0, 5*time.Second)
}

// Ordinary polling — many sequential requests on ONE connection — must keep
// working; the deadlines are per request, not per connection.
func TestPollingOverOneConnectionStillWorks(t *testing.T) {
	_, srvAddr, srvPub := controlTestServer(t)

	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cli, err := DialControl(ctx, c, srvAddr, srvPub, priv, 30*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cli.Close()

	for i := 0; i < 12; i++ {
		rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
		resp, err := cli.Roundtrip(rctx, []byte("poll"))
		rcancel()
		if err != nil || string(resp) != "ok" {
			t.Fatalf("poll %d failed: resp=%q err=%v", i, resp, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
