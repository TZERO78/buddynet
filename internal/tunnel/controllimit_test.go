package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/tzero78/buddynet/internal/safe"
)

// controlTestServer starts a control listener that echoes every request.
func controlTestServer(t *testing.T) (*ControlServer, *net.UDPAddr, ed25519.PublicKey) {
	t.Helper()
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	srvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := ListenControl(srvConn, srvPriv, 30*time.Second, nil)
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
	// Assert the SERVER acted, not merely that no answer arrived: "no answer" is
	// equally true when the server hangs forever, which is exactly what this test
	// is supposed to rule out. When the read deadline fires, the server closes its
	// end and the client sees EOF / a stream error; when it hangs, the client only
	// ever hits its OWN deadline.
	st.SetReadDeadline(time.Now().Add(controlReadTimeout + 5*time.Second))
	buf := make([]byte, 16)
	_, err = st.Read(buf)
	if err == nil {
		t.Fatal("an incomplete request was answered instead of being timed out")
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the CLIENT's deadline fired first (%v) — the server never closed the "+
			"incomplete request, so the goroutine and stream slot are still pinned", err)
	}
}

// The request size limit must REJECT, not truncate. io.LimitReader reports clean
// EOF at exactly the limit, so an oversize request used to have its prefix served:
// valid JSON padded with whitespace up to maxControlReq, followed by more bytes
// and no half-close, was answered while the client kept sending.
func TestOversizeRequestIsRejectedNotTruncated(t *testing.T) {
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	srvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srvConn.Close()
	srv, err := ListenControl(srvConn, srvPriv, 30*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	served := make(chan int, 2)
	go func() {
		for {
			req, aerr := srv.Accept(context.Background())
			if aerr != nil {
				return
			}
			served <- len(req.Payload)
			req.Reply([]byte("ok"))
		}
	}()

	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cli, err := DialControl(ctx, c, srvConn.LocalAddr().(*net.UDPAddr), srvPriv.Public().(ed25519.PublicKey), priv, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	body := `{"type":"REGISTER","token":"x","id":"x"}`
	over := body + strings.Repeat(" ", maxControlReq-len(body)) + strings.Repeat("A", 4096)
	st, err := cli.conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte(over)); err != nil {
		t.Fatal(err)
	}
	// No Close(): the send side stays open, so a size check can still fire.
	select {
	case n := <-served:
		t.Fatalf("an oversize request (%d bytes, limit %d) was truncated to %d and served",
			len(over), maxControlReq, n)
	case <-time.After(controlReadTimeout + 3*time.Second):
	}

	// Positive control: a request AT the limit is still served, so the fix rejects
	// oversize rather than everything near it.
	atLimit := body + strings.Repeat(" ", maxControlReq-len(body))
	st2, err := cli.conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st2.Write([]byte(atLimit)); err != nil {
		t.Fatal(err)
	}
	st2.Close()
	select {
	case n := <-served:
		if n != maxControlReq {
			t.Fatalf("request at the limit arrived as %d bytes, want %d", n, maxControlReq)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a request at exactly the limit was not served — the gate is too strict")
	}
}

// Accounting per EXACT IPv6 address is free money for an attacker: one /64 is the
// smallest block a site is handed, so a single host could mint
// maxCtrlConns/maxCtrlConnsPerIP distinct "sources" out of it and fill the global
// table. Aggregating to /64 takes that away.
//
// It does NOT make the table unfillable: a residential /56 or /48 contains 256
// resp. 65536 distinct /64s, so a determined attacker still has enough prefixes.
// Closing that needs eviction under pressure (the way hsRegistry.evictStalestLocked
// handles the same problem for token buckets) rather than a wider prefix — see
// docs/plans/audit-v4-followup.md. What this test pins is that the CHEAPEST
// version of the attack, one prefix, is gone.
func TestOneIPv6PrefixCannotFillTheGlobalTable(t *testing.T) {
	s := &ControlServer{perIP: map[string]int{}}
	admitted := 0
	for host := 1; host <= maxCtrlConns; host++ {
		addr := &net.UDPAddr{IP: net.ParseIP(fmt.Sprintf("2001:db8::%x", host)), Port: 1000}
		if _, ok := s.admit(addr); ok {
			admitted++
		}
	}
	if admitted > maxCtrlConnsPerIP {
		t.Fatalf("one /64 was admitted %d times, want at most %d — IPv6 is accounted per address again",
			admitted, maxCtrlConnsPerIP)
	}
	// A buddy from a different prefix is unaffected.
	if _, ok := s.admit(&net.UDPAddr{IP: net.ParseIP("2001:db8:1::9"), Port: 1}); !ok {
		t.Fatal("a source in another /64 was locked out by the first one")
	}
}

// The /64 aggregation must be real: two addresses in one prefix share a budget,
// two prefixes do not, and IPv4 stays per address.
func TestIPv6IsAccountedPerPrefix(t *testing.T) {
	a := ipKey(&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1})
	b := ipKey(&net.UDPAddr{IP: net.ParseIP("2001:db8::dead:beef"), Port: 2})
	if a != b {
		t.Fatalf("addresses in one /64 must share a key: %q vs %q", a, b)
	}
	if other := ipKey(&net.UDPAddr{IP: net.ParseIP("2001:db8:1::1"), Port: 1}); other == a {
		t.Fatalf("a different /64 must NOT share the key %q", a)
	}
	v4a := ipKey(&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1})
	v4b := ipKey(&net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 1})
	if v4a == v4b {
		t.Fatal("IPv4 must stay accounted per address")
	}
}

// setConnHandler installs (or clears) the per-connection handler override under
// the server's own lock — acceptConns reads it from another goroutine.
func setConnHandler(s *ControlServer, h func(*ControlServer, *quic.Conn)) {
	s.connMu.Lock()
	s.handler = h
	s.connMu.Unlock()
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
	srv, err := ListenControl(srvConn, srvPriv, 30*time.Second, nil)
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

// A panic in the per-connection goroutine — which parses an attacker-supplied
// certificate chain — must cost that connection and nothing else: the process
// survives, the slot is released, and the server keeps serving other clients.
func TestPanicInConnectionHandlerIsContained(t *testing.T) {
	srv, srvAddr, srvPub := controlTestServer(t)

	// A one-shot latch: ONLY the first connection blows up. (A buffered channel
	// would not do — draining it below would re-arm the panic for the follow-up
	// connection, and the test would hang instead of proving anything.)
	var armed atomic.Bool
	armed.Store(true)
	panicked := make(chan struct{}, 1)
	setConnHandler(srv, func(s *ControlServer, qc *quic.Conn) {
		if armed.CompareAndSwap(true, false) {
			panicked <- struct{}{}
			panic("crafted connection")
		}
		s.acceptStreams(qc)
	})
	t.Cleanup(func() { setConnHandler(srv, nil) })

	before := safe.PanicCount()

	// A connection that makes the handler blow up.
	boom, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer boom.Close()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	cli, err := DialControl(ctx, boom, srvAddr, srvPub, priv, 30*time.Second)
	cancel()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cli.Close()

	select {
	case <-panicked:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never ran")
	}

	// Reaching this line at all means the process survived the panic.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && safe.PanicCount() == before {
		time.Sleep(50 * time.Millisecond)
	}
	if safe.PanicCount() <= before {
		t.Fatal("the panic was not recovered and counted by safe.Do")
	}

	// The slot must be back — release() is deferred ahead of the recovery.
	waitSlots(t, srv, 0, 5*time.Second)

	// And the server must still serve the NEXT client normally.
	next, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	cli2, err := DialControl(ctx2, next, srvAddr, srvPub, priv2, 30*time.Second)
	if err != nil {
		t.Fatalf("the server stopped accepting after a panicking connection: %v", err)
	}
	defer cli2.Close()
	if resp, rerr := cli2.Roundtrip(ctx2, []byte("hi")); rerr != nil || string(resp) != "ok" {
		t.Fatalf("the server stopped serving after a panicking connection: resp=%q err=%v", resp, rerr)
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
