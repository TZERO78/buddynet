package role

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
)

// inProcHandshake runs a real matchmaking server (the production handleRegister
// path) on loopback and returns its address and the base64 server key to pin.
func inProcHandshake(t *testing.T) (addr, serverKeyB64 string) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("handshake listen: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	reg := newHSRegistry(time.Minute)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			raw := make([]byte, n)
			copy(raw, buf[:n])
			handleRegister(conn, reg, priv, nil, "", src, raw)
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return conn.LocalAddr().String(), bcrypto.PubKeyB64(pub)
}

func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()
	return ln.Addr().String()
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// TestTunnelEndToEnd runs the whole buddy path over loopback: two buddies find
// each other via a real handshake server, hole-punch, bring up QUIC, and forward
// a byte stream through to an echo server on the far side.
func TestTunnelEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network end-to-end test in -short mode")
	}
	srvAddr, srvKey := inProcHandshake(t)
	echoAddr := echoServer(t)
	lAddr := freeTCPAddr(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const token = "test-token"
	// The handshake replies only to the sender, so the two buddies start punching
	// up to ~1s apart (the first registrant learns its partner only on the next
	// poll). Use a punch window wide enough that the two windows overlap.
	base := BuddyConfig{
		Server: srvAddr, ServerKey: srvKey, Token: token,
		Insecure: true, PunchDur: 3 * time.Second, IdleTimeout: 60 * time.Second,
	}
	// A forwards incoming streams to the echo server; B exposes the local port.
	cfgA := base
	cfgA.Forward = echoAddr
	cfgB := base
	cfgB.LocalListen = lAddr
	go Buddy(ctx, cfgA)
	go Buddy(ctx, cfgB)

	// Wait for the tunnel to come up, then echo a payload through it.
	payload := []byte("buddynet end-to-end hello\n")
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		c, err := net.Dial("tcp", lAddr)
		if err != nil {
			lastErr = err
			continue
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write(payload); err != nil {
			lastErr = err
			c.Close()
			continue
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(c, got); err != nil {
			lastErr = err
			c.Close()
			continue
		}
		c.Close()
		if string(got) != string(payload) {
			t.Fatalf("echo mismatch: got %q want %q", got, payload)
		}
		return // success
	}
	t.Fatalf("tunnel did not carry data within deadline; last error: %v", lastErr)
}
