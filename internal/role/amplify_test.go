package role

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

// The address-validation challenge must never be larger than the datagram that
// triggered it. The documentation states that as an absolute, and the old code
// only satisfied it for REALISTIC requests: the parser also accepts a 40-byte
// REGISTER, which drew a 59-byte reply — 1.48x, or 1.28x once IP/UDP headers are
// counted. Small, and the per-source rate limit bounds it further, but an
// absolute claim has to hold absolutely.
//
// The test drives the SMALLEST request the parser accepts, which is exactly what
// the previous tests did not: they used a full registration and compared against
// that, so the property looked safe.
func TestCookieChallengeIsNeverAnAmplifier(t *testing.T) {
	_, srvPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cookieKey = deriveSubkey(srvPriv.Seed(), "buddynet-cookie-v1")

	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	src := cli.LocalAddr().(*net.UDPAddr)

	// The smallest datagram parseRegister accepts. Kept as a literal on purpose: if
	// a future change makes the parser accept something even smaller, this test
	// still measures the OLD minimum and the property could silently rot — so the
	// assertion below re-checks acceptance too.
	minimal := []byte(`{"type":"REGISTER","token":"x","id":"x"}`)
	if _, ok := parseRegister(minimal); !ok {
		t.Fatalf("the assumed minimal request is no longer accepted by the parser: %s", minimal)
	}

	sendCookie(srv, src, len(minimal))
	cli.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := cli.Read(make([]byte, 1500)); err == nil {
		t.Errorf("a %d-byte request drew a %d-byte reply — the challenge is an amplifier",
			len(minimal), n)
	}

	// Positive control: a real registration is still challenged, or the gate would
	// have broken address validation instead of fixing amplification.
	nd, _ := testNode(t)
	real := mustBuild(t, nd, "")
	sendCookie(srv, src, len(real))
	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := cli.Read(make([]byte, 1500))
	if err != nil {
		t.Fatalf("a legitimate %d-byte registration drew no challenge: %v", len(real), err)
	}
	if n >= len(real) {
		t.Errorf("challenge %d bytes vs request %d bytes — not strictly smaller", n, len(real))
	}
}
