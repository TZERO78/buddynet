package relay

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

// A session id on a refusal path is attacker-supplied. ParseBind now keeps
// control characters out, but the log line must not depend on that: whatever
// reaches rejectTicket is written escaped, so one datagram can never add a
// line to the relay's log (2026-09-15 audit, BN-05).
func TestRejectTicketEscapesUnverifiedSessionID(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	s := New(Config{TTL: time.Minute})
	s.rejectTicket(reasonNoTicket, "\nFAKE\nXX"+strings.Repeat("a", 20), "\x1b[2J", nil)

	out := buf.String()
	if n := strings.Count(out, "\n"); n != 1 {
		t.Fatalf("refusal wrote %d line breaks, want exactly one:\n%q", n, out)
	}
	if strings.ContainsRune(out, 0x1b) {
		t.Fatalf("refusal wrote a raw escape byte: %q", out)
	}
	if !strings.Contains(out, `sid="\nFAKE\nXX" leg="\x1b[2J"`) {
		t.Fatalf("expected the escaped, truncated sid and leg in the line: %q", out)
	}
}
