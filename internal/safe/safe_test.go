package safe

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

// captureLog redirects the stdlib logger to a buffer for the duration of fn.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	old := log.Writer()
	flags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() { log.SetOutput(old); log.SetFlags(flags) }()
	fn()
	return buf.String()
}

// resetState clears the package throttle/counter so tests don't bleed into each
// other (the counter is process-global by design).
func resetState() {
	mu.Lock()
	lastLogged = map[string]time.Time{}
	mu.Unlock()
	panicCount.Store(0)
}

func TestDoRecoversAndReports(t *testing.T) {
	resetState()
	out := captureLog(t, func() {
		ok := Do("test.boom", func() { panic("kaboom") })
		if ok {
			t.Fatal("Do must report ok=false when fn panics")
		}
	})
	if PanicCount() != 1 {
		t.Fatalf("PanicCount = %d, want 1", PanicCount())
	}
	if !strings.Contains(out, "SECURITY: event=panic-recovered component=test.boom") {
		t.Fatalf("missing structured SECURITY line, got: %q", out)
	}
	if !strings.Contains(out, "kaboom") {
		t.Fatalf("panic value not in log: %q", out)
	}
}

func TestDoNormalCompletion(t *testing.T) {
	resetState()
	ran := false
	out := captureLog(t, func() {
		if ok := Do("test.ok", func() { ran = true }); !ok {
			t.Fatal("Do must report ok=true on normal completion")
		}
	})
	if !ran {
		t.Fatal("fn did not run")
	}
	if PanicCount() != 0 || out != "" {
		t.Fatalf("normal path must not log or count: count=%d log=%q", PanicCount(), out)
	}
}

// A reliably-triggerable panic must NOT flood the log: the same component logs at
// most once per throttle window, while the counter still records every panic.
func TestPanicLogIsThrottled(t *testing.T) {
	resetState()
	out := captureLog(t, func() {
		for i := 0; i < 100; i++ {
			Do("test.flood", func() { panic("again") })
		}
	})
	if PanicCount() != 100 {
		t.Fatalf("PanicCount = %d, want 100 (every panic counted)", PanicCount())
	}
	if n := strings.Count(out, "panic-recovered"); n != 1 {
		t.Fatalf("throttle failed: %d log lines, want 1", n)
	}
}

func TestGoRecovers(t *testing.T) {
	resetState()
	// Go must not let the panic escape its goroutine (which would crash the test
	// binary). We confirm the program survives and the panic is counted; the
	// counter is atomic, so polling it is race-safe (unlike the shared log buffer,
	// which the recover goroutine writes concurrently).
	Go("test.go", func() { panic("async") })
	deadline := time.Now().Add(2 * time.Second)
	for PanicCount() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("Go did not recover+count the async panic (count=%d)", PanicCount())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestOnelineSanitizes(t *testing.T) {
	got := oneline("line1\nline2\r\tend")
	if strings.ContainsAny(got, "\n\r\t") {
		t.Fatalf("oneline left control chars: %q", got)
	}
	long := oneline(strings.Repeat("x", 500))
	if len([]rune(long)) > 201 { // 200 + the ellipsis rune
		t.Fatalf("oneline did not cap length: %d runes", len([]rune(long)))
	}
}
