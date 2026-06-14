// Package secret holds shared helpers for generating and safely displaying
// pairing tokens and session tokens, used across the buddynet roles.
package secret

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// NewToken returns a fresh 384-bit pairing token as a 64-char base64url string
// (no padding; URL- and shell-safe). 384 bits is far beyond brute force even if
// the token travels over a weak channel.
func NewToken() (string, error) {
	var b [48]byte // 48 bytes -> exactly 64 base64url chars
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// NewSessionToken returns a short-lived 128-bit token used to pair the two legs
// of a relayed session. It need only be unguessable for the lifetime of one
// connection, so 128 bits is ample.
func NewSessionToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Interactive reports whether both stdout and stdin are a terminal, i.e. a human
// is watching. When false (piped/redirected) callers should print the secret
// plainly so `TOKEN=$(... gen-token)` keeps working.
func Interactive() bool {
	return term.IsTerminal(int(os.Stdout.Fd())) && term.IsTerminal(int(os.Stdin.Fd()))
}

// RevealUntilKey shows secret on the terminal (stderr), waits for a single
// keypress, then erases the secret from the screen so it doesn't linger on
// screen or in scrollback. It assumes Interactive() is true.
func RevealUntilKey(secret string) {
	block := fmt.Sprintf("\n    %s\n\nPress any key to hide it… ", secret)
	fmt.Fprint(os.Stderr, block)
	waitKey()
	up := strings.Count(block, "\n")
	fmt.Fprintf(os.Stderr, "\r\033[%dA\033[J", up)
}

// waitKey blocks until one keypress. It puts the terminal in raw mode so any
// key (not just Enter) ends the wait; on failure it falls back to reading a
// line (Enter).
func waitKey() {
	fd := int(os.Stdin.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		var b [1]byte
		os.Stdin.Read(b[:]) // best-effort: wait for Enter
		return
	}
	defer term.Restore(fd, old)
	var b [1]byte
	os.Stdin.Read(b[:])
}
