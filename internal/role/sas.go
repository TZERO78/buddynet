package role

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// ErrSASRejected is returned when the human explicitly said the SAS did NOT
// match — a positive attack signal (MITM or token theft). ErrSASTimeout is
// returned when no answer arrived in time, which is ambiguous (the user may just
// be away). Either way the partner key is NOT trusted and the connection drops;
// they differ only in how loudly the event is logged.
var (
	ErrSASRejected = errors.New("SAS rejected (mismatch)")
	ErrSASTimeout  = errors.New("SAS not confirmed in time")
)

// sasLabel is the RFC 5705 exporter label binding the SAS to this TLS session.
const sasLabel = "buddynet-sas-v1"

// sasAlphabet is Crockford base32 — digits and letters with the easily confused
// I, L, O and U removed, so a 6-character code is unambiguous to read aloud or
// type. 32 symbols = 5 bits each; 6 symbols = 30 bits of agreement.
const sasAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// sasDigest hashes both identities (in a fixed order, so both ends agree) plus a
// per-session binding value (sessionID). sessionID is the TLS exported keying
// material on the QUIC path and the ephemeral-DH binding from runBinding on the
// WireGuard path; either way it ties the digest to THIS connection, so a man in
// the middle — who establishes a different session/binding to each side — makes
// the two ends derive different digests and their SAS will not match.
func sasDigest(myPub, peerPub ed25519.PublicKey, sessionID []byte) [sha256.Size]byte {
	a, b := []byte(myPub), []byte(peerPub)
	if bytes.Compare(a, b) > 0 {
		a, b = b, a
	}
	h := sha256.New()
	h.Write(a)
	h.Write(b)
	h.Write(sessionID)
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// ComputeSAS returns the six-character Short Authentication String for a pair of
// identities over a session, e.g. "K7QX2M". Both peers compute the identical
// code (the keys are sorted, and sessionID is symmetric channel binding), so the
// humans read it out and compare. Six Crockford-base32 symbols is 30 bits — a
// man in the middle cannot feasibly force a match.
func ComputeSAS(myPub, peerPub ed25519.PublicKey, sessionID []byte) string {
	sum := sasDigest(myPub, peerPub, sessionID)
	// Use the top 30 bits of the first four digest bytes.
	v := uint32(sum[0])<<24 | uint32(sum[1])<<16 | uint32(sum[2])<<8 | uint32(sum[3])
	var out [6]byte
	for i := 5; i >= 0; i-- {
		out[i] = sasAlphabet[v&31]
		v >>= 5
	}
	return string(out[:])
}

// PromptSAS shows the safety check and waits for the human to confirm the SAS
// matches their buddy's. Anything other than an explicit yes — including no
// answer within timeout — is treated as a mismatch and returns ErrSASRejected,
// so a silent/automated context never blindly trusts a new key. It reads from
// stdin and writes the prompt to stderr (so a piped stdout stays clean).
func PromptSAS(sas string, timeout time.Duration) error {
	fmt.Fprintf(os.Stderr, `
🔑 Safety check — first contact with this buddy.
   Read this code to your buddy over a trusted channel (phone, Signal) and check
   it matches what THEY see. If it differs, someone may be in the middle — abort.

        %s

   Confirm only if BOTH sides show the SAME code.
   No answer within %s counts as a mismatch (abort).
Do they match? [y/N] `, sas, timeout)

	return readSASConfirmation(timeout)
}

// readSASConfirmation reads one line of confirmation from stdin within timeout.
// It prefers a read deadline, so the read itself unblocks on timeout and no
// reader goroutine can outlive the call. On a stdin that does not support
// deadlines (a regular-file redirect) it falls back to a background reader —
// there the read returns promptly (data or EOF) anyway, so nothing leaks.
func readSASConfirmation(timeout time.Duration) error {
	if err := os.Stdin.SetReadDeadline(time.Now().Add(timeout)); err == nil {
		defer os.Stdin.SetReadDeadline(time.Time{})
		line, rerr := bufio.NewReader(os.Stdin).ReadString('\n')
		if rerr != nil {
			if errors.Is(rerr, os.ErrDeadlineExceeded) {
				fmt.Fprintln(os.Stderr, "\n⏰ no answer — aborting (key NOT trusted).")
				return ErrSASTimeout
			}
			return ErrSASRejected
		}
		return decideSAS(line)
	}

	// Fallback path (stdin has no deadline support, e.g. `buddynet ... < file`).
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	stdin := os.Stdin
	go func() {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		ch <- result{line, err}
	}()
	select {
	case <-time.After(timeout):
		fmt.Fprintln(os.Stderr, "\n⏰ no answer — aborting (key NOT trusted).")
		return ErrSASTimeout
	case r := <-ch:
		if r.err != nil {
			return ErrSASRejected
		}
		return decideSAS(r.line)
	}
}

// decideSAS maps a human's answer line to the trust decision: an explicit yes
// trusts the key, anything else (including blank) refuses it.
func decideSAS(line string) error {
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	default:
		fmt.Fprintln(os.Stderr, "aborted — key NOT trusted.")
		return ErrSASRejected
	}
}
