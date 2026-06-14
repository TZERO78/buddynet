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

// ErrSASRejected is returned when the human did not confirm the Short
// Authentication String (mismatch, explicit no, or timeout). The partner key is
// then NOT trusted and the connection is dropped.
var ErrSASRejected = errors.New("SAS not confirmed")

// sasLabel is the RFC 5705 exporter label binding the SAS to this TLS session.
const sasLabel = "buddynet-sas-v1"

// sasAlphabet is Crockford base32 — digits and letters with the easily confused
// I, L, O and U removed, so a 6-character code is unambiguous to read aloud or
// type. 32 symbols = 5 bits each; 6 symbols = 30 bits of agreement.
const sasAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// sasDigest hashes both identities (in a fixed order, so both ends agree) plus a
// per-session binding value. With sessionID = the TLS exported keying material,
// the digest is tied to THIS QUIC session: a man in the middle terminates a
// different TLS session to each side, so the two ends derive different digests
// and their SAS will not match.
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

	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	stdin := os.Stdin // capture once; the reader goroutine may outlive a timeout
	go func() {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		ch <- result{line, err}
	}()

	select {
	case <-time.After(timeout):
		fmt.Fprintln(os.Stderr, "\n⏰ no answer — treating as MISMATCH, aborting (key NOT trusted).")
		return ErrSASRejected
	case r := <-ch:
		if r.err != nil {
			return ErrSASRejected
		}
		switch strings.ToLower(strings.TrimSpace(r.line)) {
		case "y", "yes":
			return nil
		default:
			fmt.Fprintln(os.Stderr, "aborted — key NOT trusted.")
			return ErrSASRejected
		}
	}
}
