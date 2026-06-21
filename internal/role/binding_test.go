package role

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"
)

// link is an in-memory message transport for the binding exchange in tests.
type link struct {
	in  chan []byte
	out chan []byte
}

func newPair() (a, b *link) {
	ab := make(chan []byte, 4)
	ba := make(chan []byte, 4)
	return &link{in: ba, out: ab}, &link{in: ab, out: ba}
}

func (l *link) send(b []byte) error {
	cp := append([]byte(nil), b...)
	l.out <- cp
	return nil
}

func (l *link) recv() ([]byte, error) {
	select {
	case b := <-l.in:
		return b, nil
	case <-time.After(2 * time.Second):
		return nil, errTimeout
	}
}

var errTimeout = &timeoutErr{}

type timeoutErr struct{}

func (*timeoutErr) Error() string { return "recv timeout" }

func runBoth(t *testing.T, a, b *link) (sidA, sidB []byte) {
	t.Helper()
	type res struct {
		sid []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		sid, err := runBinding(false, b.send, b.recv) // initiator
		ch <- res{sid, err}
	}()
	sidA, errA := runBinding(true, a.send, a.recv) // committer
	if errA != nil {
		t.Fatalf("committer: %v", errA)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("initiator: %v", r.err)
	}
	return sidA, r.sid
}

func TestBindingHappyPathAgrees(t *testing.T) {
	a, b := newPair()
	sidA, sidB := runBoth(t, a, b)
	if !bytes.Equal(sidA, sidB) {
		t.Fatalf("session bindings differ:\n a=%x\n b=%x", sidA, sidB)
	}
	// Fed into ComputeSAS, both ends must show the same SAS.
	pubA, _, _ := ed25519.GenerateKey(nil)
	pubB, _, _ := ed25519.GenerateKey(nil)
	if ComputeSAS(pubA, pubB, sidA) != ComputeSAS(pubB, pubA, sidB) {
		t.Fatal("SAS mismatch on identical binding")
	}
}

// A MITM terminates two SEPARATE exchanges (one with each side); the two ends
// derive different bindings → different SAS → humans catch it.
func TestBindingMITMProducesDifferentSAS(t *testing.T) {
	// Alice <-> attacker
	aliceL, attackerToAlice := newPair()
	// attacker <-> Bob
	attackerToBob, bobL := newPair()

	type res struct{ sid []byte }
	aliceCh := make(chan res, 1)
	bobCh := make(chan res, 1)
	// Alice is committer on her leg; Bob is initiator on his leg.
	go func() { sid, _ := runBinding(true, aliceL.send, aliceL.recv); aliceCh <- res{sid} }()
	go func() { sid, _ := runBinding(false, bobL.send, bobL.recv); bobCh <- res{sid} }()
	// Attacker plays initiator toward Alice and committer toward Bob.
	go func() { _, _ = runBinding(false, attackerToAlice.send, attackerToAlice.recv) }()
	go func() { _, _ = runBinding(true, attackerToBob.send, attackerToBob.recv) }()

	sidAlice := (<-aliceCh).sid
	sidBob := (<-bobCh).sid
	if sidAlice == nil || sidBob == nil {
		t.Fatal("a leg failed to complete")
	}
	if bytes.Equal(sidAlice, sidBob) {
		t.Fatal("MITM went undetected: bindings matched across two exchanges")
	}
	pubA, _, _ := ed25519.GenerateKey(nil)
	pubB, _, _ := ed25519.GenerateKey(nil)
	if ComputeSAS(pubA, pubB, sidAlice) == ComputeSAS(pubA, pubB, sidBob) {
		t.Fatal("MITM went undetected: SAS matched")
	}
}

// A tampered ephemeral reveal (not matching the commitment) must be rejected.
func TestBindingCommitmentMismatchRejected(t *testing.T) {
	a, b := newPair()
	errCh := make(chan error, 1)
	go func() {
		_, err := runBinding(false, b.send, b.recv) // initiator verifies commitment
		errCh <- err
	}()

	// Play a malicious committer by hand: send a commit, then reveal a DIFFERENT
	// ephemeral key than the one committed to.
	commit := sha256.Sum256([]byte("committed-key-placeholder-32byte"))
	_ = a.send(commit[:])
	_, _ = a.recv() // initiator's ephemeral
	var bogus [32]byte
	bogus[0] = 0xAA
	_ = a.send(bogus[:]) // does not hash to commit

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("initiator accepted a reveal that did not match the commitment")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("initiator did not return")
	}
}
