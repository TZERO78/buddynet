package role

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	bcrypto "github.com/tzero78/buddynet/internal/crypto"
	"github.com/tzero78/buddynet/internal/invite"
)

// captureStderr runs fn with stderr redirected and returns everything it wrote.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, rerr := r.Read(buf)
			b.Write(buf[:n])
			if rerr != nil {
				break
			}
		}
		done <- b.String()
	}()
	fn()
	os.Stderr = old
	w.Close()
	out := <-done
	r.Close()
	return out
}

// The blind prompt is the whole point of the key-bound invite on the inviter's
// side: it must NOT print the code it expects. If it did, the lazy human could
// type what is on their own screen and confirm an unverified key without ever
// calling their buddy — which is exactly what a man in the middle needs, since
// under an attack each side sees a code that matches only its own screen.
func TestPromptSASBlindNeverShowsTheCode(t *testing.T) {
	const sas = "K7QX2M"
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	out := captureStderr(t, func() {
		r, w, _ := os.Pipe()
		os.Stdin = r
		go func() { w.WriteString(sas + "\n"); w.Close() }()
		if err := PromptSASBlind(sas, 2*time.Second); err != nil {
			t.Errorf("correct code should confirm, got %v", err)
		}
	})
	if strings.Contains(out, sas) {
		t.Fatalf("the blind prompt leaked the expected code %q — a human could copy it off their own screen instead of hearing it from their buddy:\n%s", sas, out)
	}

	// Same verification strength as the symmetric prompt: a wrong code, a bare
	// confirmation and a timeout all leave the key untrusted.
	for _, tc := range []struct {
		name, input string
		want        error
	}{
		{"wrong code", "AAAAAA\n", ErrSASRejected},
		{"bare yes", "yes\n", ErrSASRejected},
		{"blank", "\n", ErrSASRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			captureStderr(t, func() {
				r, w, _ := os.Pipe()
				os.Stdin = r
				go func() { w.WriteString(tc.input); w.Close() }()
				if err := PromptSASBlind(sas, 2*time.Second); err != tc.want {
					t.Errorf("PromptSASBlind(%q) = %v, want %v", tc.input, err, tc.want)
				}
			})
		})
	}

	t.Run("timeout", func(t *testing.T) {
		captureStderr(t, func() {
			r, w, _ := os.Pipe()
			os.Stdin = r
			defer w.Close()
			if err := PromptSASBlind(sas, 100*time.Millisecond); err != ErrSASTimeout {
				t.Error("a timeout must not confirm")
			}
		})
	})
}

// The joining side displays its code and returns — it must never block waiting
// for input, because there is no human step on that end at all (the inviter was
// pinned from the blob). A blocking display would hang an unattended joiner.
func TestShowSASDisplaysAndReturns(t *testing.T) {
	const sas = "K7QX2M"
	done := make(chan string, 1)
	go func() { done <- captureStderr(t, func() { ShowSAS(sas) }) }()
	select {
	case out := <-done:
		if !strings.Contains(out, sas) {
			t.Fatalf("ShowSAS did not print the code the buddy has to type:\n%s", out)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ShowSAS blocked — the joining side must not wait for a human")
	}
}

// The end-to-end shape of a key-bound invite: two real buddies pair over the
// in-process handshake server, and exactly ONE human step happens — on the
// inviter, blind. The joiner pinned the inviter from the invite blob, so it only
// displays its code and never prompts.
//
// This is the asymmetry the whole design rests on. If the joiner also prompted,
// both ends would be showing and typing the same code, and a human could satisfy
// either side from their own screen.
func TestKeyBoundInvitePairsAsymmetrically(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in -short mode")
	}
	srvAddr, srvKey := inProcHandshake(t)
	dir := t.TempDir()
	knownA := filepath.Join(dir, "a-known_peers")
	knownB := filepath.Join(dir, "b-known_peers")

	var prompts, blindPrompts, shows atomic.Int32
	savedPrompt, savedShow := promptSAS, showSAS
	promptSAS = func(_ string, blind bool, _ time.Duration) error {
		prompts.Add(1)
		if blind {
			blindPrompts.Add(1)
		}
		return nil // the human typed the right code
	}
	showSAS = func(string) { shows.Add(1) }
	t.Cleanup(func() { promptSAS, showSAS = savedPrompt, savedShow })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const token = "invite-blob-token"
	a := buddySide(t, srvKey, knownA, filepath.Join(dir, "a-peers.json"))
	b := buddySide(t, srvKey, knownB, filepath.Join(dir, "b-peers.json"))

	// What the invite blob does on the joining side: B pins A's key before it
	// ever hears from the server.
	aPub, err := bcrypto.DecodePubKey(a.pub)
	if err != nil {
		t.Fatal(err)
	}
	b.trust.pinned = aPub

	base := BuddyConfig{
		Server: srvAddr, ServerKey: srvKey, Token: token,
		PunchDur: 3 * time.Second, IdleTimeout: 60 * time.Second,
		Interactive: true, SASTimeout: 10 * time.Second,
	}
	cfgA := base // inviter: verifies, blind
	cfgA.Inviting = true
	cfgA.KnownPeers = knownA
	cfgA.PeersPath = filepath.Join(dir, "a-peers.json")
	cfgA.Forward = echoServer(t)

	cfgB := base // joiner: pinned from the blob, displays only
	cfgB.SASShow = true
	cfgB.PeerKey = a.pub
	cfgB.KnownPeers = knownB
	cfgB.PeersPath = filepath.Join(dir, "b-peers.json")
	cfgB.LocalListen = freeTCPAddr(t)

	att := attempt{rendezvous: token, inviteToken: token, firstPairing: true}
	runSide(ctx, cfgA, att, a)
	runSide(ctx, cfgB, att, b)

	if !waitFor(t, 25*time.Second, func() bool {
		return prompts.Load() > 0 && shows.Load() > 0
	}) {
		t.Fatalf("pairing did not reach the first-contact step (prompts=%d shows=%d)", prompts.Load(), shows.Load())
	}
	// Give a wrongly-prompting joiner time to show up rather than racing past it.
	time.Sleep(2 * time.Second)

	if got := prompts.Load(); got != 1 {
		t.Errorf("expected exactly one human verification step, got %d — the joining side must not prompt when it pinned the inviter from the invite", got)
	}
	if blindPrompts.Load() != prompts.Load() {
		t.Errorf("the inviter prompted while showing its own code (%d of %d prompts were blind) — that reopens the self-copy bypass", blindPrompts.Load(), prompts.Load())
	}
	if got := shows.Load(); got != 1 {
		t.Errorf("expected the joining side to display its code exactly once, got %d — the inviter would have nothing to type", got)
	}
	// The inviter learned the key only after the confirmation, which is what makes
	// a rejected code leave nothing behind.
	if _, err := os.Stat(knownA); err != nil {
		t.Errorf("inviter did not record the confirmed buddy key in %s: %v", knownA, err)
	}
}

// The security claim of the key-bound invite, end to end in one place: the key
// that comes out of the blob is the key the trust policy enforces, so a partner
// the server vouches for but the invite never named is refused — no prompt, no
// human, nothing learned. This is the whole reason the key rides along with the
// token instead of the token travelling alone.
func TestInviteBlobPinRefusesAnyoneElse(t *testing.T) {
	inviterPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rogue, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// What --join does with the invite it was handed.
	token, pinned, err := invite.Parse(invite.Mint("rendezvous-token", inviterPub))
	if err != nil {
		t.Fatalf("parse invite: %v", err)
	}
	policy := &trustPolicy{pinned: pinned}

	needSAS, err := policy.decide(token, inviterPub)
	if err != nil {
		t.Fatalf("the inviter named by the invite must be accepted: %v", err)
	}
	if needSAS {
		t.Error("a buddy pinned from the invite must not trigger a verification prompt — that is the human step this removes")
	}

	if _, err := policy.decide(token, rogue); err == nil {
		t.Fatal("a partner the server substituted was ACCEPTED — the key in the invite is not being enforced")
	}
}
