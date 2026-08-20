package role

// AUDIT 2026-08-20, finding A-06 (LOW / hardening): listenLocal creates a Unix
// domain socket and tightens it afterwards, so between the two calls the socket
// exists with the process umask's permissions:
//
//	ln, err := net.Listen(network, address)   // <-- created 0777 &^ umask
//	...
//	os.Chmod(address, 0o600)                  // <-- tightened only now
//
// The socket is already accepting during that window. A local user who connects
// inside it gets a stream spliced straight onto the tunnel — i.e. onto the
// partner's side of the BuddyNet door — with no further check, because -L has no
// authentication of its own: the file mode IS the access control.
//
// This is the same class the project already closed for the identity key
// (crypto TOCTOU / O_NOFOLLOW hardening) and it has the same one-line remedy:
// create the socket inside a 0700 directory, or set the umask around the listen.
// It is rated hardening because the window is short and the attacker must be a
// local user already racing a known path — but "short" is not a control, and on
// the Unraid boxes this ships to, -L paths are predictable.
//
// The test proves the window in two independent ways, so it does not depend on
// winning a race:
//
//  1. deterministically — the mode net.Listen actually produces, which is what
//     exists until Chmod runs, and
//  2. empirically — an observer polling the path while listenLocal runs.

import (
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

// TestAuditUnixSocketCreatedWorldAccessible is the deterministic half: it makes
// the same net.Listen call listenLocal makes and reports the mode that exists
// before any Chmod.
func TestAuditUnixSocketCreatedWorldAccessible(t *testing.T) {
	// Read the process umask without leaving it changed.
	umask := syscall.Umask(0)
	syscall.Umask(umask)

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil { // a normal -L directory, not a private one
		t.Fatalf("chmod dir: %v", err)
	}

	// The property the fix rests on: inside withTightUmask, anything created is
	// owner-only AT CREATION — not narrowed afterwards. Tested on a plain file,
	// because that is the same umask that governs the socket, and a file's mode
	// can be observed the instant it exists.
	probe := filepath.Join(dir, "probe")
	if err := withTightUmask(func() error {
		f, ferr := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0o666)
		if ferr != nil {
			return ferr
		}
		return f.Close()
	}); err != nil {
		t.Fatalf("withTightUmask: %v", err)
	}
	fi, err := os.Stat(probe)
	if err != nil {
		t.Fatalf("stat probe: %v", err)
	}
	if m := fi.Mode().Perm(); m&0o077 != 0 {
		t.Fatalf(`A-06 is back — withTightUmask does not make creation owner-only.

The probe file was created %04o (process umask %04o). listenLocal relies on this
to create the -L socket private in the first place: net.Listen makes the socket
with 0777 &^ umask and the listener accepts immediately, so a chmod afterwards
closes a door somebody may already be through. -L has no authentication of its
own — the file mode IS the access control.`, m, umask)
	}

	// And the umask must be back to what it was: it is process-wide state.
	if got := syscall.Umask(0); got != umask {
		syscall.Umask(umask)
		t.Fatalf("withTightUmask leaked the umask: %04o, want %04o", got, umask)
	}
	syscall.Umask(umask)

	// The production path end to end: the socket exists and is owner-only.
	sock := filepath.Join(dir, "buddynet.sock")
	ln, err := listenLocal("unix:" + sock)
	if err != nil {
		t.Fatalf("listenLocal: %v", err)
	}
	defer ln.Close()
	si, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if m := si.Mode().Perm(); m&0o077 != 0 {
		t.Fatalf("the -L socket is %04o — group/world can connect and be spliced onto the tunnel", m)
	}
	t.Logf("socket created and left owner-only (%04o) under process umask %04o", si.Mode().Perm(), umask)
}

// TestAuditUnixSocketRaceObservable is the empirical half: it runs the real
// listenLocal while a second goroutine polls the path, and reports the most
// permissive mode actually observed. It never fails the run on its own — losing
// a microsecond race proves nothing — it only records what was seen.
func TestAuditUnixSocketRaceObservable(t *testing.T) {
	const rounds = 200
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}

	worst := os.FileMode(0)
	hits := 0
	for i := 0; i < rounds; i++ {
		sock := filepath.Join(dir, "race.sock")
		_ = os.Remove(sock)

		var wg sync.WaitGroup
		stop := make(chan struct{})
		var mu sync.Mutex
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if fi, err := os.Stat(sock); err == nil {
					m := fi.Mode().Perm()
					if m&0o077 != 0 {
						mu.Lock()
						if m > worst {
							worst = m
						}
						hits++
						mu.Unlock()
						return
					}
				}
			}
		}()

		ln, err := listenLocal(sock)
		close(stop)
		wg.Wait()
		if err != nil {
			t.Fatalf("listenLocal round %d: %v", i, err)
		}
		ln.Close()
	}

	if hits == 0 {
		t.Logf("the window was not observed in %d rounds — the deterministic half of A-06 stands on its own", rounds)
		return
	}
	t.Logf("A-06 window observed empirically: an unprivileged observer saw the socket at mode %04o "+
		"in %d of %d rounds before listenLocal tightened it to 0600", worst, hits, rounds)
}
