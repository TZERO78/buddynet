package dns

import (
	"context"
	"errors"
	"log"
	"os"
	"os/exec"
	"strings"
)

// resolvectlPath is resolved once to an ABSOLUTE path, so a root daemon can never
// be steered into running an attacker-planted `resolvectl` earlier in $PATH. The
// command is also run with an empty environment for the same reason.
var resolvectlPath = findResolvectl()

func findResolvectl() string {
	for _, p := range []string{"/usr/bin/resolvectl", "/bin/resolvectl", "/usr/sbin/resolvectl", "/sbin/resolvectl"} {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath("resolvectl"); err == nil {
		return p
	}
	return ""
}

// RegisterSystem tries to route .buddy queries to our stub resolver.
// It attempts resolvectl first (systemd-resolved); on failure it logs a note
// so the operator can configure routing manually. The function never returns
// an error — DNS routing is best-effort and the tunnel must not fail over it.
//
// On ctx cancel the routing is removed (best-effort cleanup).
func RegisterSystem(ctx context.Context) {
	if err := resolvectlAdd(); err != nil {
		log.Printf("NOTE: BuddyDNS: could not register .buddy with systemd-resolved (%v); "+
			"add 'nameserver 127.0.0.153' to /etc/resolv.conf or point your resolver at it manually", err)
		return
	}
	log.Printf("BUDDYDNS: action=resolver-registered addr=%s detail=%q", stubAddr, "*.buddy routed via resolvectl")
	go func() {
		<-ctx.Done()
		if err := resolvectlRemove(); err != nil {
			log.Printf("NOTE: BuddyDNS cleanup: resolvectl revert failed: %v", err)
		}
	}()
}

// resolvectlAdd points systemd-resolved's stub resolver at our address for the
// .buddy search domain. We operate on the loopback interface because that is
// always present and does not require a real network interface.
func resolvectlAdd() error {
	ip := strings.TrimSuffix(stubAddr, ":53")
	if err := resolvectl("dns", "lo", ip); err != nil {
		return err
	}
	return resolvectl("domain", "lo", "~buddy")
}

func resolvectlRemove() error {
	return resolvectl("revert", "lo")
}

func resolvectl(args ...string) error {
	if resolvectlPath == "" {
		return errors.New("resolvectl not found on this system")
	}
	// Absolute path (no PATH lookup) and an empty environment: a context-bound exec
	// would cancel cleanup, and all args are hardcoded literals from internal
	// callers, so neither $PATH nor user input can influence what runs.
	cmd := exec.Command(resolvectlPath, args...) // #nosec G204 -- absolute path, hardcoded literal args, empty env
	cmd.Env = []string{}
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) > 0 {
		return &runError{cmd: resolvectlPath + " " + strings.Join(args, " "), out: string(out), err: err}
	}
	return err
}

type runError struct {
	cmd string
	out string
	err error
}

func (e *runError) Error() string { return e.cmd + ": " + strings.TrimSpace(e.out) }
func (e *runError) Unwrap() error { return e.err }
