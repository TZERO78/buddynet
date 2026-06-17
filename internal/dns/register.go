package dns

import (
	"context"
	"log"
	"os/exec"
	"strings"
)

// RegisterSystem tries to route .buddy queries to our stub resolver.
// It attempts resolvectl first (systemd-resolved); on failure it logs a note
// so the operator can configure routing manually. The function never returns
// an error — DNS routing is best-effort and the tunnel must not fail over it.
//
// On ctx cancel the routing is removed (best-effort cleanup).
func RegisterSystem(ctx context.Context) {
	if err := resolvectlAdd(); err != nil {
		log.Printf("NOTE: MagicDNS: could not register .buddy with systemd-resolved (%v); "+
			"add 'nameserver 127.0.0.153' to /etc/resolv.conf or point your resolver at it manually", err)
		return
	}
	log.Printf("MagicDNS: .buddy domain routed to %s via resolvectl", stubAddr)
	go func() {
		<-ctx.Done()
		if err := resolvectlRemove(); err != nil {
			log.Printf("NOTE: MagicDNS cleanup: resolvectl revert failed: %v", err)
		}
	}()
}

// resolvectlAdd points systemd-resolved's stub resolver at our address for the
// .buddy search domain. We operate on the loopback interface because that is
// always present and does not require a real network interface.
func resolvectlAdd() error {
	ip := strings.TrimSuffix(stubAddr, ":53")
	if err := run("resolvectl", "dns", "lo", ip); err != nil {
		return err
	}
	return run("resolvectl", "domain", "lo", "~buddy")
}

func resolvectlRemove() error {
	if err := run("resolvectl", "revert", "lo"); err != nil {
		return err
	}
	return nil
}

func run(name string, args ...string) error {
	// A context-bound exec would cancel cleanup; use a bare command here.
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil && len(out) > 0 {
		return &runError{cmd: name + " " + strings.Join(args, " "), out: string(out), err: err}
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
