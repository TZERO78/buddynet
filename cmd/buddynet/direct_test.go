package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildOnce compiles the CLI for the exec-based checks below. The validation
// under test lives in main() (flag parsing + validate()), so it can only be
// exercised through a real process — which is also how an operator meets it.
func buildOnce(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "buddynet")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

// TestDirectModeRefusals pins the fail-closed rules of direct mode at the CLI
// boundary. Direct mode removes the handshake server, and with it the SAS, the
// signed roster and the relay ticket — the pinned key is then the ENTIRETY of
// the authentication. So every combination that would weaken or bypass that pin
// has to be refused at startup, loudly, rather than silently interpreted.
//
// Exit code 2 throughout: a usage error, not a runtime failure.
func TestDirectModeRefusals(t *testing.T) {
	bin := buildOnce(t)
	const key = "0LqJ6b1CEyjKU6jaaq+ZIo9K89xnRbxQXLuVn0iYEZ0="

	for _, tc := range []struct {
		name string
		args []string
		want string // substring the operator must see
	}{
		{
			name: "no pin at all",
			args: []string{"--role=buddy", "--direct", "--peer-endpoint", "h:51820", "-L", "127.0.0.1:0"},
			want: "--direct requires --peer-key",
		},
		{
			name: "no way for the two to meet",
			args: []string{"--role=buddy", "--direct", "--peer-key", key, "-L", "127.0.0.1:0"},
			want: "--peer-endpoint",
		},
		{
			name: "a server would contradict the mode",
			args: []string{"--role=buddy", "--direct", "--peer-key", key, "--peer-endpoint", "h:51820",
				"--server", "s:51820", "--server-key", key, "-L", "127.0.0.1:0"},
			want: "mutually exclusive",
		},
		{
			// The dangerous one: --lab disables partner verification outright. In
			// server mode that is merely reckless; here it would leave NOTHING
			// authenticating the peer, since the pin is all there is.
			name: "lab would disable the only authentication there is",
			args: []string{"--role=buddy", "--direct", "--peer-key", key, "--peer-endpoint", "h:51820",
				"--lab", "-L", "127.0.0.1:0"},
			want: "only authentication",
		},
		{
			name: "invite/join need a server to redeem them",
			args: []string{"--role=buddy", "--direct", "--peer-key", key, "--peer-endpoint", "h:51820",
				"--join", "sometoken", "-L", "127.0.0.1:0"},
			want: "--invite/--join",
		},
		{
			name: "MultiPeer needs an endpoint per buddy",
			args: []string{"--role=buddy", "--direct", "--peer-key", key, "--peer-endpoint", "h:51820",
				"--peers-file", "/nonexistent.yaml", "-L", "127.0.0.1:0"},
			want: "--peers-file",
		},
		{
			// One fixed port cannot serve N tunnels; the second bind would fail.
			name: "a fixed port cannot be shared by MultiPeer",
			args: []string{"--role=buddy", "--listen-port", "51820", "--peers-file", "/nonexistent.yaml",
				"--server", "s:51820", "--server-key", key},
			want: "--listen-port cannot be combined with --peers-file",
		},
		{
			name: "port out of range",
			args: []string{"--role=buddy", "--direct", "--peer-key", key, "--listen-port", "70000",
				"-L", "127.0.0.1:0"},
			want: "not a valid udp port",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(bin, tc.args...)
			// BUDDYNET_LAB is forced empty so the --lab case is refused by the
			// direct-mode rule under test and not by the unrelated opt-in guard.
			cmd.Env = append(os.Environ(), "BUDDYNET_LAB=", "BUDDYNET_JOIN=")
			out, err := cmd.CombinedOutput()

			ee, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("want a non-zero exit, got err=%v\noutput:\n%s", err, out)
			}
			if ee.ExitCode() != 2 {
				t.Fatalf("want exit 2 (usage error), got %d\noutput:\n%s", ee.ExitCode(), out)
			}
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("message does not mention %q — an operator could not act on it:\n%s", tc.want, out)
			}
		})
	}
}

// TestDirectModeAcceptsAServerlessConfig is the counterpart that stops the test
// above from passing vacuously: if the CLI rejected everything, all those cases
// would be "green" while direct mode was simply broken. A valid configuration
// must get PAST validation — it fails later, on the network, which is a
// different exit code than a usage error.
func TestDirectModeAcceptsAServerlessConfig(t *testing.T) {
	bin := buildOnce(t)
	dir := t.TempDir()

	// A real identity, so the run gets as far as the connect loop.
	if out, err := exec.Command(bin, "--key", filepath.Join(dir, "id.key"), "init").CombinedOutput(); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	const peer = "0LqJ6b1CEyjKU6jaaq+ZIo9K89xnRbxQXLuVn0iYEZ0="

	cmd := exec.Command(bin, "--role=buddy", "--direct",
		"--key", filepath.Join(dir, "id.key"),
		"--known-peers", filepath.Join(dir, "known"),
		"--peer-key", peer,
		"--peer-endpoint", "definitely-does-not-exist.invalid:51820",
		"--no-interactive", "-L", "127.0.0.1:0")
	cmd.Env = append(os.Environ(), "BUDDYNET_LAB=")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	// Give it a moment to get through validation, then stop it. We are asserting
	// that it did NOT exit 2 immediately, not that it connects to a name that
	// deliberately does not resolve.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 2 {
			t.Fatal("a valid serverless direct-mode configuration was rejected as a usage error")
		}
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		<-done // reaped
	}
}
