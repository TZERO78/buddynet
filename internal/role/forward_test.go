package role

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalNetwork(t *testing.T) {
	cases := map[string][2]string{
		"127.0.0.1:9000":   {"tcp", "127.0.0.1:9000"},
		"unix:/tmp/x.sock": {"unix", "/tmp/x.sock"},
		"/run/x.sock":      {"unix", "/run/x.sock"},
	}
	for in, want := range cases {
		if n, a := localNetwork(in); n != want[0] || a != want[1] {
			t.Errorf("localNetwork(%q) = %q,%q; want %q,%q", in, n, a, want[0], want[1])
		}
	}
}

func TestUnixSocketForwarding(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "s.sock")
	ln, err := listenLocal("unix:" + sock)
	if err != nil {
		t.Fatalf("listenLocal: %v", err)
	}
	defer ln.Close()
	if fi, _ := os.Stat(sock); fi.Mode().Perm() != 0o600 {
		t.Errorf("socket perms = %o, want 600", fi.Mode().Perm())
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		io.Copy(c, c) // echo
		c.Close()
	}()
	c, err := dialLocal(sock) // absolute path => unix
	if err != nil {
		t.Fatalf("dialLocal: %v", err)
	}
	defer c.Close()
	c.Write([]byte("ping"))
	c.(interface{ CloseWrite() error }).CloseWrite()
	got, _ := io.ReadAll(c)
	if string(got) != "ping" {
		t.Fatalf("echo over unix socket = %q, want ping", got)
	}
}
