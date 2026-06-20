package crypto

import (
	"crypto/ed25519"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVirtualIPDeterministic(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	a := VirtualIP(pub)
	b := VirtualIP(pub)
	if a != b {
		t.Fatalf("not deterministic: %v != %v", a, b)
	}
	if !a.Is4() {
		t.Fatalf("want IPv4, got %v", a)
	}
}

func TestVirtualIPInSubnet(t *testing.T) {
	prefix := netip.MustParsePrefix(VirtualSubnet)
	// Many random keys must all land inside 10.66.0.0/16 and never on the
	// reserved network (10.66.0.0) or broadcast (10.66.255.255) host.
	for i := 0; i < 1000; i++ {
		pub, _, _ := ed25519.GenerateKey(nil)
		ip := VirtualIP(pub)
		if !prefix.Contains(ip) {
			t.Fatalf("%v not in %v", ip, prefix)
		}
		b := ip.As4()
		if b[2] == 0 && b[3] == 0 {
			t.Fatalf("network address is reserved (%v)", ip)
		}
		if b[2] == 255 && b[3] == 255 {
			t.Fatalf("broadcast address is reserved (%v)", ip)
		}
	}
}

func TestPubKeyRoundTrip(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	got, err := DecodePubKey(PubKeyB64(pub))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(pub) {
		t.Fatal("round trip changed the key")
	}
	if _, err := DecodePubKey("not-base64!!"); err == nil {
		t.Fatal("expected error on garbage")
	}
	if _, err := DecodePubKey("c2hvcnQ="); err == nil {
		t.Fatal("expected error on wrong-length key")
	}
}

func TestSealOpenCode(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	enc, err := SealCode("ab56fe2", pub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenCode(enc, priv)
	if err != nil {
		t.Fatal(err)
	}
	if got != "ab56fe2" {
		t.Fatalf("got %q", got)
	}
	// A different key must not decrypt it.
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	if _, err := OpenCode(enc, otherPriv); err == nil {
		t.Fatal("expected wrong-key decryption to fail")
	}
}

// A key path that is a symlink must be refused outright. os.ReadFile/Stat/Chmod
// and os.WriteFile all follow symlinks, so honoring one would read, chmod, or
// clobber the LINK TARGET (e.g. a key path pointing at /etc/shadow). The target
// must be left completely untouched.
func TestLoadOrCreateKeyRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("not a key"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "key.symlink")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	_, _, err := LoadOrCreateKey(link)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a symlinked key path must be refused, got err=%v", err)
	}

	// The target must be untouched: perms NOT tightened to 0600, content intact.
	info, serr := os.Stat(target)
	if serr != nil {
		t.Fatal(serr)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("symlink target was chmod'd to %v — it must be left alone", info.Mode().Perm())
	}
	if b, _ := os.ReadFile(target); string(b) != "not a key" {
		t.Fatal("symlink target content changed — it must be left alone")
	}
}

// A DANGLING symlink (target does not exist) must also be refused — otherwise
// os.WriteFile on the create path would follow it and create the target.
func TestLoadOrCreateKeyRefusesDanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "does-not-exist")
	link := filepath.Join(dir, "key.symlink")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
	if _, _, err := LoadOrCreateKey(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a dangling symlinked key path must be refused, got err=%v", err)
	}
	if _, serr := os.Stat(target); !os.IsNotExist(serr) {
		t.Fatal("dangling symlink target was created — write followed the link")
	}
}
