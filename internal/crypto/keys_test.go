package crypto

import (
	"crypto/ed25519"
	"net/netip"
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
	// Many random keys must all land inside 10.66.0.0/24 and never on the
	// network (.0) or broadcast (.255) host.
	for i := 0; i < 1000; i++ {
		pub, _, _ := ed25519.GenerateKey(nil)
		ip := VirtualIP(pub)
		if !prefix.Contains(ip) {
			t.Fatalf("%v not in %v", ip, prefix)
		}
		last := ip.As4()[3]
		if last == 0 || last == 255 {
			t.Fatalf("host octet %d is reserved (%v)", last, ip)
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
