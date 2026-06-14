package secret

import (
	"encoding/base64"
	"testing"
)

func TestNewToken(t *testing.T) {
	tok, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatalf("token is not valid base64url: %q (%v)", tok, err)
	}
	if len(raw) != 48 {
		t.Fatalf("token decodes to %d bytes, want 48 (384 bits)", len(raw))
	}
	if len(tok) != 64 {
		t.Fatalf("token is %d chars, want 64", len(tok))
	}

	// Two calls must differ — a fixed token would be catastrophic.
	other, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken (2nd): %v", err)
	}
	if tok == other {
		t.Fatalf("two tokens were identical: %q", tok)
	}
}

func TestNewSessionToken(t *testing.T) {
	tok, err := NewSessionToken()
	if err != nil {
		t.Fatalf("NewSessionToken: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatalf("session token is not valid base64url: %q (%v)", tok, err)
	}
	if len(raw) != 16 {
		t.Fatalf("session token decodes to %d bytes, want 16 (128 bits)", len(raw))
	}

	other, err := NewSessionToken()
	if err != nil {
		t.Fatalf("NewSessionToken (2nd): %v", err)
	}
	if tok == other {
		t.Fatalf("two session tokens were identical: %q", tok)
	}
}
