package role

import (
	"encoding/json"
	"testing"

	"github.com/tzero78/buddynet/pkg/protocol"
)

// FuzzParseRegister throws arbitrary bytes at the REGISTER parser — the first
// thing the handshake server does with an untrusted internet datagram. The
// invariant: it must never panic, and whenever it accepts (ok), the structural
// guarantees the rest of the server relies on (before fields become map keys)
// must hold. The seed corpus runs under plain `go test`, so this also guards
// against regressions, not just crashes.
func FuzzParseRegister(f *testing.F) {
	valid, _ := json.Marshal(protocol.Message{
		Type: protocol.TypeRegister, Ver: protocol.Version,
		Token: "tok", ID: "id", PubKey: "pk",
	})
	f.Add(valid)
	f.Add([]byte("{}"))
	f.Add([]byte(`{"type":"REGISTER","ver":999}`))
	f.Add([]byte("not json at all"))
	f.Add([]byte(""))
	f.Add([]byte(`{"type":"REGISTER","ver":` + itoa(protocol.Version) + `,"token":"","id":"x"}`))
	// Found by fuzzing, kept as a seed: Go's JSON decoder matches field names
	// CASE-INSENSITIVELY, so "tYpe" reaches Message.Type. Nothing is gained by it —
	// an attacker can just write "type" — but it means the wire format is laxer than
	// the struct tags suggest, and a future check that keys off the raw bytes rather
	// than the decoded message would be wrong.
	f.Add([]byte(`{"tYpe":"REGISTER","token":"0","id":"0"}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		m, ok := parseRegister(raw)
		if !ok {
			return
		}
		if m.Type != protocol.TypeRegister {
			t.Fatalf("accepted a non-REGISTER type %q", m.Type)
		}
		// NOT asserted: the protocol version. parseRegister deliberately does not
		// check it — a client on an older version must reach the point where the
		// server can answer replyIncompatible ("update buddynet") instead of being
		// dropped in silence, which is what the side-by-side rollout in
		// docs/PROTOCOL.md depends on. The version is checked by the callers, after
		// the source address is validated. Asserting it here made the fuzzer report
		// the documented design as a bug.
		if m.Token == "" || len(m.Token) > protocol.MaxFieldLen {
			t.Fatalf("accepted bad token len=%d", len(m.Token))
		}
		if m.ID == "" || len(m.ID) > protocol.MaxFieldLen {
			t.Fatalf("accepted bad id len=%d", len(m.ID))
		}
		if len(m.PubKey) > protocol.MaxFieldLen {
			t.Fatalf("accepted oversized pubkey len=%d", len(m.PubKey))
		}
		if len(m.CodeEnc) > maxCodeEncLen {
			t.Fatalf("accepted oversized code_enc len=%d", len(m.CodeEnc))
		}
	})
}

// itoa avoids importing strconv just for one seed string.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
