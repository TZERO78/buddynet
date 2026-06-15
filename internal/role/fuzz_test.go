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

	f.Fuzz(func(t *testing.T, raw []byte) {
		m, ok := parseRegister(raw)
		if !ok {
			return
		}
		if m.Type != protocol.TypeRegister {
			t.Fatalf("accepted a non-REGISTER type %q", m.Type)
		}
		if m.Ver != protocol.Version {
			t.Fatalf("accepted a mismatched version %d", m.Ver)
		}
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
