module github.com/tzero78/buddynet

go 1.25.0

// Build with a patched toolchain (stdlib CVEs fixed past 1.25.0); the `go`
// minimum above stays 1.25.0 for compatibility. CI/release build with `stable`.
toolchain go1.25.11

require (
	filippo.io/edwards25519 v1.2.0
	github.com/quic-go/quic-go v0.60.0
	golang.org/x/crypto v0.53.0
	golang.org/x/term v0.44.0
)

require (
	github.com/miekg/dns v1.1.72 // indirect
	golang.org/x/mod v0.35.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/tools v0.44.0 // indirect
)
