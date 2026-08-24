module github.com/tzero78/buddynet

go 1.25.0

// The toolchain every official build uses. It is pinned FORWARD to the version
// v5.1.1 was actually built and shipped with, not back to an older patch that
// never produced a release. CI, the release workflow and the container build all
// take it from THIS line (setup-go `go-version-file: go.mod`, GOTOOLCHAIN=local),
// so the stdlib govulncheck scans is the stdlib in the artifact.
//
// The `go` minimum above deliberately stays 1.25.0: a distro packager with Go
// 1.25.x and GOTOOLCHAIN=local can still build. Only GOTOOLCHAIN=auto fetches
// 1.26.6.
toolchain go1.26.6

require (
	filippo.io/edwards25519 v1.2.0
	github.com/miekg/dns v1.1.73
	github.com/quic-go/quic-go v0.61.0
	golang.org/x/crypto v0.55.0
	golang.org/x/term v0.45.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/kr/text v0.2.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
