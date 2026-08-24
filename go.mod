module github.com/tzero78/buddynet

go 1.25.0

// The toolchain every official build uses: the newest patch of the 1.26 line.
// CI, the release workflow and the container build all take it from THIS line
// (setup-go `go-version-file: go.mod`), so the stdlib govulncheck scans is the
// stdlib in the artifact. Keep the `FROM golang:` pin in deployments/Dockerfile
// on the same version and its digest — that build path does not read this line.
//
// Deliberately NOT go1.27.x: 1.27.0 is a fresh major release, and 1.26.7 is the
// newest patch of the line the shipped releases were built with. 1.26.6 carried
// the last security fixes; 1.26.7 adds net/http bug fixes on top. Moving to 1.27
// is a separate, deliberate step once that line has had a patch release or two.
//
// The `go` minimum above deliberately stays 1.25.0: a distro packager with Go
// 1.25.x and GOTOOLCHAIN=local can still build. Only GOTOOLCHAIN=auto fetches
// 1.26.7.
toolchain go1.26.7

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
