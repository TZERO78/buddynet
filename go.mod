module github.com/tzero78/buddynet

go 1.26.0

// The toolchain every official build uses: the newest patch of the 1.26 line.
// CI, the release workflow and the container build all take it from THIS line
// (setup-go `go-version-file: go.mod`), so the stdlib govulncheck scans is the
// stdlib in the artifact. Keep the `FROM golang:` pin in deployments/Dockerfile
// on the same version and its digest — that build path does not read this line
// (dependabot.yml only proposes patch bumps of that image for the same reason).
//
// Deliberately NOT go1.27.x: 1.27 is a fresh major line, and 1.26.8 is the newest
// patch of the line the shipped releases were built with (1.26.8 is bug fixes
// only; 1.26.6 carried the last security fixes). Moving to 1.27 is a separate,
// deliberate step once that line has had a patch release or two.
//
// The `go` minimum above is 1.26.0 because quic-go ≥ 0.62 requires it; a distro
// packager with Go 1.26.x and GOTOOLCHAIN=local can still build. Only
// GOTOOLCHAIN=auto fetches 1.26.8.
toolchain go1.26.8

require (
	filippo.io/edwards25519 v1.2.0
	github.com/miekg/dns v1.1.73
	github.com/quic-go/quic-go v0.62.0
	golang.org/x/crypto v0.57.0
	golang.org/x/term v0.46.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)
