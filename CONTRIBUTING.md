# Contributing to BuddyNet

Thanks for taking the time. BuddyNet is a small, security-focused project, and
honest feedback — including "this is wrong" — is genuinely welcome. We promise
nothing beyond what we've actually tested, bugs can always remain, and a good bug
report or critique is worth more to us than a star.

## Found a bug or a security issue?

- **Non-sensitive bugs:** open an issue using the
  [bug report template](.github/ISSUE_TEMPLATE/bug_report.md). Include version
  (`buddynet version`), OS/arch, the roles involved, and a minimal reproduction —
  please redact any keys or tokens.
- **Security vulnerabilities:** please don't open a public issue first. Follow the
  private disclosure process in [SECURITY.md](SECURITY.md). We read every report
  and are grateful for responsible disclosure.

## Ideas and feedback

Open a [feature request](.github/ISSUE_TEMPLATE/feature_request.md) describing the
problem first, then the proposed solution. Disagreement with a design choice is
fine — the threat model and trade-offs are written down in
[SECURITY.md](SECURITY.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) so they
can be argued about.

## Sending a pull request

Before opening a PR, please make sure the same checks CI runs pass locally:

```bash
gofmt -l ./cmd ./internal ./pkg   # must be empty
go vet ./...
go test -race ./...
go build ./...

# the security pass CI runs (same versions):
go install golang.org/x/vuln/cmd/govulncheck@v1.5.0
govulncheck ./...
go install github.com/securego/gosec/v2/cmd/gosec@v2.27.1
gosec -severity medium -exclude=G104,G115,G117,G304,G402 ./...
```

CI additionally validates the shipped systemd units and checks that no shipped
artifact passes a flag the binaries do not define. Official builds use the exact
toolchain on the `toolchain` line of `go.mod`; each job asserts it got that
version.

- Keep changes focused and match the style of the file you are editing: errors
  wrapped with `fmt.Errorf("context: %w", err)`, stdlib `log` (no structured
  logger), stdlib `testing` (no assertion library), and every function doing I/O
  taking a `context.Context` first and honouring cancellation.
- Anything touching the control plane, crypto, or trust logic should stay
  **additive and backward-compatible** where possible, and bump
  `protocol.Version` when the wire format changes.
- New untrusted-input paths belong behind `safe.Do` / `safe.Go` panic isolation.
- Re-run the structural pentest probe after security-relevant changes:
  [lab/pentest/README.md](lab/pentest/README.md).

The [pull request template](.github/PULL_REQUEST_TEMPLATE.md) has the full
checklist.

## Thanks

BuddyNet stands on a lot of open-source work — see [CREDITS.md](CREDITS.md). Thank
you to everyone who builds, breaks, reports, and improves it.

## License

By contributing you agree that your contributions are licensed under the project's
[MIT License](LICENSE).
