## What does this PR do?



## Type

- [ ] Bug fix
- [ ] Feature
- [ ] Security fix
- [ ] Documentation
- [ ] Refactor

## Security checklist (for any change touching protocol/crypto/auth)

- [ ] `go test -race ./...` green
- [ ] `govulncheck ./...` clean
- [ ] No new untrusted-input path without `safe.Do` / `safe.Go`
- [ ] `SECURITY.md` updated if the threat model changed

## Testing

What did you test and how?
