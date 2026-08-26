# secrets/

Credentials for the **opt-in** labs. Everything in this directory is ignored by
git except the `*.example` templates and this file — see `.gitignore`.

Nothing in BuddyNet itself ever reads from here. These are operator credentials
for test tooling, kept in one place so they cannot end up in a command line, a
shell history or a commit by accident.

## dynv6.env

Used by `lab/test-direct-dynv6.sh`, which brings up a direct-mode tunnel over a
real dynamic-DNS name. Copy the template and fill it in:

```bash
cp secrets/dynv6.env.example secrets/dynv6.env
$EDITOR secrets/dynv6.env
./lab/test-direct-dynv6.sh
```

The token is an **update credential**: whoever holds it can repoint the DNS
record your buddies resolve. That cannot forge an identity — a direct-mode buddy
authenticates its partner by pinned key, never by name — but it can deny you
service. Treat it accordingly, and rotate it at the provider if it leaks.

If the file is absent the lab skips itself, so a fresh checkout stays runnable.
