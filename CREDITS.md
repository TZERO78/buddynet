# Credits & thanks

BuddyNet stands on the shoulders of excellent open-source work. Thank you to
everyone who built and maintains these projects.

## Dependencies

- **[quic-go](https://github.com/quic-go/quic-go)** — the production-grade pure-Go
  QUIC implementation that powers the tunnel's reliable, ordered, multiplexed and
  TLS-1.3-encrypted data path over our hole-punched UDP socket. Thank you for
  doing the genuinely hard part (reliability + congestion control + crypto) so we
  don't have to.
- **[golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto)** — including
  `nacl/box`, used to seal enrollment codes to the server's identity.
  **[x/net](https://pkg.go.dev/golang.org/x/net)**,
  **[x/sys](https://pkg.go.dev/golang.org/x/sys)** — the Go extended libraries
  underpinning the crypto and networking.
  **[x/term](https://pkg.go.dev/golang.org/x/term)** — to show a freshly
  generated token and hide it again on a keypress (`gen-token`).
  Thank you to the Go team.
- **[filippo.io/edwards25519](https://filippo.io/edwards25519)** — for the
  Ed25519→X25519 key conversion that lets us reuse the server's pinned identity
  key to encrypt enrollment codes (no second key to distribute). Thank you,
  Filippo Valsorda.
- **[miekg/dns](https://github.com/miekg/dns)** — the Go DNS library powering
  MagicDNS: wire-format encoding/decoding, the `ServeMux`, and the UDP+TCP
  server behind the `.buddy` stub resolver. The first external runtime dependency
  BuddyNet took on. Thank you, Miek Gieben and contributors.

## Planned (v2)

- **[wireguard-go](https://git.zx2c4.com/wireguard-go/)
  (`golang.zx2c4.com/wireguard`)** — the userspace WireGuard implementation
  earmarked for the v2 data-plane transport behind the same `Transport` seam.
  Thank you, Jason A. Donenfeld and the WireGuard project.

## Design inspiration

- **[RustDesk](https://github.com/rustdesk/rustdesk)** — its rendezvous (`hbbs`)
  design, NaCl-based key exchange, and Ed25519 signing of forwarded public keys
  directly shaped BuddyNet's matchmaking and MITM-protection approach. Thank you.
- **[Tailscale](https://tailscale.com/blog/nat-traversal-improvements-pt3-looking-ahead)**
  — their writing on NAT traversal in the wild (and honest treatment of the
  symmetric-NAT/relay reality) informed our IPv6-first strategy. Thank you.
- **[libp2p](https://github.com/libp2p/go-libp2p)** and the
  **["Implementing NAT Hole Punching with QUIC"](https://arxiv.org/abs/2408.01791)**
  paper — for showing that QUIC over hole-punched UDP is a sound, proven pattern.
  Thank you.
