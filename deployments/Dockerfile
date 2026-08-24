# Single static binary on a distroless, non-root runtime. One image, three
# roles — choose with --role at runtime. Multi-arch images are produced by
# buildx in CI, which runs this build per target platform so `go build` yields
# each arch natively.
# Exact version AND digest, matching the `toolchain` line in go.mod: a floating
# 1.26-alpine tag would drift away from the toolchain every other build path is
# pinned to (A-07).
FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/buddynet ./cmd/buddynet
# Pre-create the state dir so a fresh named volume mounted over it inherits the
# non-root ownership (distroless has no shell to chown at runtime).
RUN mkdir -p /out/state

# Distroless static: no shell, no package manager, runs as an unprivileged user
# (uid/gid 65532). The binary is fully static (CGO_ENABLED=0) and the roles
# authenticate by pinned self-signed certs, so no CA bundle is needed.
FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
COPY --from=build --chown=65532:65532 /out/buddynet /usr/local/bin/buddynet
# The identity key lives here; owned by uid 65532 so a fresh named volume that
# mounts over it is writable by the non-root process.
COPY --from=build --chown=65532:65532 /out/state /var/lib/buddynet
VOLUME ["/var/lib/buddynet"]
# Default to the handshake server; override --role for relay or buddy. Ports are
# the documented defaults (see pkg/protocol); override with --listen.
EXPOSE 51820/udp 51821/udp
USER 65532:65532
ENTRYPOINT ["buddynet"]
CMD ["--role=handshake", "--listen", "[::]:51820", "--key", "/var/lib/buddynet/id.key"]
