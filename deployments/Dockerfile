# Single static binary on a distroless, non-root runtime. One image, three
# roles — choose with --role at runtime.
#
# NO IMAGE IS PUBLISHED. There is no registry to pull from: build it yourself
# from this repository (deployments/docker-compose.yml does exactly that). The
# deliberate trade is that a published image ages — its base would need a rebuild
# on every CVE, whether or not BuddyNet changed — while the shipped static
# binaries do not. CI builds this file on every change so it cannot rot, but it
# pushes nothing.
#
# Building for another architecture: this is a plain single-platform build, so
# use `docker buildx build --platform linux/arm64` if you need one.
# Exact version AND digest, matching the `toolchain` line in go.mod: a floating
# 1.26-alpine tag would drift away from the toolchain every other build path is
# pinned to (A-07).
FROM golang:1.26.8-alpine@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS build
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
FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
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
