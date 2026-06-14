# Single static binary on a tiny Alpine runtime. One image, three roles —
# choose with --role at runtime. Multi-arch images are produced by buildx in CI,
# which runs this build per target platform so `go build` yields each arch
# natively.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/buddynet ./cmd/buddynet

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/buddynet /usr/local/bin/buddynet
# Default to the handshake server; override --role for relay or buddy.
EXPOSE 51820/udp 51821/udp
ENTRYPOINT ["buddynet"]
CMD ["--role=handshake", "--listen", "[::]:51820", "--key", "/var/lib/buddynet/id.key"]
