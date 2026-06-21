# Lab image for buddy containers — alpine-based (not distroless) so we can run
# a busybox httpd test service alongside buddynet in buddy-a.
# NOT for production use; see deployments/Dockerfile for the hardened image.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/buddynet ./cmd/buddynet
RUN mkdir -p /out/state

FROM alpine:3.21
# curl for testing; busybox-extras provides the httpd applet (not in base busybox);
# iproute2 lets the CGNAT-lab entrypoint point the default route at its NAT router.
RUN apk add --no-cache curl busybox-extras iproute2
COPY --from=build /out/buddynet /usr/local/bin/buddynet
COPY --from=build /out/state /var/lib/buddynet
COPY lab/entrypoint-a.sh /entrypoint-a.sh
RUN chmod +x /entrypoint-a.sh
VOLUME ["/var/lib/buddynet"]
EXPOSE 51820/udp
ENTRYPOINT ["/usr/local/bin/buddynet"]
