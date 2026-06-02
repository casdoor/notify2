# Hanzo Notify — multi-arch Dockerfile.
#
# Builds a static cmd/notifyd binary; runs FROM Distroless's
# static-debian12-nonroot user. Matches the hanzoai/auto image layout
# (sibling service) so K8s manifests can use one set of probes and
# resource limits across both.

# ─── build stage ───────────────────────────────────────────────────────
# Debian-based golang image — git + ca-certificates + tzdata pre-baked,
# no `apk add` against dl-cdn.alpinelinux.org which the hanzo home-lab
# runner can't reach reliably. Adds ~50MB to the build layer (discarded
# at the FROM scratch hand-off so the final image is unaffected).
FROM golang:1.26.3 AS build
WORKDIR /src
RUN groupadd -g 65532 nonroot && \
    useradd  -u 65532 -g 65532 -M -s /usr/sbin/nologin nonroot

# Cache the module graph first.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=amd64

ENV CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH}
RUN go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/notifyd \
      ./cmd/notifyd

# ─── runtime stage ─────────────────────────────────────────────────────
# Scratch — zero base image dependency, zero registry auth, zero attack
# surface. The build stage above supplies ca-certs, tzdata, /etc/passwd
# + /etc/group for the nonroot user. CGO is off so the static binary
# needs nothing else at runtime.
FROM scratch
LABEL service=notify
LABEL org.opencontainers.image.source="https://github.com/hanzoai/notify"
LABEL org.opencontainers.image.vendor="Hanzo AI Inc."
LABEL org.opencontainers.image.title="Hanzo Notify"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /etc/group /etc/group
COPY --from=build /out/notifyd /usr/local/bin/notifyd

# /var/lib/notify is the default data dir for the embedded SQLite.
# K8s mounts an emptyDir or PVC here; raw `docker run` callers can
# override with the base flag `--dir`.
VOLUME ["/var/lib/notify"]

ENV PORT=8090
EXPOSE 8090

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/notifyd"]
CMD ["serve", "--http", "0.0.0.0:8090", "--dir", "/var/lib/notify"]
