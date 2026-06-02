# Hanzo Notify — multi-arch Dockerfile.
#
# Builds a static cmd/notifyd binary; runs FROM Distroless's
# static-debian12-nonroot user. Matches the hanzoai/auto image layout
# (sibling service) so K8s manifests can use one set of probes and
# resource limits across both.

# ─── build stage ───────────────────────────────────────────────────────
FROM golang:1.26.3-alpine AS build
WORKDIR /src
RUN apk add --no-cache git

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
# Distroless mirrored to GHCR. Source: gcr.io/distroless/static-debian12:nonroot
# (bit-identical, crane copy). Self-hosted runners can't reach gcr.io
# reliably; ghcr.io is the registry the build is already authenticated
# against (docker/login-action upstream of this FROM).
FROM ghcr.io/hanzoai/distroless-static:nonroot
LABEL service=notify
LABEL org.opencontainers.image.source="https://github.com/hanzoai/notify"
LABEL org.opencontainers.image.vendor="Hanzo AI Inc."
LABEL org.opencontainers.image.title="Hanzo Notify"

COPY --from=build /out/notifyd /usr/local/bin/notifyd

# /var/lib/notify is the default data dir for the embedded SQLite.
# K8s mounts an emptyDir or PVC here; raw `docker run` callers can
# override with the base flag `--dir`.
VOLUME ["/var/lib/notify"]

ENV PORT=8090
EXPOSE 8090

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/notifyd"]
CMD ["serve", "--http", "0.0.0.0:8090", "--dir", "/var/lib/notify"]
