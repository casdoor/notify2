# Hanzo Notify — multi-arch Dockerfile.
#
# Builds a static cmd/notifyd binary; runs FROM scratch with
# Distroless's static-debian12-nonroot user.

# ─── build stage ───────────────────────────────────────────────────────
FROM golang:1.23-alpine AS build
WORKDIR /src

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
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/notifyd /usr/local/bin/notifyd

ENV PORT=8090
EXPOSE 8090

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/notifyd"]
