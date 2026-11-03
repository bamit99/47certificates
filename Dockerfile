# 47c — 47-day TLS certificate impact auditor
#
# Build:   docker build -t 47c:dev .
# Run:     docker run --rm -v "$PWD/data:/data" -p 127.0.0.1:8080:8080 47c:dev
# First boot provisions admin/ADMIN_PASSWORD once if ADMIN_PASSWORD is set.

FROM golang:1.24-alpine AS build
WORKDIR /src

# Reproducible, auditable module downloads.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /47c ./cmd/47c \
    && mkdir -p /data \
    && chown 65532:65532 /data

FROM scratch
LABEL org.opencontainers.image.title="47c" \
      org.opencontainers.image.description="Self-hosted inventory of publicly-trusted TLS certificates vs the CA/B Forum 47-day schedule"
COPY --from=build /47c /47c
COPY --from=build --chown=65532:65532 /data /data
VOLUME ["/data"]
ENV 47C_DATA_DIR=/data \
    47C_LISTEN=0.0.0.0:8080
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["/47c", "health"]
ENTRYPOINT ["/47c"]
CMD ["serve"]
