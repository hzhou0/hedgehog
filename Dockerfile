# Hedgehog: one static Go binary plus the pinned scanner/patcher CLIs it executes.
# Tool versions are pinned here; bumping grype requires re-checking its risk formula (TestRiskFormulaUnchanged in grype_test.go).
ARG GO_VERSION=1.27

FROM golang:${GO_VERSION} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/hedgehog ./cmd/hedgehog

FROM alpine:3.22 AS tools
ARG TARGETARCH
ARG GRYPE_VERSION=0.122.1
ARG SYFT_VERSION=1.57.2
ARG COPA_VERSION=0.15.0
RUN apk add --no-cache curl
WORKDIR /tools
# Each release publishes a checksums file; every download is verified against it.
RUN set -eu; \
    fetch() { \
      repo="$1"; name="$2"; ver="$3"; sums="$4"; file="${name}_${ver}_linux_${TARGETARCH}.tar.gz"; \
      curl -fsSLO "https://github.com/${repo}/releases/download/v${ver}/${file}"; \
      curl -fsSL "https://github.com/${repo}/releases/download/v${ver}/${sums}" | grep " ${file}\$" | sha256sum -c -; \
      tar -xzf "$file" "$name"; rm "$file"; \
    }; \
    fetch anchore/grype grype "$GRYPE_VERSION" "grype_${GRYPE_VERSION}_checksums.txt"; \
    fetch anchore/syft syft "$SYFT_VERSION" "syft_${SYFT_VERSION}_checksums.txt"; \
    fetch project-copacetic/copacetic copa "$COPA_VERSION" copacetic_checksums.txt

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=tools /tools/grype /tools/syft /tools/copa /usr/local/bin/
COPY --from=build /out/hedgehog /usr/local/bin/hedgehog
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/hedgehog"]
