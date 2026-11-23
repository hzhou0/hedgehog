IMG ?= hedgehog:dev
CLUSTER := hedgehog-e2e
CONTEXT := k3d-$(CLUSTER)

.PHONY: all
all: fmt vet test build

.PHONY: fmt
fmt:
	go fmt ./...

# Fails instead of rewriting, for CI.
.PHONY: fmt-check
fmt-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

# The e2e package is behind a build tag, so it's vetted separately.
.PHONY: vet
vet:
	go vet ./...
	go vet -tags e2e ./e2e

.PHONY: test
test:
	go test ./... -count=1

.PHONY: build
build:
	go build -o bin/hedgehog ./cmd/hedgehog

.PHONY: docker-build
docker-build:
	docker build -t $(IMG) .

# The k3d cluster with the in-cluster registry (see the Tiltfile). Needs k3d, Tilt, and grype at the Dockerfile's
# version on the host.
.PHONY: cluster
cluster:
	@k3d cluster list $(CLUSTER) >/dev/null 2>&1 || k3d cluster create --config e2e/k3d.yaml --kubeconfig-switch-context=false --wait

.PHONY: cluster-delete
cluster-delete:
	k3d cluster delete $(CLUSTER)

# Dev loop: rebuilds and redeploys on change; trigger the e2e resource from the Tilt UI.
.PHONY: dev
dev: cluster
	tilt up --context $(CONTEXT)

# One-shot: deploys and runs the e2e test, and exits non-zero if it fails.
.PHONY: e2e
e2e: cluster
	tilt ci --context $(CONTEXT) --timeout 50m
