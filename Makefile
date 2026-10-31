BINARY_NAME=tzsp-processor
BIN=bin/$(BINARY_NAME)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: help fmt fmt-check lint vet test build run clean dist docker-build

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

fmt: ## Format code with gofmt
	gofmt -s -w ./cmd ./internal

fmt-check: ## Fail if any file is not gofmt formatted
	@files="$$(gofmt -s -l ./cmd ./internal)" || exit 1; \
	if [ -n "$$files" ]; then echo "The following files need formatting:"; echo "$$files"; exit 1; fi

lint: ## Run golangci-lint
	golangci-lint run ./...

vet: ## Run go vet
	go vet ./...

test: ## Run unit tests with race detector and coverage
	go test -v -race -cover ./...

build: ## Build static binary
	@mkdir -p $(dir $(BIN))
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN) ./cmd/tzsp-processor

run: build ## Run the built binary
	./$(BIN)

clean: ## Remove binaries and release artifacts
	@rm -rf bin/ dist/

dist: ## Build release binaries for linux/amd64 and linux/arm64
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" \
		-o dist/$(BINARY_NAME)-linux-amd64 ./cmd/tzsp-processor
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" \
		-o dist/$(BINARY_NAME)-linux-arm64 ./cmd/tzsp-processor
	@cd dist && sha256sum $(BINARY_NAME)-linux-* > SHA256SUMS

docker-build: ## Build production Docker image
	docker build --build-arg VERSION=$(VERSION) -t $(BINARY_NAME):latest -f build/Dockerfile .
