# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt
GOVET=$(GOCMD) vet

# Project info
BINARY_NAME=go-authkit
BINARY_UNIX=$(BINARY_NAME)_unix
MODULE_NAME=github.com/hugoFelippe/go-authkit

# Test parameters
TEST_TIMEOUT=30s
TEST_COVERAGE_OUT=coverage.out
TEST_COVERAGE_HTML=coverage.html

# Lint tools
GOLINT=golangci-lint
STATICCHECK=staticcheck

.PHONY: all build clean test test-unit test-integration test-coverage test-race fmt vet lint check install deps examples watch help

# Default target
all: check test build

## Build commands
build: ## Build all examples
	@echo "Building examples..."
	@cd examples/basic && $(GOBUILD) -v -o go-authkit_basic .

build-keep: ## Build examples and keep binaries for execution
	@echo "Building examples (keeping binaries)..."
	@cd examples/basic && $(GOBUILD) -v -o go-authkit_basic .
	@echo "✓ Built: examples/basic/go-authkit_basic"

build-linux: ## Build for Linux
	@echo "Building for Linux..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -a -installsuffix cgo -o $(BINARY_UNIX) .

## Test commands
test: ## Run all tests
	@echo "Running all tests..."
	$(GOTEST) -timeout $(TEST_TIMEOUT) -v ./...

test-unit: ## Run unit tests only
	@echo "Running unit tests..."
	$(GOTEST) -timeout $(TEST_TIMEOUT) -v -short ./...

test-integration: ## Run integration tests only
	@echo "Running integration tests..."
	$(GOTEST) -timeout $(TEST_TIMEOUT) -v -run Integration ./tests/integration/...

test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	$(GOTEST) -timeout $(TEST_TIMEOUT) -coverprofile=$(TEST_COVERAGE_OUT) -covermode=atomic ./...
	$(GOCMD) tool cover -html=$(TEST_COVERAGE_OUT) -o $(TEST_COVERAGE_HTML)
	@echo "Coverage report generated: $(TEST_COVERAGE_HTML)"

test-race: ## Run tests with race detector
	@echo "Running tests with race detector..."
	$(GOTEST) -timeout $(TEST_TIMEOUT) -race -v ./...

test-bench: ## Run benchmarks
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

## Code quality commands
fmt: ## Format code
	@echo "Formatting code..."
	$(GOFMT) -s -w .

vet: ## Run go vet
	@echo "Running go vet..."
	$(GOVET) ./...

lint: ## Run linters
	@echo "Running linters..."
	@if command -v $(GOLINT) >/dev/null 2>&1; then \
		$(GOLINT) run ./...; \
	else \
		echo "golangci-lint not found. Install with: make install-tools"; \
	fi

staticcheck: ## Run staticcheck
	@echo "Running staticcheck..."
	@if command -v $(STATICCHECK) >/dev/null 2>&1; then \
		$(STATICCHECK) ./...; \
	else \
		echo "staticcheck not found. Install with: make install-tools"; \
	fi

check: fmt vet ## Run formatting and vetting

## Development commands
install: ## Install dependencies
	@echo "Installing dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

install-tools: ## Install development tools
	@echo "Installing development tools..."
	$(GOGET) github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GOGET) honnef.co/go/tools/cmd/staticcheck@latest

deps: ## Update dependencies
	@echo "Updating dependencies..."
	$(GOMOD) tidy
	$(GOGET) -u ./...

examples: ## Run examples
	@echo "Running basic example..."
	@cd examples/basic && $(GOCMD) run .

watch: ## Watch for changes and run tests
	@echo "Watching for changes..."
	@if command -v fswatch >/dev/null 2>&1; then \
		fswatch -o . | xargs -n1 -I{} make test-unit; \
	elif command -v inotifywait >/dev/null 2>&1; then \
		while inotifywait -r -e modify,create,delete .; do make test-unit; done; \
	else \
		echo "Install fswatch (macOS) or inotify-tools (Linux) to enable watch mode"; \
	fi

## Cleanup commands
clean: ## Clean build artifacts
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)
	rm -f $(TEST_COVERAGE_OUT)
	rm -f $(TEST_COVERAGE_HTML)
	rm -f examples/*/go-authkit_*
	rm -f examples/*/basic
	rm -f examples/*/main

clean-deps: ## Clean dependency cache
	@echo "Cleaning dependency cache..."
	$(GOCMD) clean -modcache

## CI/CD commands
ci: install check test-coverage ## Run CI pipeline
	@echo "CI pipeline completed successfully"

pre-commit: fmt vet lint test ## Run pre-commit checks
	@echo "Pre-commit checks completed successfully"

## Documentation commands
docs: ## Generate documentation
	@echo "Generating documentation..."
	$(GOCMD) doc -all .

## Docker commands (if needed in future)
docker-build: ## Build Docker image
	docker build -t $(BINARY_NAME) .

docker-run: ## Run Docker container
	docker run --rm -it $(BINARY_NAME)

## Help
help: ## Show this help
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Include additional makefiles if they exist
-include Makefile.local
