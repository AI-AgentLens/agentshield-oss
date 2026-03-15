.PHONY: build test lint clean install run help setup-hooks lint-fix coverage mcp-verify test-mcp

VERSION ?= 0.1.0-dev
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X 'github.com/security-researcher-ca/agentshield/internal/cli.Version=$(VERSION)' \
           -X 'github.com/security-researcher-ca/agentshield/internal/cli.GitCommit=$(GIT_COMMIT)' \
           -X 'github.com/security-researcher-ca/agentshield/internal/cli.BuildDate=$(BUILD_DATE)'

BINARY := agentshield
BUILD_DIR := ./build

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/agentshield

test: ## Run tests
	go test -v ./...

lint: ## Run linter (requires golangci-lint)
	golangci-lint run ./...

clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)
	go clean

install: build ## Install to /usr/local/bin
	cp $(BUILD_DIR)/$(BINARY) /usr/local/bin/$(BINARY)

run: build ## Build and run with args (usage: make run ARGS="run -- echo hi")
	$(BUILD_DIR)/$(BINARY) $(ARGS)

deps: ## Download dependencies
	go mod download
	go mod tidy

setup-hooks: ## Set up pre-commit hooks
	@echo "🔧 Setting up pre-commit hooks..."
	@chmod +x .git/hooks/pre-commit
	@echo "✅ Pre-commit hooks installed!"

lint-fix: ## Run linter with auto-fix
	@echo "🔧 Running linter with auto-fix..."
	golangci-lint run --fix

coverage: ## Generate COVERAGE.md from pack rules and test data
	go run ./cmd/coverage

mcp-verify: ## Run MCP proxy self-test and output Markdown report
	go run ./cmd/mcp-verify

test-mcp: ## Run MCP scenario tests
	go test -v -run TestMCPScenarios ./internal/mcp/

check: lint-fix test build ## Run full pre-commit check (lint, test, build)
