.PHONY: build test lint clean install run help setup-hooks lint-fix coverage mcp-verify test-mcp compliance-indexes test-install test-install-oss

VERSION ?= 0.1.0-dev
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X 'github.com/AI-AgentLens/agentshield/internal/cli.Version=$(VERSION)' \
           -X 'github.com/AI-AgentLens/agentshield/internal/cli.GitCommit=$(GIT_COMMIT)' \
           -X 'github.com/AI-AgentLens/agentshield/internal/cli.BuildDate=$(BUILD_DATE)'

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

mcp-gen: ## Generate MCP rules from shell rules (packs/mcp/mcp-generated.yaml)
	go run ./cmd/mcp-gen

compliance-indexes: ## Regenerate compliance/indexes/ markdown from taxonomy entries and standards
	go run ./internal/taxonomy/generate_index.go

deploy: build ## Build and deploy packs + binary to ~/.agentshield
	@echo "Deploying packs..."
	@mkdir -p ~/.agentshield/packs ~/.agentshield/mcp-packs
	@cp packs/community/*.yaml ~/.agentshield/packs/ 2>/dev/null || true
	@cp packs/premium/*.yaml ~/.agentshield/packs/ 2>/dev/null || true
	@echo "Deploying binary..."
	@cp $(BUILD_DIR)/$(BINARY) /opt/homebrew/bin/$(BINARY) 2>/dev/null || sudo cp $(BUILD_DIR)/$(BINARY) /opt/homebrew/bin/$(BINARY)
	@echo "Verifying..."
	@agentshield scan > /dev/null 2>&1 && echo "✅ AgentShield deployed and verified" || echo "⚠️  Deploy done but scan failed"

check: lint-fix test build ## Run full pre-commit check (lint, test, build)

test-install: ## Test homebrew install in Docker container (full build)
	@echo "=== Installation Test (full) ==="
	@./scripts/integration-test-oss.sh

test-install-oss: ## Test homebrew install in Docker container (OSS build, premium excluded)
	@echo "=== Installation Test (OSS) ==="
	@./scripts/integration-test-oss.sh --oss

test-brew: ## Test brew tap + install + scan in Docker container
	@echo "=== Homebrew Tap Install Test ==="
	@docker run --rm homebrew/brew:latest bash -c ' \
		set -e; \
		HOMEBREW_NO_AUTO_UPDATE=1 brew tap AI-AgentLens/oss 2>&1 | tail -2; \
		HOMEBREW_NO_AUTO_UPDATE=1 brew install AI-AgentLens/oss/agentshield 2>&1 | tail -3; \
		mkdir -p $$HOME/.agentshield; \
		echo ""; \
		agentshield scan 2>&1; \
		echo ""; \
		echo "=== HOMEBREW INSTALL TEST PASSED ===" \
	'

test-premium: build ## Test premium pack update flow (requires agentshield login)
	@echo "=== Premium Pack Update Test ==="
	@if [ ! -f ~/.agentshield/credentials.json ]; then \
		echo "❌ Not logged in. Run: agentshield login"; exit 1; \
	fi
	@echo "[1/4] Clearing existing premium packs..."
	@rm -f ~/.agentshield/packs/terminal-safety.yaml ~/.agentshield/packs/secrets-pii.yaml
	@echo "[2/4] Running agentshield update..."
	@$(BUILD_DIR)/$(BINARY) update
	@echo ""
	@echo "[3/4] Verifying packs downloaded..."
	@test -f ~/.agentshield/packs/terminal-safety.yaml || (echo "❌ terminal-safety.yaml not downloaded" && exit 1)
	@test -f ~/.agentshield/packs/secrets-pii.yaml || (echo "❌ secrets-pii.yaml not downloaded" && exit 1)
	@echo "  ✅ Premium packs present"
	@echo ""
	@echo "[4/4] Running scan with premium packs..."
	@$(BUILD_DIR)/$(BINARY) scan 2>&1 | grep -A4 "Premium Status"
	@echo ""
	@echo "=== PREMIUM UPDATE TEST PASSED ==="
