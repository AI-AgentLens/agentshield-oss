.PHONY: build test test-perf lint clean install help setup-hooks lint-fix coverage mcp-verify test-mcp compliance-indexes test-install test-install-oss test-cask test-oss-walkthrough check-rule-coverage check-mcp-tool-symmetry check-pack-taxonomy-fit check-testdata-taxonomy-fit premium-manifest

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

# shield-server is the agentless evaluation service (issue #3315). It is an
# OPTIONAL, experimental artifact: not built by `make build`, not installed by
# `agentshield setup`, not part of the release by default. Its version vars
# live in package main (not internal/cli) so building it never touches the
# hook binary's build graph.
SERVER_LDFLAGS := -X 'main.Version=$(VERSION)' \
                  -X 'main.GitCommit=$(GIT_COMMIT)' \
                  -X 'main.BuildDate=$(BUILD_DATE)'

build-server: ## Build the experimental shield-server binary (agentless /v1/evaluate)
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "$(SERVER_LDFLAGS)" -o $(BUILD_DIR)/shield-server ./cmd/shield-server

test: ## Run tests
	go test -v -timeout 40m ./...

# The pipeline latency fitness function, quarantined out of `test` by #3505 —
# it measured the runner's co-tenancy, not the code, and produced five red
# `main` runs with zero true positives. Kept as a measurement, run by the
# nightly perf-budget workflow and by hand here. Needs a QUIET machine: do not
# run it alongside Comply's `make test-all`.
test-perf: ## Run the pipeline P95 latency budget (quarantined; needs a quiet machine)
	SHIELD_PERF_BUDGET=1 go test -v -count=1 -timeout 10m \
		-run 'TestPipelinePerfBudget' ./internal/policy/

lint: ## Run linter (requires golangci-lint)
	golangci-lint run ./...

clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)
	go clean

install: build ## Install to /usr/local/bin
	cp $(BUILD_DIR)/$(BINARY) /usr/local/bin/$(BINARY)

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

mcp-gen: ## Generate MCP rules from shell rules (packs/community/mcp/mcp-generated.yaml)
	go run ./cmd/mcp-gen

compliance-indexes: ## Regenerate compliance/indexes/ markdown from taxonomy entries and standards
	go run ./internal/taxonomy/generate_index.go

LIVE_LINK ?= /opt/homebrew/bin/$(BINARY)

deploy: build ## Build and deploy packs + binary to ~/.agentshield
	@echo "Preparing binary..."
	@# Apple Silicon: `go build -o $(BUILD_DIR)/$(BINARY)` rewrites the binary in
	@# place, which invalidates the ad-hoc signature the kernel cached for that
	@# inode. The next exec dies with SIGKILL (137) and no useful message. A
	@# deploy that produces an unrunnable binary is worse than one that does
	@# nothing, so re-sign before anything is wired up to it.
	@if [ "$$(uname -s)" = "Darwin" ] && command -v codesign >/dev/null 2>&1; then \
		if codesign --force -s - "$(BUILD_DIR)/$(BINARY)" 2>/dev/null; then \
			echo "  ✅ codesigned $(BUILD_DIR)/$(BINARY) (ad-hoc)"; \
		else \
			echo "  ⚠️  codesign failed — the binary may die with SIGKILL 137 on exec."; \
		fi; \
	fi
	@# The live-binary link is CREATED OR REPAIRED here, never assumed (#3141).
	@# It ran before the pack copy on purpose: the failure mode that hid #3141
	@# for months was a deploy that half-worked — packs refreshed, binary stale —
	@# because every symptom of a stale engine looks like a rule problem. If the
	@# binary cannot be wired up, stop before shipping rules to it.
	@bash scripts/ensure-live-link.sh "$(LIVE_LINK)" "$(abspath $(BUILD_DIR)/$(BINARY))"
	@echo "Deploying packs..."
	@# Remove legacy nested layouts from historical deploys. Earlier versions
	@# of this target copied into ~/.agentshield/packs/community/ and
	@# ~/.agentshield/packs/premium/; the pack loader walks subdirectories,
	@# so stale copies there would be loaded alongside the fresh flat layout
	@# and resurrect rules we thought we retired (see issue #1153 dogfooding
	@# incident). Nuke them before copying so only the current layout exists.
	@# ~/.agentshield/packs/mcp is the same trap (issue #2219): MCP packs use a
	@# schema the *terminal* loader (policy.LoadPacks) can't parse, so when it
	@# recurses into packs/mcp/ it errors out ("cannot unmarshal !!map into
	@# string") and #2188's loud reporting flags every premium MCP pack as
	@# failed. MCP packs belong in ~/.agentshield/mcp-packs/ — the canonical dir
	@# the MCP loader, proxy, and `scan` actually read (mcp.DefaultMCPPacksDir),
	@# matching what `agentshield setup mcp` installs. Nuke any stale packs/mcp/.
	@rm -rf ~/.agentshield/packs/community ~/.agentshield/packs/premium ~/.agentshield/packs/mcp
	@# Stale flat MCP packs: older `agentshield update` clients wrote mcp-*.yaml
	@# directly into packs/ (#2219). Sweep them so the terminal loader stops
	@# tripping on them; the fresh copies land in mcp-packs/ below.
	@rm -f ~/.agentshield/packs/mcp-*.yaml
	@rm -f ~/.agentshield/packs/packs.go ~/.agentshield/packs/packs_premium.go
	@mkdir -p ~/.agentshield/packs ~/.agentshield/mcp-packs
	@cp packs/community/*.yaml ~/.agentshield/packs/ 2>/dev/null || true
	@cp packs/premium/*.yaml ~/.agentshield/packs/ 2>/dev/null || true
	@cp packs/community/mcp/*.yaml ~/.agentshield/mcp-packs/ 2>/dev/null || true
	@cp packs/premium/mcp/*.yaml ~/.agentshield/mcp-packs/ 2>/dev/null || true
	@# The old binary step lived here and did `cmp || cp || sudo -n cp`. It has
	@# moved above ensure-live-link.sh, and the cp modes are gone: a `cmp`
	@# against a symlink says "already current" no matter *where* that symlink
	@# points, which is precisely the check that reported success throughout
	@# #3141. Replacing a regular file now requires AGENTSHIELD_LINK_FORCE=1
	@# rather than happening silently.
	@echo "Verifying..."
	@# Ask the binary that PATH actually resolves — not the one we just linked.
	@# Repairing $(LIVE_LINK) is useless if a different agentshield sits earlier
	@# on PATH, and that is the same shape of silent disconnect as #3141.
	@LIVE_COMMIT="$$(agentshield version 2>/dev/null | awk '/Commit:/ {print $$2}')"; \
	if [ "$$LIVE_COMMIT" = "$(GIT_COMMIT)" ]; then \
		echo "  ✅ $$(command -v agentshield) reports commit $$LIVE_COMMIT (matches this tree)"; \
	else \
		echo "  ⚠️  PATH agentshield reports commit '$$LIVE_COMMIT', this tree is $(GIT_COMMIT)."; \
		echo "     $$(command -v agentshield 2>/dev/null || echo 'agentshield not on PATH') is not the binary this deploy built."; \
	fi
	@agentshield scan > /dev/null 2>&1 && echo "✅ AgentShield deployed and verified" || echo "⚠️  Deploy done but scan failed"

check: lint-fix test build check-rule-coverage ## Run full pre-commit check (lint, test, build, rule coverage)

check-rule-coverage: ## Enforce TP+TN test coverage on every terminal pack rule
	go run ./cmd/check-rule-coverage -v

check-mcp-tool-symmetry: ## Flag MCP credential-exposure rules with read-only tool_name_any (write-tool bypass, #3525)
	go run ./cmd/check-mcp-tool-symmetry -v

# Semantic-fit of pack taxonomy refs (#3333). Needs the AI_risk_compliance
# taxonomy tree, which this repo does not vendor — pass its path, the same
# contract as scripts/check-taxonomy-refs.sh, which CI already satisfies.
#   make check-pack-taxonomy-fit TAXONOMY_DIR=~/dev/AI_risk_compliance/taxonomy
TAXONOMY_DIR ?= ../AI_risk_compliance/taxonomy
check-pack-taxonomy-fit: ## Check pack taxonomy refs FIT their node's prose (needs TAXONOMY_DIR)
	@test -d "$(TAXONOMY_DIR)" || { \
	  echo "TAXONOMY_DIR=$(TAXONOMY_DIR) is not a directory."; \
	  echo "Pass the AI_risk_compliance taxonomy tree:"; \
	  echo "  make check-pack-taxonomy-fit TAXONOMY_DIR=/path/to/AI_risk_compliance/taxonomy"; \
	  exit 2; }
	go run ./cmd/check-pack-taxonomy-fit -taxonomy "$(TAXONOMY_DIR)"

# Same gate, scored against internal/analyzer/testdata TP cases instead of
# pack rules (#3336) — a mislabelled TaxonomyRef in the test corpus is a wrong
# assertion about what the attestation resolves to, same stakes as a pack rule.
check-testdata-taxonomy-fit: ## Check testdata TaxonomyRefs FIT their node's prose (needs TAXONOMY_DIR)
	@test -d "$(TAXONOMY_DIR)" || { \
	  echo "TAXONOMY_DIR=$(TAXONOMY_DIR) is not a directory."; \
	  echo "Pass the AI_risk_compliance taxonomy tree:"; \
	  echo "  make check-testdata-taxonomy-fit TAXONOMY_DIR=/path/to/AI_risk_compliance/taxonomy"; \
	  exit 2; }
	go run ./cmd/check-pack-taxonomy-fit -testdata -taxonomy "$(TAXONOMY_DIR)"

premium-manifest: ## Print the premium-pack manifest the release publishes for the SaaS (aiagentlens#77)
	@go run ./cmd/gen-premium-manifest

test-setup: ## Test IDE setup/hook/disable cycle in Docker container
	@echo "=== Setup Integration Test ==="
	@./scripts/integration-test-setup.sh

test-install: ## Test homebrew install in Docker container (full build)
	@echo "=== Installation Test (full) ==="
	@./scripts/integration-test-oss.sh

test-install-oss: ## Test homebrew install in Docker container (OSS build, premium excluded)
	@echo "=== Installation Test (OSS) ==="
	@./scripts/integration-test-oss.sh --oss

test-cask: ## E2E: brew install --cask path; verifies embedded packs protect a fresh install
	@echo "=== Cask Install E2E (Linuxbrew container) ==="
	@./scripts/integration-test-cask.sh

test-oss-walkthrough: ## Run the README walkthrough end-to-end in a fresh linuxbrew container (12 steps, ~2 min)
	@echo "=== OSS Walkthrough Test (homebrew/brew:latest) ==="
	@docker run --rm -v $(PWD)/scripts/oss-walkthrough-test.sh:/walk.sh:ro homebrew/brew:latest bash /walk.sh

test-e2e: ## Full friend-install E2E in Docker: cask + login + update + premium rule fires. Requires AGENTSHIELD_TEST_TOKEN
	@echo "=== Friend-Install E2E (with premium pack delivery) ==="
	@AGENTSHIELD_TEST_TOKEN="$${AGENTSHIELD_TEST_TOKEN:-$$(jq -r .token ~/.agentshield/credentials.json 2>/dev/null)}" \
		./scripts/integration-test-e2e.sh

test-brew: ## Test brew tap + install + scan in Docker container
	@echo "=== Homebrew Tap Install Test ==="
	@# HOMEBREW_CURL_RETRIES + DOWNLOAD_CONCURRENCY=1 + a shell retry loop
	@# guard against ghcr.io bottle-download SSL EOFs at nightly hours
	@# (~9PM EDT). Two consecutive nightly failures (5/20 + 5/21) were
	@# ghcr.io load on the go-bottle download, not formula breakage.
	@#
	@# The retry MUST capture output instead of piping to tail: a pipeline
	@# exits with tail's status (always 0), so `if brew install | tail` broke
	@# on attempt 1 every time and the loop never retried. That is exactly
	@# how a transient git fetch EOF failed the 8/19 nightly (Shield #3437).
	@docker run --rm \
		-e HOMEBREW_NO_AUTO_UPDATE=1 \
		-e HOMEBREW_NO_ANALYTICS=1 \
		-e HOMEBREW_CURL_RETRIES=5 \
		-e HOMEBREW_DOWNLOAD_CONCURRENCY=1 \
		homebrew/brew:latest bash -c ' \
		set -e; \
		brew --version | head -1; \
		brew tap AI-AgentLens/oss 2>&1 | tail -2; \
		brew trust AI-AgentLens/oss >/dev/null 2>&1 || \
			echo "note: brew trust unavailable on this Homebrew - skipping (install is the real gate)"; \
		for attempt in 1 2 3; do \
			if out=$$(brew install AI-AgentLens/oss/agentshield 2>&1); then \
				printf "%s\n" "$$out" | tail -5; \
				break; \
			fi; \
			printf "%s\n" "$$out" | tail -15 >&2; \
			if [ $$attempt -eq 3 ]; then \
				echo "brew install failed after 3 attempts (likely ghcr.io bottle download issue)" >&2; \
				exit 1; \
			fi; \
			echo "brew install attempt $$attempt failed; sleeping 30s before retry..." >&2; \
			sleep 30; \
		done; \
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
	@# Premium pack filenames carry the -advanced suffix; terminal-safety.yaml and
	@# secrets-pii.yaml are COMMUNITY packs served from the embedded corpus. Clearing
	@# those names tested nothing and deleted the wrong packs off a live install.
	@rm -f ~/.agentshield/packs/terminal-safety-advanced.yaml ~/.agentshield/packs/secrets-pii-advanced.yaml
	@echo "[2/4] Running agentshield update..."
	@$(BUILD_DIR)/$(BINARY) update
	@echo ""
	@echo "[3/4] Verifying packs downloaded..."
	@test -f ~/.agentshield/packs/terminal-safety-advanced.yaml || (echo "❌ terminal-safety-advanced.yaml not downloaded" && exit 1)
	@test -f ~/.agentshield/packs/secrets-pii-advanced.yaml || (echo "❌ secrets-pii-advanced.yaml not downloaded" && exit 1)
	@echo "  ✅ Premium packs present"
	@echo ""
	@echo "[4/4] Running scan with premium packs..."
	@$(BUILD_DIR)/$(BINARY) scan 2>&1 | grep -A4 "Premium Status"
	@echo ""
	@echo "=== PREMIUM UPDATE TEST PASSED ==="
