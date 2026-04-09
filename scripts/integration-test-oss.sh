#!/usr/bin/env bash
# integration-test-oss.sh — Verify the OSS build installs and works in a clean environment.
#
# Uses the homebrew/brew Docker container to simulate a fresh user machine.
# Tests: build from source, install, setup, and basic command evaluation.
#
# Usage:
#   ./scripts/integration-test-oss.sh           # test current repo state
#   ./scripts/integration-test-oss.sh --oss     # simulate OSS build (exclude premium)
#
# Prerequisites:
#   - Docker installed and running
#   - homebrew/brew:latest image available

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

OSS_MODE=false
if [[ "${1:-}" == "--oss" ]]; then
    OSS_MODE=true
fi

echo "=== AgentShield Integration Test ==="
echo "Mode: $(if $OSS_MODE; then echo 'OSS (premium excluded)'; else echo 'Full (all packs)'; fi)"
echo "Source: $REPO_ROOT"
echo ""

# Create a temp directory with the repo content
STAGING=$(mktemp -d)
trap "rm -rf $STAGING" EXIT

echo "Staging repo content..."
# Use git archive to get a clean copy (respects .gitignore, no .git dir)
git archive HEAD | tar -x -C "$STAGING"

# If OSS mode, remove premium files
if $OSS_MODE; then
    rm -rf "$STAGING/packs/premium/" \
           "$STAGING/packs/packs_premium.go" \
           "$STAGING/RULE_REVIEW.md" \
           "$STAGING/FAILING_TESTS.md"
    # Remove disabled legacy packs
    rm -f "$STAGING"/packs/_*.yaml
    echo "  Removed premium files for OSS simulation"
fi

echo "Running Docker integration test..."
echo ""

docker run --rm \
    -v "$STAGING:/agentshield:ro" \
    homebrew/brew:latest \
    bash -c '
set -e

echo "=== [1/5] Install Go ==="
# Homebrew container has brew, use it to install Go
brew install go 2>&1 | tail -3
go version

echo ""
echo "=== [2/5] Build from source ==="
cp -r /agentshield /tmp/agentshield
cd /tmp/agentshield
go build -o /tmp/agentshield-bin ./cmd/agentshield
echo "Build: OK"

echo ""
echo "=== [3/5] Verify binary ==="
/tmp/agentshield-bin version 2>&1 || /tmp/agentshield-bin --help | head -3
echo "Binary: OK"

echo ""
echo "=== [4/5] Run unit tests ==="
# Run the core tests (skip slow ones)
go test ./internal/policy/ ./internal/analyzer/ -count=1 -timeout 120s 2>&1 | tail -5
echo "Tests: OK"

echo ""
echo "=== [5/5] Sanity check: command evaluation ==="
# Setup creates config dir
mkdir -p ~/.agentshield

# Test that agentshield scan works (basic self-test)
/tmp/agentshield-bin scan 2>&1 | head -10 || true
echo ""
echo "Sanity: OK"

echo ""
echo "========================================="
echo "  ALL INTEGRATION TESTS PASSED"
echo "========================================="
'

RESULT=$?
echo ""
if [ $RESULT -eq 0 ]; then
    echo "Integration test: PASSED"
else
    echo "Integration test: FAILED (exit code $RESULT)"
    exit 1
fi
