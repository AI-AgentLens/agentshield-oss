#!/usr/bin/env bash
# integration-test-oss.sh — Verify the OSS build installs and works in a clean environment.
#
# Uses the homebrew/brew Docker container to simulate a fresh user machine.
# Tests: build from source, install, setup, and basic command evaluation.
#
# Usage:
#   ./scripts/integration-test-oss.sh                    # test current repo state
#   ./scripts/integration-test-oss.sh --oss              # OSS build: strip exactly what
#                                                        #   scripts/publish-oss.sh strips
#   ./scripts/integration-test-oss.sh --oss --stage-only DIR
#                                                        # stage + strip + leakage check
#                                                        #   into DIR, no Docker; DIR is
#                                                        #   left for the caller to inspect
#
# What --oss builds, and what it does not (#3373): the strip and the carve-out
# restore come from scripts/oss-excludes.sh, the same file publish-oss.sh
# consumes, so the tree graded here is the tree that script would push. Two
# things still differ from a real publish and are NOT covered: this stages from
# `git archive HEAD` (tracked files only) where publish rsyncs the WORKING tree,
# and publish then rewrites identifiers (the perl sanitize block) and runs the
# private-identifier scan — neither happens here. This script never contacts
# the public repo.
#
# Prerequisites:
#   - Docker installed and running (not for --stage-only)
#   - homebrew/brew:latest image available (not for --stage-only)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

OSS_MODE=false
STAGE_ONLY=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --oss)
            OSS_MODE=true
            ;;
        --stage-only)
            if [[ -z "${2:-}" ]]; then
                echo "Usage: $0 [--oss] [--stage-only DIR]" >&2
                exit 2
            fi
            STAGE_ONLY="$2"
            shift
            ;;
        *)
            echo "Usage: $0 [--oss] [--stage-only DIR]" >&2
            exit 2
            ;;
    esac
    shift
done

if $OSS_MODE; then
    if [[ ! -f "$REPO_ROOT/scripts/oss-excludes.sh" ]]; then
        # The list is on its own exclude list, so it is absent from the
        # published tree on purpose — and there --oss is meaningless: that tree
        # already IS the OSS tree. In the source repo this means the file was
        # moved or deleted, and a strip with no list would grade the full tree
        # while calling it OSS. Refuse rather than fall through.
        echo "ERROR: $REPO_ROOT/scripts/oss-excludes.sh not found." >&2
        echo "       It ships only in the source repo. If this is the published" >&2
        echo "       agentshield-oss tree, it already is the OSS build: run" >&2
        echo "       'make test-install' instead." >&2
        exit 2
    fi
    # shellcheck source=scripts/oss-excludes.sh
    source "$REPO_ROOT/scripts/oss-excludes.sh"
fi

echo "=== AgentShield Integration Test ==="
echo "Mode: $(if $OSS_MODE; then echo 'OSS (premium excluded)'; else echo 'Full (all packs)'; fi)"
echo "Source: $REPO_ROOT"
echo ""

if [[ -n "$STAGE_ONLY" ]]; then
    mkdir -p "$STAGE_ONLY"
    if [[ -n "$(ls -A "$STAGE_ONLY")" ]]; then
        echo "ERROR: --stage-only DIR must be empty: $STAGE_ONLY" >&2
        exit 2
    fi
    STAGING="$STAGE_ONLY"
else
    # Create a temp directory with the repo content
    STAGING=$(mktemp -d)
    # mktemp -d is 0700 and owned by the invoking user. The homebrew/brew container
    # builds as its own "linuxbrew" user (uid 1000), a different uid, so it cannot
    # traverse 0700 and the first cp out of /agentshield dies with "Permission
    # denied" (#3159). Docker Desktop on darwin remaps bind-mount ownership to the
    # container user, which masks this entirely -- so this failed only on the Linux
    # self-hosted runner, and only once the gate was able to fail at all (#3130).
    # The mount is :ro, so widening the host-side mode grants the container nothing
    # it could not already read.
    chmod 755 "$STAGING"
    trap "rm -rf $STAGING" EXIT
fi

echo "Staging repo content..."
# Use git archive to get a clean copy (respects .gitignore, no .git dir)
git archive HEAD | tar -x -C "$STAGING"

if $OSS_MODE; then
    # Strip + restore with the shared function; before #3373 this was a
    # hardcoded 5-entry list against the publisher's 18.
    if ! oss_strip_tree "$STAGING" "$REPO_ROOT"; then
        echo "ERROR: could not build the OSS tree (see above)." >&2
        exit 1
    fi
    echo "  Stripped ${#OSS_EXCLUDES[@]} exclude entries per scripts/oss-excludes.sh"

    # Positive control before the real assertion: a leakage check that cannot
    # fail is the same defect as the gate that could not fail (#3130). A planted
    # premium file must be reported, or this run stops here.
    CONTROL=$(mktemp -d)
    mkdir -p "$CONTROL/packs/premium"
    : > "$CONTROL/packs/premium/planted.yaml"
    if oss_check_leakage "$CONTROL" > /dev/null; then
        rm -rf "$CONTROL"
        echo "ERROR: leakage check passed a planted packs/premium/planted.yaml." >&2
        echo "       The assertion is vacuous; refusing to trust it on the real tree." >&2
        exit 1
    fi
    rm -rf "$CONTROL"

    # The assertion the nightly could not make before #3373: nothing premium and
    # nothing on the exclude list survives in the tree we are about to grade.
    if ! LEAKS="$(oss_check_leakage "$STAGING")"; then
        echo "ERROR: OSS tree contains paths the publish excludes:" >&2
        printf '%s\n' "$LEAKS" >&2
        exit 1
    fi
    echo "  Leakage check: OK (nothing under packs/premium/, nothing on the exclude list)"
fi

if [[ -n "$STAGE_ONLY" ]]; then
    echo ""
    echo "Staged $(find "$STAGING" -type f | wc -l | tr -d ' ') files into $STAGING (no Docker run)."
    exit 0
fi

echo "Running Docker integration test..."
echo ""

# The container script below is single-quoted, so it must not contain a single
# quote — apostrophes in comments included.
#
# It also contains no pipelines around anything whose exit status matters. In a
# pipeline $? is the LAST command status, so "go test ... | tail -5" reported
# tail success and the gate could not fail (#3130). PIPESTATUS is not the fix:
# it is a bash-ism, and zsh spells the same array "pipestatus" with 1-based
# indexes, so a ${PIPESTATUS[0]} guard silently reads nothing under zsh.
# Redirect to a file and read the file afterwards instead — that is correct in
# every shell, and keeps the full output for diagnosis.
DOCKER_STATUS=0
docker run --rm \
    -v "$STAGING:/agentshield:ro" \
    homebrew/brew:latest \
    bash -c '
set -e

echo "=== [1/5] Install Go ==="
# Homebrew container has brew, use it to install Go.
if ! brew install go > /tmp/brew-install.log 2>&1; then
    echo "brew install go FAILED:"
    tail -20 /tmp/brew-install.log
    exit 1
fi
tail -3 /tmp/brew-install.log
go version

echo ""
echo "=== [2/5] Build from source ==="
cp -r /agentshield /tmp/agentshield
cd /tmp/agentshield
go build -o /tmp/agentshield-bin ./cmd/agentshield
echo "Build: OK"

echo ""
echo "=== [3/5] Verify binary ==="
# Each form is checked on its own status. Piping --help into head handed the
# status to head, so a binary that could answer NEITHER version nor --help
# still reported "Binary: OK".
if /tmp/agentshield-bin version > /tmp/version.log 2>&1; then
    cat /tmp/version.log
elif /tmp/agentshield-bin --help > /tmp/help.log 2>&1; then
    head -3 /tmp/help.log
else
    echo "binary answered neither version nor --help:"
    tail -20 /tmp/version.log /tmp/help.log
    exit 1
fi
echo "Binary: OK"

echo ""
echo "=== [4/5] Run unit tests ==="
# THE gate: these two packages are what verifies the stripped tree still
# enforces. No pipe, so a failing test exits non-zero here and fails the run.
# Full output is kept on purpose: the parity fitness functions print the exact
# commands that leaked, which is the only useful diagnostic when they trip.
#
# The timeout is per test binary. internal/analyzer runs the whole corpus
# through several parity sweeps: ~150s for the OSS rule set and ~610s with
# premium loaded (measured 2026-07-28, cold cache, native arm64), so the 120s
# this used to pass was itself a guaranteed failure -- another one the
# swallowed status was hiding. Headroom is deliberate: a slow CI box must not
# turn this gate red for a reason that has nothing to do with the OSS build.
# AGENTSHIELD_OSS_MEASURE_GAP keeps the premium-sized tests running here. In a
# plain clone they SKIP (internal/ossbuild.SkipPremiumSized); here their failures
# are the free-tier gap scripts/oss-known-failures.txt records, and skipping them
# would empty that file on the next --refresh.
AGENTSHIELD_OSS_MEASURE_GAP=1 go test ./internal/policy/ ./internal/analyzer/ -count=1 -timeout 1800s
echo "Tests: OK"

echo ""
echo "=== [5/5] Sanity check: command evaluation ==="
# Setup creates config dir
mkdir -p ~/.agentshield

# agentshield scan is the shipped self-test: it runs a fixed set of commands
# through the embedded packs. It reports findings and ALWAYS exits 0, so its
# status is not a pass/fail signal -- the summary line is. This is the only
# step that exercises the binary a user actually installs, so assert on it
# rather than the previous "| head -10 || true", which could not fail twice
# over. A non-zero status here means the binary crashed, which is also fatal.
if ! /tmp/agentshield-bin scan > /tmp/scan.log 2>&1; then
    echo "scan FAILED to run:"
    tail -20 /tmp/scan.log
    exit 1
fi
head -10 /tmp/scan.log
echo "..."
if ! grep -E "All [0-9]+ tests passed" /tmp/scan.log; then
    echo "scan self-test did not report a clean pass:"
    cat /tmp/scan.log
    exit 1
fi
echo "Sanity: OK"

echo ""
echo "========================================="
echo "  ALL INTEGRATION TESTS PASSED"
echo "========================================="
' || DOCKER_STATUS=$?

# Captured explicitly: with "set -e" a bare "docker run" failure aborted the
# script before this point, so the FAILED branch below was unreachable and a
# broken OSS build exited quietly.
echo ""
if [ "$DOCKER_STATUS" -eq 0 ]; then
    echo "Integration test: PASSED"
else
    echo "Integration test: FAILED (exit code $DOCKER_STATUS)"
    exit 1
fi
