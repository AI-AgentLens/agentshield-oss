#!/usr/bin/env bash
# publish-oss.sh — Publish a filtered copy of AI_Agent_Shield to the agentshield-oss public repo.
#
# Usage:
#   ./scripts/publish-oss.sh              # dry run (shows what would be excluded)
#   ./scripts/publish-oss.sh --publish    # actually push to public repo
#
# Prerequisites:
#   - Public repo exists: github.com/AI-AgentLens/agentshield-oss
#   - git remote 'oss' is configured (or will be added automatically)
#
# What gets excluded from the public repo:
#   - packs/premium/             (premium rule packs)
#   - packs/packs_premium.go     (premium MCP pack embed)
#   - packs/_*.yaml              (disabled legacy pack files)
#   - scripts/baby-kai-*         (internal agent prompts)
#   - scripts/supervisor-kai.md  (internal agent prompt)
#   - scripts/logs/              (internal agent logs)
#   - RULE_REVIEW.md             (internal review notes)
#   - FAILING_TESTS.md           (internal tracking)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

OSS_REMOTE="oss"
OSS_REPO="git@github.com:AI-AgentLens/agentshield-oss.git"
OSS_BRANCH="main"
PUBLISH=false

if [[ "${1:-}" == "--publish" ]]; then
    PUBLISH=true
fi

# Files and directories to exclude from OSS
EXCLUDES=(
    "packs/premium/"
    "packs/packs_premium.go"
    "packs/_*.yaml"
    "scripts/baby-kai-*.md"
    "scripts/supervisor-kai.md"
    "scripts/baby-kai-opus-deepdive-*.md"
    "scripts/logs/"
    "scripts/prompt-backups/"
    "RULE_REVIEW.md"
    "FAILING_TESTS.md"
)

echo "=== AgentShield OSS Publish ==="
echo "Source: $REPO_ROOT ($(git rev-parse --short HEAD))"
echo ""
echo "Excluded from OSS:"
for ex in "${EXCLUDES[@]}"; do
    # Count matching files
    count=$(find . -path "./$ex" 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$count" -gt 0 ]]; then
        echo "  - $ex ($count files)"
    else
        echo "  - $ex (pattern)"
    fi
done

if [[ "$PUBLISH" != "true" ]]; then
    echo ""
    echo "Dry run complete. Use --publish to push to $OSS_REPO"
    exit 0
fi

# Ensure the OSS remote exists
if ! git remote get-url "$OSS_REMOTE" &>/dev/null; then
    echo ""
    echo "Adding remote '$OSS_REMOTE' → $OSS_REPO"
    git remote add "$OSS_REMOTE" "$OSS_REPO"
fi

# Create a temporary branch for the filtered content
TEMP_BRANCH="oss-publish-$(date +%s)"
echo ""
echo "Creating filtered branch: $TEMP_BRANCH"

git checkout -b "$TEMP_BRANCH"

# Remove excluded files
for ex in "${EXCLUDES[@]}"; do
    git rm -rf --ignore-unmatch "$ex" 2>/dev/null || true
done

# Commit the filtered state
git commit -m "Publish $(git describe --tags --always) to agentshield-oss

Filtered from AI_Agent_Shield $(git rev-parse --short HEAD~1).
Premium packs and internal files excluded."

# Push to OSS remote
echo ""
echo "Pushing to $OSS_REMOTE/$OSS_BRANCH..."
git push "$OSS_REMOTE" "$TEMP_BRANCH:$OSS_BRANCH" --force

# Clean up: go back to main and delete temp branch
git checkout main
git branch -D "$TEMP_BRANCH"

echo ""
echo "Published to $OSS_REPO ($OSS_BRANCH)"
echo "Done."
