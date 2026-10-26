#!/usr/bin/env bash
# install-live-binary.sh — give the live hook its own copy of the binary (#4390).
#
# The live link (/opt/homebrew/bin/agentshield) used to point straight at this
# checkout's build/agentshield. Every later `make build` or `make check`, on any
# branch, then rewrote the binary the hook was running, with no deploy at all.
# On 2026-10-17 the dev machine was enforcing with an unmerged PR branch's build.
# A rewrite in progress can also leave the hook a missing or partial file, and
# Claude Code treats a hook that fails that way as non-blocking, so the window
# fails open.
#
# So `make deploy`, and only `make deploy`, installs a COPY outside the working
# tree and points the link at that copy. The copy is written beside the
# destination and renamed over it. The swap is atomic: a hook exec sees the old
# file or the new one, never a half-written one. The new file is also a new
# inode, so no cached code signature is invalidated (the SIGKILL 137 shape).
#
# Usage:  scripts/install-live-binary.sh <built-binary> <install-path>
# Exit:   0 = installed; 1 = could not install (dest left as it was);
#         2 = usage error / source missing.
set -uo pipefail

SRC="${1:-}"
DEST="${2:-}"
if [ -z "$SRC" ] || [ -z "$DEST" ]; then
  echo "usage: $0 <built-binary> <install-path>" >&2
  exit 2
fi
if [ ! -f "$SRC" ] || [ ! -x "$SRC" ]; then
  echo "  ❌ install-live-binary: $SRC is missing or not executable — run make build first" >&2
  exit 2
fi

dir="$(dirname "$DEST")"
mkdir -p "$dir" || { echo "  ❌ install-live-binary: cannot create $dir" >&2; exit 1; }
tmp="$dir/.$(basename "$DEST").tmp.$$"
trap 'rm -f "$tmp"' EXIT

cp "$SRC" "$tmp" && chmod 755 "$tmp" || { echo "  ❌ install-live-binary: copy to $tmp failed" >&2; exit 1; }
if [ "$(uname -s)" = "Darwin" ] && command -v codesign >/dev/null 2>&1; then
  codesign --force -s - "$tmp" 2>/dev/null \
    || echo "  ⚠️  codesign of the installed copy failed — it may die with SIGKILL 137 on exec."
fi
mv -f "$tmp" "$DEST" || { echo "  ❌ install-live-binary: rename onto $DEST failed" >&2; exit 1; }
trap - EXIT
echo "  ✅ live binary installed: $DEST (a copy; later builds in this checkout do not touch it)"
