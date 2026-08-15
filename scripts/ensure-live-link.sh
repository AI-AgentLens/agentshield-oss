#!/usr/bin/env bash
# ensure-live-link.sh — make the live `agentshield` on PATH actually point at the
# binary this repo just built, instead of assuming it already does (#3141).
#
# The assumption failed once, quietly, for a long time. `make deploy` refreshed
# ~/.agentshield/packs/ correctly and rebuilt ./build/agentshield correctly, but
# /opt/homebrew/bin/agentshield pointed at a *different* clone's build dir
# (~/dev/baby-kai/shield-workspace/build/agentshield). Rules shipped; the engine
# that reads them did not. Every symptom pointed at rules, so nobody looked at
# the engine for months.
#
# The load-bearing line in this script is not the repair — it is the sentence
# that names the *old* target when a repair happens. That sentence is what would
# have surfaced the drift on the first nightly run.
#
# Usage:  scripts/ensure-live-link.sh <link-path> <target-path>
#
# Exit:   0 = link now points at <target-path> (was already correct, repaired,
#             or created)
#         1 = refused or unable — needs a human decision. Never a silent pass.
#         2 = usage error (bad arguments, missing target)
#
# Override: AGENTSHIELD_LINK_FORCE=1 proceeds through the two refusals below.
#
# Deliberate refusals (both are "someone may have meant this"):
#
#   * <link-path> is a regular file, not a symlink. Someone may have installed a
#     real binary there on purpose. Replacing it destroys it.
#
#   * <link-path> is a symlink into a Homebrew store directory (.../Cellar/... or
#     .../Caskroom/...). That is a live `brew` install: the AgentShield cask
#     declares `binary "agentshield"`, so brew owns that symlink. Stomping it
#     desyncs brew's bookkeeping AND is temporary — the next `brew upgrade
#     --cask agentshield` relinks it back to the Caskroom and the deploy
#     silently disconnects all over again. Uninstall the cask, or accept that
#     the repair is not durable.
set -uo pipefail

LINK="${1:-}"
TARGET="${2:-}"
FORCE="${AGENTSHIELD_LINK_FORCE:-0}"

if [ -z "$LINK" ] || [ -z "$TARGET" ]; then
  echo "usage: $0 <link-path> <target-path>" >&2
  exit 2
fi

# Canonicalise a path: resolve symlinks in the *directory* part, leave the final
# component alone (so a symlink's own path is not followed through). Portable —
# `readlink -f` and `realpath` are not on every macOS in the fleet.
abspath() {
  local p="$1" d b
  d="$(dirname "$p")"
  b="$(basename "$p")"
  # Runs in a command substitution, so the cd is confined to that subshell.
  if cd "$d" 2>/dev/null; then
    printf '%s/%s\n' "$(pwd -P)" "$b"
  else
    printf '%s\n' "$p"
  fi
}

# Where a symlink actually points, canonicalised. Relative link values are
# resolved against the link's own directory, the way the kernel does it.
link_target() {
  local link="$1" t
  t="$(readlink "$link")" || return 1
  case "$t" in
    /*) ;;
     *) t="$(dirname "$link")/$t" ;;
  esac
  abspath "$t"
}

# Homebrew's two store directories. A symlink into either means brew put it
# there; the prefix varies (/opt/homebrew, /usr/local, /home/linuxbrew/...) but
# these two path components do not.
is_brew_managed() {
  case "$1" in
    */Cellar/*|*/Caskroom/*) return 0 ;;
    *) return 1 ;;
  esac
}

if [ ! -e "$TARGET" ]; then
  echo "ensure-live-link: build target does not exist: $TARGET" >&2
  echo "                  run 'make build' first." >&2
  exit 2
fi

TARGET_ABS="$(abspath "$TARGET")"
LINK_ABS="$(abspath "$LINK")"
LINK_DIR="$(dirname "$LINK_ABS")"

# ── Case: already correct ───────────────────────────────────────────────────
if [ -L "$LINK" ]; then
  CURRENT="$(link_target "$LINK")"
  if [ "$CURRENT" = "$TARGET_ABS" ]; then
    echo "  ✅ live link OK: $LINK -> $TARGET_ABS"
    exit 0
  fi
fi

# ── Case: not writable ──────────────────────────────────────────────────────
# Checked before any refusal so the message is about permissions, not about a
# decision the user cannot act on anyway. Creating or replacing a symlink writes
# to the *directory*, not to the link, so the directory is what must be writable.
if [ ! -d "$LINK_DIR" ]; then
  echo "  ❌ live link: directory does not exist: $LINK_DIR" >&2
  echo "     Create it, or point the deploy somewhere else." >&2
  exit 1
fi
if [ ! -w "$LINK_DIR" ]; then
  echo "  ❌ live link: $LINK_DIR is not writable by $(id -un)." >&2
  echo "     The binary at $TARGET_ABS is fresh, but nothing on PATH points at it." >&2
  echo "     Fix with:  sudo ln -sfn $TARGET_ABS $LINK" >&2
  exit 1
fi

# ── Case: exists but is not a symlink ───────────────────────────────────────
if [ -e "$LINK" ] && [ ! -L "$LINK" ]; then
  KIND="regular file"
  [ -d "$LINK" ] && KIND="directory"

  if [ -d "$LINK" ]; then
    echo "  ❌ live link: $LINK is a directory. Refusing to touch it, force or not." >&2
    exit 1
  fi

  if [ "$FORCE" != "1" ]; then
    echo "  ❌ live link: $LINK is a $KIND, not a symlink." >&2
    echo "     Refusing to replace it — someone may have installed a real binary" >&2
    echo "     there on purpose, and overwriting it silently is how a deploy" >&2
    echo "     destroys something it did not create." >&2
    echo "     To replace it with a symlink to this build, re-run with:" >&2
    echo "         AGENTSHIELD_LINK_FORCE=1 make deploy" >&2
    exit 1
  fi
  echo "  ⚠️  $LINK is a $KIND, not a symlink."
  echo "      AGENTSHIELD_LINK_FORCE=1 — replacing it with a symlink to this build."
  rm -f "$LINK" || { echo "  ❌ live link: could not remove $LINK" >&2; exit 1; }
  CREATED_FROM_FILE=1
fi

# ── Case: symlink pointing somewhere else ───────────────────────────────────
if [ -L "$LINK" ]; then
  CURRENT="$(link_target "$LINK")"
  RAW="$(readlink "$LINK")"

  if is_brew_managed "$CURRENT"; then
    if [ "$FORCE" != "1" ]; then
      echo "  ❌ live link: $LINK is a Homebrew-managed symlink." >&2
      echo "     It points at:  $CURRENT" >&2
      echo "     That is a live brew install (the agentshield cask declares" >&2
      echo "     'binary \"agentshield\"', so brew owns this path). Repointing it" >&2
      echo "     desyncs brew's bookkeeping, and 'brew upgrade --cask agentshield'" >&2
      echo "     will relink it back — silently disconnecting the deploy again." >&2
      echo "     Either:  brew uninstall --cask agentshield   (recommended for dev machines)" >&2
      echo "     or:      AGENTSHIELD_LINK_FORCE=1 make deploy   (repair now, brew may revert it)" >&2
      exit 1
    fi
    echo "  ⚠️  $LINK is a Homebrew-managed symlink ($CURRENT)."
    echo "      AGENTSHIELD_LINK_FORCE=1 — repointing it anyway. brew may revert this."
  fi

  # THE line. #3141 went unnoticed because nothing ever printed the old target.
  echo "  ⚠️  LIVE LINK WAS STALE — repointing $LINK"
  echo "      was: $CURRENT"
  [ "$RAW" != "$CURRENT" ] && echo "           (link value: $RAW)"
  echo "      now: $TARGET_ABS"
  echo "      Every 'agentshield' run since that link was set used the OLD binary."
  ln -sfn "$TARGET_ABS" "$LINK" || { echo "  ❌ live link: ln failed for $LINK" >&2; exit 1; }
else
  # ── Case: missing ─────────────────────────────────────────────────────────
  if [ "${CREATED_FROM_FILE:-0}" != "1" ]; then
    echo "  ➕ live link missing — creating $LINK -> $TARGET_ABS"
  fi
  ln -sfn "$TARGET_ABS" "$LINK" || { echo "  ❌ live link: ln failed for $LINK" >&2; exit 1; }
fi

# Never trust the write. `ln -sfn` onto an existing *directory* symlink creates a
# link *inside* it instead of replacing it, which would leave the old link in
# place while reporting success.
FINAL="$(link_target "$LINK" 2>/dev/null || echo "<not a symlink>")"
if [ "$FINAL" != "$TARGET_ABS" ]; then
  echo "  ❌ live link: repair did not take. $LINK now resolves to: $FINAL" >&2
  exit 1
fi
echo "  ✅ live link now: $LINK -> $TARGET_ABS"
exit 0
