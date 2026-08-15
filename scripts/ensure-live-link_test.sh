#!/usr/bin/env bash
# Smoke test for ensure-live-link.sh — proves the guard can fail, and that the
# one sentence that matters (naming the OLD target on a repair) is actually
# printed (#3141).
#
# Everything runs against a temp prefix. This test must never touch a real
# /opt/homebrew/bin.
#
# Run: bash scripts/ensure-live-link_test.sh
set -uo pipefail

GUARD="$(cd "$(dirname "$0")" && pwd)/ensure-live-link.sh"
TMP="$(mktemp -d)"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
fail=0

check() { # <desc> <expected_exit> <actual_exit>
  if [ "$2" -eq "$3" ]; then echo "  ok: $1 (exit $3)"
  else echo "  FAIL: $1 — expected exit $2 got $3"; fail=1; fi
}
contains() { # <desc> <file> <needle>
  if grep -qF -- "$3" "$2"; then echo "  ok: $1"
  else echo "  FAIL: $1 — output did not mention '$3'"; fail=1; fi
}
not_contains() { # <desc> <file> <needle>
  if grep -qF -- "$3" "$2"; then echo "  FAIL: $1 — output should not mention '$3'"; fail=1
  else echo "  ok: $1"; fi
}
links_to() { # <desc> <link> <expected target>
  local actual
  actual="$(readlink "$2" 2>/dev/null)"
  if [ "$actual" = "$3" ]; then echo "  ok: $1"
  else echo "  FAIL: $1 — $2 -> '${actual:-<not a symlink>}', expected '$3'"; fail=1; fi
}

# A stand-in for ./build/agentshield and for a rival clone's build dir.
BUILD="$TMP/repo/build"; mkdir -p "$BUILD"; echo "fresh" > "$BUILD/agentshield"
OTHER="$TMP/other-clone/build"; mkdir -p "$OTHER"; echo "stale" > "$OTHER/agentshield"
TARGET="$(cd "$BUILD" && pwd -P)/agentshield"
STALE="$(cd "$OTHER" && pwd -P)/agentshield"

BIN="$TMP/prefix/bin"; mkdir -p "$BIN"
LINK="$BIN/agentshield"

echo "ensure-live-link guard (#3141):"

# ── Case 1: already correct -> quiet no-op ──────────────────────────────────
# The stale-repair banner must NOT fire here. A guard that always shouts is a
# guard people stop reading, and it would let case 2's assertion pass vacuously.
ln -sfn "$TARGET" "$LINK"
bash "$GUARD" "$LINK" "$TARGET" > "$TMP/out1.txt" 2>&1
check "correct link -> pass" 0 $?
contains "confirms the link is OK" "$TMP/out1.txt" "live link OK"
not_contains "does not cry wolf on a correct link" "$TMP/out1.txt" "WAS STALE"
links_to "leaves the link alone" "$LINK" "$TARGET"

# ── Case 2: symlink points elsewhere -> repair, LOUDLY ──────────────────────
# This is the #3141 case: the link pointed at another clone's build dir, so the
# nightly rebuilt a binary nothing ran. Naming the old target is the entire
# value of this guard.
ln -sfn "$STALE" "$LINK"
bash "$GUARD" "$LINK" "$TARGET" > "$TMP/out2.txt" 2>&1
check "wrong target -> repaired" 0 $?
contains "announces the repair loudly" "$TMP/out2.txt" "LIVE LINK WAS STALE"
contains "names the OLD target" "$TMP/out2.txt" "$STALE"
contains "names the new target" "$TMP/out2.txt" "$TARGET"
links_to "link actually repointed" "$LINK" "$TARGET"

# ── Case 3: missing -> create ───────────────────────────────────────────────
rm -f "$LINK"
bash "$GUARD" "$LINK" "$TARGET" > "$TMP/out3.txt" 2>&1
check "missing link -> created" 0 $?
contains "says it created the link" "$TMP/out3.txt" "live link missing"
links_to "link created" "$LINK" "$TARGET"

# ── Case 4: regular file -> refuse, do NOT clobber ──────────────────────────
# Someone may have installed a real binary here on purpose.
rm -f "$LINK"; echo "somebody-elses-binary" > "$LINK"
bash "$GUARD" "$LINK" "$TARGET" > "$TMP/out4.txt" 2>&1
check "regular file -> refuse" 1 $?
contains "says it is a regular file" "$TMP/out4.txt" "not a symlink"
contains "offers the override" "$TMP/out4.txt" "AGENTSHIELD_LINK_FORCE=1"
if [ "$(cat "$LINK")" = "somebody-elses-binary" ]; then echo "  ok: did not clobber the file"
else echo "  FAIL: the regular file was destroyed"; fail=1; fi

# ── Case 4b: regular file + explicit override -> replace ────────────────────
AGENTSHIELD_LINK_FORCE=1 bash "$GUARD" "$LINK" "$TARGET" > "$TMP/out4b.txt" 2>&1
check "regular file + force -> replaced" 0 $?
links_to "force converted it to a symlink" "$LINK" "$TARGET"

# ── Case 5: not writable -> clear message, not a confusing EACCES ───────────
if [ "$(id -u)" -eq 0 ]; then
  echo "  SKIP: unwritable-dir case (running as root; chmod would not deny root)"
else
  RO="$TMP/ro/bin"; mkdir -p "$RO"; chmod 500 "$RO"
  bash "$GUARD" "$RO/agentshield" "$TARGET" > "$TMP/out5.txt" 2>&1
  check "unwritable dir -> fail" 1 $?
  contains "says the directory is not writable" "$TMP/out5.txt" "is not writable"
  contains "tells you how to fix it" "$TMP/out5.txt" "sudo ln -sfn"
  chmod 700 "$RO"
fi

# ── Case 6: Homebrew-managed symlink -> refuse by default ───────────────────
# `brew` owns /opt/homebrew/bin/agentshield when the cask is installed (it
# declares `binary "agentshield"`). Repointing it desyncs brew AND gets reverted
# by the next `brew upgrade --cask`, which would re-create #3141 silently.
CASK="$TMP/prefix/Caskroom/agentshield/1.0"; mkdir -p "$CASK"; echo "brew" > "$CASK/agentshield"
CASK_BIN="$(cd "$CASK" && pwd -P)/agentshield"
ln -sfn "$CASK_BIN" "$LINK"
bash "$GUARD" "$LINK" "$TARGET" > "$TMP/out6.txt" 2>&1
check "brew-managed link -> refuse" 1 $?
contains "says it is Homebrew-managed" "$TMP/out6.txt" "Homebrew-managed"
contains "names the brew target" "$TMP/out6.txt" "$CASK_BIN"
links_to "brew link left intact" "$LINK" "$CASK_BIN"

AGENTSHIELD_LINK_FORCE=1 bash "$GUARD" "$LINK" "$TARGET" > "$TMP/out6b.txt" 2>&1
check "brew-managed link + force -> repaired" 0 $?
links_to "force repointed the brew link" "$LINK" "$TARGET"

# A Cellar path (formula install) is the same call.
CELLAR="$TMP/prefix/Cellar/agentshield/1.0/bin"; mkdir -p "$CELLAR"; echo "brew" > "$CELLAR/agentshield"
ln -sfn "$(cd "$CELLAR" && pwd -P)/agentshield" "$LINK"
bash "$GUARD" "$LINK" "$TARGET" > "$TMP/out6c.txt" 2>&1
check "Cellar link -> refuse too" 1 $?

# ── Case 7: relative symlinks resolve like the kernel resolves them ─────────
# A relative link to the right file must read as correct, not as a stale link
# needing repair — otherwise the guard rewrites a working install every run.
ln -sfn "../../repo/build/agentshield" "$LINK"
bash "$GUARD" "$LINK" "$TARGET" > "$TMP/out7.txt" 2>&1
check "relative link to the right file -> pass" 0 $?
not_contains "does not rewrite a correct relative link" "$TMP/out7.txt" "WAS STALE"

# ── Case 7b: dangling symlink -> repair ─────────────────────────────────────
# The realistic end state of #3141: the link still points into the scratch clone
# after that clone is deleted. `[ -e ]` is false but `[ -L ]` is true, so a guard
# that keys off existence alone would take the "missing" path and never report
# what the link used to point at.
GONE="$TMP/deleted-clone/build/agentshield"
mkdir -p "$(dirname "$GONE")"; : > "$GONE"
ln -sfn "$GONE" "$LINK"
rm -rf "$TMP/deleted-clone"
bash "$GUARD" "$LINK" "$TARGET" > "$TMP/out7b.txt" 2>&1
check "dangling link -> repaired" 0 $?
contains "reports it as stale, not as missing" "$TMP/out7b.txt" "LIVE LINK WAS STALE"
contains "still names the vanished target" "$TMP/out7b.txt" "deleted-clone"
links_to "dangling link repaired" "$LINK" "$TARGET"

# ── Case 8: usage errors are distinct from findings ─────────────────────────
bash "$GUARD" >/dev/null 2>&1;                 check "no args -> exit 2" 2 $?
bash "$GUARD" "$LINK" >/dev/null 2>&1;         check "one arg -> exit 2" 2 $?
bash "$GUARD" "$LINK" "$TMP/nope" > "$TMP/out8.txt" 2>&1
check "missing build target -> exit 2" 2 $?
contains "explains the missing build" "$TMP/out8.txt" "run 'make build' first"

if [ "$fail" -eq 0 ]; then echo "ALL PASS"; else echo "FAILURES"; fi
exit "$fail"
