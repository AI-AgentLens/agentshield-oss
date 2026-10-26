#!/usr/bin/env bash
# Smoke test for install-live-binary.sh (#4390). Everything runs in a temp dir;
# it never touches ~/.agentshield or /opt/homebrew/bin.
#
# The property under test is the issue itself: after an install, rebuilding the
# source in place must leave the installed copy byte-for-byte unchanged.
#
# Run: bash scripts/install-live-binary_test.sh
set -uo pipefail

SUT="$(cd "$(dirname "$0")" && pwd)/install-live-binary.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail=0
ok()  { echo "  ok: $1"; }
bad() { echo "  FAIL: $1"; fail=1; }
inode() { ls -i "$1" | awk '{print $1}'; }

SRC="$TMP/repo/build/agentshield"; mkdir -p "$(dirname "$SRC")"
printf '#!/bin/sh\necho v1\n' > "$SRC"; chmod +x "$SRC"
DEST="$TMP/home/.agentshield/bin/agentshield"

echo "install-live-binary (#4390):"

# 1. Fresh install creates the directory and an identical, runnable copy.
bash "$SUT" "$SRC" "$DEST" > "$TMP/o1" 2>&1; rc=$?
[ "$rc" = 0 ] && ok "fresh install exits 0" || bad "fresh install exit $rc: $(cat "$TMP/o1")"
cmp -s "$SRC" "$DEST" && ok "installed copy matches the build" || bad "installed copy differs from the build"
[ -x "$DEST" ] && [ "$("$DEST")" = "v1" ] && ok "installed copy runs" || bad "installed copy not runnable"
[ ! -L "$DEST" ] && ok "installed copy is a file, not a link into the checkout" || bad "dest is a symlink"

# 2. THE ISSUE: rebuilding the source in place leaves the live copy alone.
printf '#!/bin/sh\necho branch-build\n' > "$SRC"
[ "$("$DEST")" = "v1" ] && ok "a later build in the checkout does not change the live copy" \
  || bad "the live copy followed a rebuild of the checkout (#4390 regression)"

# 3. Re-install replaces by rename: new bytes AND a new inode (never an in-place write).
before=$(inode "$DEST")
bash "$SUT" "$SRC" "$DEST" > "$TMP/o3" 2>&1
[ "$("$DEST")" = "branch-build" ] && ok "re-install delivers the new build" || bad "re-install did not update the copy"
[ "$(inode "$DEST")" != "$before" ] && ok "re-install swapped by rename (new inode)" || bad "re-install wrote in place (same inode)"
ls -a "$(dirname "$DEST")" | grep -q '\.tmp\.' && bad "temp file left behind" || ok "no temp file left behind"

# 4. Missing source: exit 2, live copy untouched.
cp "$DEST" "$TMP/keep"
bash "$SUT" "$TMP/nope" "$DEST" > "$TMP/o4" 2>&1; rc=$?
[ "$rc" = 2 ] && ok "missing source exits 2" || bad "missing source exit $rc"
cmp -s "$TMP/keep" "$DEST" && ok "missing source leaves the live copy as it was" || bad "live copy changed on a failed install"

# 5. Usage error.
bash "$SUT" > /dev/null 2>&1; rc=$?
[ "$rc" = 2 ] && ok "no arguments exits 2" || bad "no arguments exit $rc"

[ "$fail" = 0 ] && echo "install-live-binary: all passed" || { echo "install-live-binary: FAILED"; exit 1; }
