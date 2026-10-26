#!/usr/bin/env bash
# Test for generate-cask.sh: `brew uninstall --zap --cask agentshield` must
# remove the agent hooks `agentshield setup` wrote, and nothing on the upgrade
# path may (#4491).
#
# Why the hook removal is in `zap` and nowhere else: Homebrew runs a cask's
# uninstall stanza and uninstall flight blocks on every `brew upgrade`,
# `brew reinstall` and `brew install` of an outdated cask, and a flight block
# cannot tell those from an uninstall. Removing hooks there would strip
# protection on each upgrade, silently. Zap runs only on `brew uninstall --zap`.
#
# What this proves:
#   - the generated cask has a zap script that runs `setup <agent> --disable`
#     for every agent setup supports, plus `setup mcp --disable`;
#   - that script really runs each one, carries on past a failure (a managed
#     host refuses --disable), puts the staged binary first on PATH (setup mcp
#     looks agentshield up on PATH before it restores anything) and exits 0;
#   - nothing in the cask deletes ~/.agentshield (the audit log is evidence);
#   - no uninstall stanza or uninstall flight block runs setup;
#   - the caveats tell the user about --zap;
#   - the output parses as Ruby (when ruby is installed).
# What it does not prove: that Homebrew runs the zap stanza as described. That
# is the clean-install test in AI-AgentLens/homebrew-tap, against the published
# cask.
#
# Run: bash scripts/generate-cask_test.sh
set -uo pipefail

GEN="$(cd "$(dirname "$0")" && pwd)/generate-cask.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail=0

ok()  { echo "  ok: $1"; }
bad() { echo "  FAIL: $1"; fail=1; }
has() { # <desc> <file> <fixed string>
  if grep -qF -- "$3" "$2"; then ok "$1"; else bad "$1 (missing: $3)"; fi
}

# The agents `agentshield setup` supports (agentshield setup --help). Written
# out here, not read from the generator, so dropping one there fails here.
AGENTS="claude-code gemini-cli codex copilot-cli windsurf cursor openclaw mcp"

# --- generate ---------------------------------------------------------------
mkdir -p "$TMP/dist"
for a in darwin_amd64 darwin_arm64 linux_amd64 linux_arm64; do
  echo "$a" > "$TMP/dist/agentshield_9.9.9_${a}.tar.gz"
done
CASK="$TMP/agentshield.rb"
if ! bash "$GEN" v9.9.9 "$TMP/dist" "$CASK" > "$TMP/gen.out" 2>&1; then
  bad "generate-cask.sh exited non-zero: $(cat "$TMP/gen.out")"
  exit 1
fi

echo "zap stanza"
has "cask has a zap script" "$CASK" "zap script: {"
has "zap script is non-fatal" "$CASK" "must_succeed: false,"

# The zap stanza runs from "zap script:" to the closing "  }".
sed -n '/^  zap script: {/,/^  }$/p' "$CASK" > "$TMP/zap.rb"
[ -s "$TMP/zap.rb" ] || bad "could not isolate the zap stanza"
has "zap runs the staged binary" "$TMP/zap.rb" '"#{staged_path}/agentshield"'
for a in $AGENTS; do
  if grep -qE "for agent in .*\\b${a}\\b" "$TMP/zap.rb"; then ok "zap covers $a"
  else bad "zap does not cover $a"; fi
done

echo "nothing deletes ~/.agentshield"
# "/.agentshield", so the launchd plist com.aiagentlens.agentshield.plist does not count.
if grep -nE '(trash|delete|rmdir):' "$CASK" | grep -q '/\.agentshield'; then
  bad "a trash/delete/rmdir entry names ~/.agentshield: $(grep -nE '(trash|delete|rmdir):' "$CASK" | grep '/\.agentshield')"
else
  ok "no trash/delete/rmdir entry names ~/.agentshield"
fi
if grep -qE '(rm|trash)[[:space:]].*/\.agentshield' "$TMP/zap.rb"; then
  bad "the zap script removes ~/.agentshield"
else
  ok "the zap script does not remove ~/.agentshield"
fi

echo "nothing on the upgrade path removes hooks"
if grep -qE '^  uninstall_(preflight|postflight)' "$CASK"; then
  bad "cask has an uninstall flight block (runs on every brew upgrade)"
else
  ok "no uninstall flight block"
fi
# The uninstall stanza is "  uninstall ..." up to the next blank line.
sed -n '/^  uninstall /,/^$/p' "$CASK" > "$TMP/uninstall.rb"
if grep -qE 'script|setup|--disable' "$TMP/uninstall.rb"; then
  bad "the uninstall stanza runs a script or setup (runs on every brew upgrade)"
else
  ok "uninstall stanza runs no script and no setup"
fi

echo "caveats"
has "caveats name the zap uninstall" "$CASK" "brew uninstall --zap --cask agentshield"

# --- run the zap script against a fake binary --------------------------------
# The script body is the Ruby heredoc between <<~'SH' and SH. A single-quoted
# heredoc is taken literally, so this is the exact text /bin/sh receives.
echo "zap script runs"
sed -n "/<<~'SH'/,/^ *SH\$/p" "$CASK" | sed '1d;$d' > "$TMP/zap.sh"
[ -s "$TMP/zap.sh" ] || bad "could not extract the zap shell script"
mkdir -p "$TMP/stage" "$TMP/run"
cat > "$TMP/stage/agentshield" <<FAKE
#!/bin/sh
echo "\$*|\$(command -v agentshield)" >> "$TMP/calls.log"
# A managed host refuses --disable with exit 1; stand that in for codex.
[ "\$2" = codex ] && { echo "Error: cannot disable hooks in managed mode"; exit 1; }
echo "disabled \$2"
FAKE
chmod +x "$TMP/stage/agentshield"
( cd "$TMP/run" && PATH=/usr/bin:/bin /bin/sh -c "$(cat "$TMP/zap.sh")" "$TMP/stage/agentshield" ) > "$TMP/zap.out" 2>&1
rc=$?
if [ "$rc" -eq 0 ]; then ok "zap script exits 0"; else bad "zap script exited $rc"; fi
want=$(for a in $AGENTS; do echo "setup $a --disable|$TMP/stage/agentshield"; done)
if [ "$(cat "$TMP/calls.log" 2>/dev/null)" = "$want" ]; then
  ok "ran setup <agent> --disable for all 8, in order, with the staged binary first on PATH"
else
  bad "calls differ. want:"; echo "$want" | sed 's/^/      /'
  echo "    got:"; sed 's/^/      /' "$TMP/calls.log" 2>/dev/null
fi
has "a refused agent is reported, not fatal" "$TMP/zap.out" "not removed (exit 1)"
has "agents after a refusal still run" "$TMP/zap.out" "disabled mcp"
has "says ~/.agentshield is kept" "$TMP/zap.out" "~/.agentshield kept"

# --- Ruby syntax ---------------------------------------------------------------
echo "ruby syntax"
if command -v ruby > /dev/null 2>&1; then
  if ruby -c "$CASK" > "$TMP/ruby.out" 2>&1; then ok "ruby -c: $(cat "$TMP/ruby.out")"
  else bad "ruby -c failed: $(cat "$TMP/ruby.out")"; fi
else
  echo "  skip: ruby not installed (the zap checks above still ran)"
fi

if [ "$fail" -ne 0 ]; then echo "FAIL"; exit 1; fi
echo "PASS"
