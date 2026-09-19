#!/usr/bin/env bash
# Positive control for publish-oss.sh's private-identifier scan (#3627): the
# scan must reject a backslash-spelled home path, a mixed-separator one and the
# forward-slash form, and must accept a tree with none. Identifiers are built
# from pieces at runtime so this file never contains one itself.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
script="$here/publish-oss.sh"
pass=0; fail=0
check() { # name expected_status dir
    local name="$1" want="$2" dir="$3" got
    if bash "$script" --scan-only "$dir" >/dev/null 2>&1; then got=0; else got=$?; fi
    if [[ "$got" == "$want" ]]; then echo "ok   $name"; pass=$((pass+1)); else echo "FAIL $name (exit $got, want $want)"; fail=$((fail+1)); fi
}
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
first="ga"; last="ry"; who="$first$last"
bs='\'
mk() { mkdir -p "$tmp/$1"; printf '%s\n' "$2" > "$tmp/$1/fixture.txt"; }
mk fwd    "C:/Users/$who/.ssh/id_rsa"
mk back   "C:${bs}Users${bs}$who${bs}.ssh${bs}id_rsa"
mk lower  "c:${bs}users${bs}$who${bs}.aws${bs}credentials"
mk mixed  "C:${bs}Users${bs}$who/.ssh${bs}known_hosts"
mk clean  "C:${bs}Users${bs}nobody${bs}.ssh${bs}id_rsa and /home/user/.aws/credentials"
check "forward-slash home path is rejected"     1 "$tmp/fwd"
check "backslash home path is rejected"         1 "$tmp/back"
check "lower-case backslash path is rejected"   1 "$tmp/lower"
check "mixed-separator path is rejected"        1 "$tmp/mixed"
check "clean tree passes (negative control)"    0 "$tmp/clean"
check "missing directory argument is an error"  2 ""
echo "$pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
