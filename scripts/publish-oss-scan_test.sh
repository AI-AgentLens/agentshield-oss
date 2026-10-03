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
check "a scan that errors is not clean"          2 "$tmp/does-not-exist"

# History scan (--scan-history): the identifier lives only in an OLD revision.
# Before 2026-10-02 this layer never ran. Every revision went to git grep as ONE
# argument, git grep exited 128, and the publish read that as clean.
hcheck() { # name expected_status repo
    local name="$1" want="$2" dir="$3" got
    if bash "$script" --scan-history "$dir" >/dev/null 2>&1; then got=0; else got=$?; fi
    if [[ "$got" == "$want" ]]; then echo "ok   $name"; pass=$((pass+1)); else echo "FAIL $name (exit $got, want $want)"; fail=$((fail+1)); fi
}
mkrepo() { # dir first_content second_content
    git init -q "$1"
    printf '%s\n' "$2" > "$1/f.txt"; git -C "$1" add f.txt
    git -C "$1" -c user.name=t -c user.email=t@example.invalid commit -qm one
    printf '%s\n' "$3" > "$1/f.txt"; git -C "$1" add f.txt
    git -C "$1" -c user.name=t -c user.email=t@example.invalid commit -qm two
}
mkrepo "$tmp/h-old" "notes at /Users/$who/projects/todo.txt" "clean now"
mkrepo "$tmp/h-clean" "nothing here" "still nothing"
mkdir -p "$tmp/h-notrepo"
hcheck "identifier only in an old revision is rejected" 1 "$tmp/h-old"
hcheck "clean history passes (negative control)"        0 "$tmp/h-clean"
hcheck "a history scan that errors is not clean"        2 "$tmp/h-notrepo"
hcheck "missing repo argument is an error"              2 ""
echo "$pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
