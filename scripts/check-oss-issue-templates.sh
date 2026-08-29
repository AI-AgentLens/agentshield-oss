#!/usr/bin/env bash
# check-oss-issue-templates.sh — every issues/new?template=X link in a README
# must resolve to a file that actually ships.
#
# WHY THIS IS A LOCAL CHECK AND NOT A REACHABILITY PROBE.
# The published README sends users to
#   github.com/<org>/<repo>/issues/new?template=rule-request.yml
# and that link was dead for as long as publish-oss.sh has excluded .github/.
# Nothing caught it, and no network check could have: GitHub answers an
# anonymous request to issues/new with a 302 to the login page BEFORE it
# resolves the template, so a broken template and a working one are
# byte-identical over HTTP. scripts/oss-walkthrough-test.sh asserted exactly
# that 302 and reported the link healthy for months.
#
# So the question is answered where it IS answerable: in the tree. Given a
# root, every template a README references must exist under
# .github/ISSUE_TEMPLATE/. Run against the repo it catches a typo'd link;
# run against the publish tree (see publish-oss.sh) it catches the far more
# likely failure — a link that survives publication while its template is
# stripped by an exclude rule.
#
# Usage:
#   check-oss-issue-templates.sh [ROOT] [--expect-min N]
#
#   ROOT          tree to check (default: repo root)
#   --expect-min  minimum number of template links the parser must find
#                 (default 1). See the positive-control note below.
set -uo pipefail

ROOT=""
EXPECT_MIN=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --expect-min)
            EXPECT_MIN="${2:-}"
            if ! [[ "$EXPECT_MIN" =~ ^[0-9]+$ ]]; then
                echo "ERROR: --expect-min needs a non-negative integer" >&2
                exit 2
            fi
            shift 2
            ;;
        -h|--help)
            sed -n '2,26p' "$0"
            exit 0
            ;;
        -*)
            echo "ERROR: unknown flag $1" >&2
            exit 2
            ;;
        *)
            if [[ -n "$ROOT" ]]; then
                echo "ERROR: unexpected argument $1" >&2
                exit 2
            fi
            ROOT="$1"
            shift
            ;;
    esac
done

if [[ -z "$ROOT" ]]; then
    ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fi
if [[ ! -d "$ROOT" ]]; then
    echo "ERROR: root '$ROOT' is not a directory" >&2
    exit 2
fi

# Both names on purpose. In the private repo the OSS-facing link lives in
# README_oss.md; publish-oss.sh copies that file over README.md, so the publish
# tree carries it under the other name. Checking one name only would make the
# check pass in whichever tree it was not pointed at.
READMES=()
for candidate in README.md README_oss.md; do
    [[ -f "$ROOT/$candidate" ]] && READMES+=("$ROOT/$candidate")
done

if [[ "${#READMES[@]}" -eq 0 ]]; then
    echo "ERROR: no README.md or README_oss.md under $ROOT" >&2
    exit 1
fi

# A template name runs to the first character that cannot be part of a
# filename in a URL query: & (next param), ) " ' > (markdown/HTML delimiters),
# or whitespace.
LINKS="$(grep -ohE 'issues/new\?template=[^&)"'"'"'[:space:]>]+' "${READMES[@]}" 2>/dev/null \
         | sed 's#^issues/new?template=##' | sort -u)"

count=0
[[ -n "$LINKS" ]] && count="$(printf '%s\n' "$LINKS" | wc -l | tr -d ' ')"

echo "OSS issue-template links (root: $ROOT)"
echo "  readmes scanned:  ${#READMES[@]} ($(printf '%s ' "${READMES[@]##*/}"))"
echo "  template links:   $count"

# Positive control. "0 broken links" out of 0 extracted is not evidence of
# health, it is evidence the parser found nothing — the same shape as a gate
# that greens because it compared nothing. The caller states how many links it
# expects to exist, and a parser that stops matching fails loudly instead of
# reporting clean.
if [[ "$count" -lt "$EXPECT_MIN" ]]; then
    echo "  FAIL: expected at least $EXPECT_MIN template link(s), extracted $count." >&2
    echo "        Either the README stopped linking the issue form, or the link" >&2
    echo "        syntax changed and this check no longer matches it. Both mean" >&2
    echo "        the check is not measuring anything — fix before trusting it." >&2
    exit 1
fi

missing=0
while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    if [[ -f "$ROOT/.github/ISSUE_TEMPLATE/$name" ]]; then
        echo "  ok:   $name"
    else
        echo "  FAIL: $name -> .github/ISSUE_TEMPLATE/$name does not exist under $ROOT" >&2
        missing=$((missing + 1))
    fi
done <<< "$LINKS"

if [[ "$missing" -gt 0 ]]; then
    echo "" >&2
    echo "$missing referenced issue template(s) missing. A user clicking that link" >&2
    echo "gets a blank issue form, not the template — and GitHub returns the same" >&2
    echo "302 either way, so no reachability probe will tell you." >&2
    exit 1
fi

echo "  OK: all $count referenced template(s) present"
