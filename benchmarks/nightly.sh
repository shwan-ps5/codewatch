#!/bin/bash
# The full verification, meant to run unattended (e.g. overnight from a timer): lint, tests, every suite that isn't
# blind, and the apps listed in ~/.config/codewatch/nightly-apps.txt (one directory per line; # comments), against
# the tip of a branch checked out in its own worktree, so edits in the working copy don't leak into a run.
#
#   benchmarks/nightly.sh [BRANCH]        (default: the branch checked out in this repository)
#
# Writes ~/.cache/codewatch/nightly/YYYY-MM-DD/: summary.txt (what changed since the previous report), suites.txt,
# apps.txt (one finding per line), results/ (the suites' result files) and log.txt. Blind suites are never run.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
BRANCH=${1:-$(git -C "$REPO" rev-parse --abbrev-ref HEAD)}
BASE=$HOME/.cache/codewatch/nightly
SRC=$BASE/src
OUT=$BASE/$(date +%F)
APPS=$HOME/.config/codewatch/nightly-apps.txt
PREV=$(ls -d "$BASE"/20??-??-?? 2>/dev/null | grep -v "$OUT" | tail -1)
mkdir -p "$OUT"
exec > "$OUT/log.txt" 2>&1

if [ -d "$SRC" ]; then
    git -C "$SRC" checkout -q --detach "$BRANCH" || exit 1
else
    git -C "$REPO" worktree add -q --detach "$SRC" "$BRANCH" || exit 1
fi
cd "$SRC" || exit 1
PY=$REPO/venv/bin/python
echo "commit $(git rev-parse --short HEAD) ($BRANCH), started $(date '+%F %T')"

"$REPO/venv/bin/ruff" check . > "$OUT/lint.txt" 2>&1; echo "lint: $(tail -1 "$OUT/lint.txt")"
"$REPO/venv/bin/pytest" -q -n auto > "$OUT/tests.txt" 2>&1; echo "tests: $(tail -1 "$OUT/tests.txt")"

start=$(date +%s)
"$PY" benchmarks/devtools.py bench > "$OUT/suites.txt" 2>&1
echo "suites: $(( ($(date +%s) - start) / 60 )) min"
mkdir -p "$OUT/results" && cp benchmarks/results/*.json benchmarks/results/*.md "$OUT/results/" 2>/dev/null
git checkout -q -- benchmarks/results

if [ -f "$APPS" ]; then
    start=$(date +%s)
    mapfile -t dirs < <(grep -v '^\s*#' "$APPS" | grep -v '^\s*$' | sed "s|^~|$HOME|")
    "$PY" benchmarks/devtools.py repos "${dirs[@]}" 2>&1 | grep -v '^-- note' > "$OUT/apps-raw.txt"
    awk '/^== /{n=$2; sub(":","",n); next} /^-- /{next} NF>=3 {print n, $1, $2, $3}' "$OUT/apps-raw.txt" \
        | LC_ALL=C sort -u > "$OUT/apps.txt"
    echo "apps: $(( ($(date +%s) - start) / 60 )) min, $(wc -l < "$OUT/apps.txt") findings"
fi

{
    echo "commit $(git rev-parse --short HEAD) ($BRANCH), $(date '+%F %T')"
    cat "$OUT/lint.txt" | tail -1; tail -1 "$OUT/tests.txt"
    echo; echo "== suites"; grep -v '^ ' "$OUT/suites.txt"
    if [ -n "$PREV" ]; then
        echo; echo "== compared with $(basename "$PREV")"
        diff "$PREV/suites.txt" "$OUT/suites.txt" > /dev/null && echo "suites unchanged" \
            || diff "$PREV/suites.txt" "$OUT/suites.txt"
        for f in "$OUT"/results/cve-pairs-*.md; do
            [ -f "$PREV/results/$(basename "$f")" ] || continue
            changed=$(diff <(grep '^| GHSA' "$PREV/results/$(basename "$f")") <(grep '^| GHSA' "$f"))
            [ -n "$changed" ] && { echo "-- $(basename "$f" .md) cases:"; echo "$changed"; }
        done
        if [ -f "$OUT/apps.txt" ] && [ -f "$PREV/apps.txt" ]; then
            echo "-- new app findings:"; LC_ALL=C comm -13 "$PREV/apps.txt" "$OUT/apps.txt"
            echo "-- gone:"; LC_ALL=C comm -23 "$PREV/apps.txt" "$OUT/apps.txt"
        fi
    fi
} > "$OUT/summary.txt"
echo "finished $(date '+%F %T')"
