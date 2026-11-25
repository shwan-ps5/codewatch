#!/usr/bin/env bash
# One unattended research batch (AGENTS.md). opencode with a cheap cloud model reads advisories
# and commits candidate files. This script checks those commits (benchmarks/reviewed.py guard) and, only if they
# pass, pushes them to the research branch, where one open pull request into detection-gaps carries every batch
# waiting for review (opened here when none is). A Claude session reviews the batches on that branch and merges the
# pull request; the next batch starts a new one. Nothing unreviewed reaches detection-gaps, which the nightly run
# measures and cloud sessions clone, and the pull request's CI checks each push.
#
# Runs on the desktop from its own clone (~/codewatch-research/repo, so it never touches a working checkout),
# from the systemd user timer codewatch-research.timer, off-peak. Needs: the model pulled (`ollama pull NAME`),
# gh logged in, and the clone's credential helper set as in the main checkout. Run it by hand once after a change
# to it, and read the log.
# Settings: CODEWATCH_RESEARCH_MODEL (default ollama/deepseek-v4.1-flash:cloud),
#           CODEWATCH_RESEARCH_MAX_PENDING (default 3: skip while that many batches wait for review),
#           CODEWATCH_RESEARCH_KIND (default candidates; "gaps" writes gap notes on the cases the last nightly
#           missed instead, AGENTS.md section 9, on its own branch research-gaps and its own pull request; run it
#           from a second clone, ~/codewatch-research/repo-gaps, with codewatch-research-gaps.timer).
# Logs: ~/.cache/codewatch/research/ (research-gaps/ for gap notes); usage.log has one line per run (characters
# read, tokens used). Commits that fail the check are kept on a local research-rejected-* branch, never pushed.

set -uo pipefail
export PATH="$HOME/.opencode/bin:$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
export GIT_TERMINAL_PROMPT=0                  # fail at once on a credential problem instead of waiting
REPO="${CODEWATCH_RESEARCH_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
KIND="${CODEWATCH_RESEARCH_KIND:-candidates}"
case "$KIND" in
    candidates) BRANCH=research LOGS="$HOME/.cache/codewatch/research" ;;
    gaps) BRANCH=research-gaps LOGS="$HOME/.cache/codewatch/research-gaps" ;;
    *) echo "CODEWATCH_RESEARCH_KIND must be candidates or gaps, not $KIND" >&2; exit 2 ;;
esac
# Each run fast-forwards this checkout, which can rewrite this file while bash is still reading it: run a copy.
if [ -z "${CODEWATCH_RESEARCH_COPY:-}" ]; then
    mkdir -p "$LOGS"
    copy="$LOGS/research-batch.running.sh"
    cp "$0" "$copy" && CODEWATCH_RESEARCH_COPY=1 CODEWATCH_RESEARCH_REPO="$REPO" exec bash "$copy" "$@"
fi
MODEL="${CODEWATCH_RESEARCH_MODEL:-ollama/deepseek-v4.1-flash:cloud}"
MAX_PENDING="${CODEWATCH_RESEARCH_MAX_PENDING:-3}"
BASE=detection-gaps           # where reviewed batches go, by merging the pull request; each is pushed to $BRANCH
mkdir -p "$LOGS"
# Unattended, nobody can answer a permission prompt: allow what research needs and refuse the rest at once
# (tools/opencode-research.json). An ollama/ model is registered here too, so opencode finds it without
# `ollama launch` having saved it; it only has to be pulled (`ollama pull NAME`) with the Ollama server running.
export OPENCODE_CONFIG="$LOGS/opencode.json"
python3 -I - "$REPO/tools/opencode-research.json" "$MODEL" "$OPENCODE_CONFIG" <<'PY' || exit 1
import json, os, sys
config = json.load(open(sys.argv[1]))
# Outside the repository: a workspace for the model's scripts and downloads, and the advisory database. Nothing else.
home = os.path.expanduser("~")
config["permission"]["external_directory"] = {"*": "deny", f"{home}/codewatch-research/*": "allow",
                                              f"{home}/advisory-database/*": "allow"}
provider, _, name = sys.argv[2].partition("/")
if provider == "ollama":
    config["provider"] = {"ollama": {"name": "Ollama", "npm": "@ai-sdk/openai-compatible",
                                     "options": {"baseURL": "http://127.0.0.1:11434/v1"},
                                     "models": {name: {"name": name}}}}
json.dump(config, open(sys.argv[3], "w"), indent=2)
PY

exec 9>"$LOGS/lock"
flock -n 9 || exit 0                        # a batch is still running
LOG_FILE="$LOGS/$(date +%F-%H%M).log"
exec >>"$LOG_FILE" 2>&1
say() { echo "$(date '+%F %T') $*"; }

cd "$REPO" || exit 1
if [ -n "$(git status --porcelain)" ]; then
    say "working tree not clean (left over from an earlier run?); skipping. Look at: git status"
    exit 1
fi
git fetch -q origin "$BASE" || { say "git fetch failed"; exit 1; }
remote=""
if git ls-remote --exit-code --heads origin "$BRANCH" >/dev/null; then
    git fetch -q origin "$BRANCH" || { say "git fetch of $BRANCH failed"; exit 1; }
    remote="origin/$BRANCH"
fi
# (Merges of origin branches left by an earlier run are not counted: the checkout below replaces them.)
if [ -n "$(git rev-list --no-merges HEAD --not --remotes=origin)" ]; then
    say "local commits not on origin (not checked by this script); skipping until they're dealt with"
    exit 1
fi
open_pr() { gh pr list --head "$BRANCH" --base "$BASE" --state open --json number --jq '.[0].number // empty'; }
pr=$(open_pr) || { say "gh pr list failed"; exit 1; }
# Carry on from the research branch while it holds batches not yet in $BASE: under the open pull request, or with
# none yet (an earlier run couldn't open it). Start afresh from $BASE once its pull request is merged or closed.
start="origin/$BASE"
if [ -n "$remote" ] && [ -n "$(git rev-list "$remote" --not "origin/$BASE")" ]; then
    head=$(git rev-parse "$remote")
    ended=$(gh pr list --head "$BRANCH" --state all --json headRefOid,state \
            --jq "[.[] | select(.headRefOid == \"$head\" and .state != \"OPEN\")] | length") \
        || { say "gh pr list failed"; exit 1; }
    if [ -n "$pr" ] || [ "$ended" = 0 ]; then
        start=$remote
    else
        say "$BRANCH's last pull request was closed without its commits reaching $BASE; starting afresh from $BASE"
    fi
fi
git checkout -q -B "$BRANCH" "$start" || { say "can't check out $BRANCH at $start"; exit 1; }
if [ "$start" = "$remote" ]; then
    # The agent reads AGENTS.md's queue and suites.json from here, so bring in what $BASE has gained since.
    git merge -q --no-edit "origin/$BASE" || { git merge --abort; say "can't merge $BASE into $BRANCH; resolve by hand"; exit 1; }
fi

if [ "$KIND" = gaps ]; then
    waiting=$(python3 -I benchmarks/reviewed.py pending --gaps | head -1)
else
    waiting=$(python3 -I benchmarks/reviewed.py pending | head -1)
fi
if [ "$waiting" -ge "$MAX_PENDING" ]; then
    say "$waiting batches waiting for review; skipping"
    exit 0
fi
if [ "$KIND" = gaps ]; then
    # The agent never sees the nightly's results (blind suites are in there too): only this list of work on open cases.
    misses=$(python3 -I tools/export_misses.py --out "$HOME/codewatch-research/gaps/misses.tsv") \
        || { say "can't list the gap notes' work"; exit 1; }
    if [ "$misses" = 0 ]; then
        say "no gap-note work left (missed, still-flagged or quotes to check); skipping"
        exit 0
    fi
    say "$misses rows of gap-note work"
elif [ -d "$HOME/advisory-database/.git" ]; then
    git -C "$HOME/advisory-database" fetch -q --depth 1 origin main && git -C "$HOME/advisory-database" reset -q --hard FETCH_HEAD
fi

mkdir -p "$HOME/codewatch-research"
base=$(git rev-parse HEAD)
started_ms=$(( $(date +%s) * 1000 - 5000 ))
LIMIT_MIN=120                                 # the run is stopped after this; the prompt gives the clock times
stop_reading=$(date -d "+60 min" +%H:%M); commit_by=$(date -d "+$((LIMIT_MIN - 15)) min" +%H:%M)
stopped_at=$(date -d "+$LIMIT_MIN min" +%H:%M)
ALLOWLIST="Shell commands outside an allowlist (git, gh, python3, curl, unzip, jq and simple file viewers) are
refused: if one is, use python3 for it instead."
TIME="Time: this run is stopped at $stopped_at (the clock, \`date +%H:%M\`), and anything not committed by then is lost."
say "starting a batch with $MODEL at $base"
if [ "$KIND" = gaps ]; then
    TITLE="codewatch gap notes $(date +%F-%H%M)"
    PROMPT="Read AGENTS.md in full, then write one batch of gap notes as its section 9 says: no research topic, no
candidates. The work is in ~/codewatch-research/gaps/misses.tsv (its task column says which kind), in the order to take it. Keep your
scripts and downloads in ~/codewatch-research/gaps/ (the only folder outside this repository you may write to).
Commit only your benchmarks/gap-notes-*.json file, with the identity AGENTS.md gives. Don't push, pull or switch
branches: the script that started you does that. $ALLOWLIST
$TIME Commit the notes file by $commit_by with whatever has been noted by then (a smaller batch is fine).
End with the counts: notes written, by task and category, and rows left in misses.tsv."
else
    TITLE="codewatch research $(date +%F-%H%M)"
    PROMPT="Read AGENTS.md in full and do the next topic in its queue: one batch of about 60 advisories, following
'Carrying on a topic'. Keep your scripts and downloads in ~/codewatch-research/ (the only folder outside this
repository you may write to; ~/advisory-database/ is readable too). Commit only your candidate files
(and AGENTS.md if you mark a topic done), with the identity AGENTS.md gives. Don't push, pull or switch branches:
the script that started you does that. A topic marked paused is not to be worked on. If every topic in the queue
is done or paused, stop without committing and say so. $ALLOWLIST
$TIME
Stop searching and start reading by $stop_reading; commit the batch files by $commit_by, with whatever has been
read by then (a smaller batch is fine).
End with the counts: read, accepted (open, blind), rejected, unsure, candidates left in the topic."
fi
# The first run after a quiet hour or two (03:00 after the nightly, 23:00 after skipped hours; 2026-11-21..23) got
# "Model unavailable" within seconds, and the next run worked: wait and try once more.
for attempt in 1 2; do
    began=$(date +%s)
    timeout "${LIMIT_MIN}m" opencode run -m "$MODEL" --title "$TITLE" "$PROMPT"
    code=$?
    if [ "$attempt" = 1 ] && [ "$code" != 0 ] && [ $(( $(date +%s) - began )) -lt 120 ] \
            && tail -n 30 "$LOG_FILE" | grep -q "Model unavailable"; then
        say "opencode exited $code: model unavailable at the start; trying again in 2 minutes"
        sleep 120
        continue
    fi
    break
done
say "opencode exited $code"

# What the run read and spent (characters its tools returned, model tokens): one line in usage.log, and into the
# batch's JSON (amending the batch commit) so the review sees it too.
batch_json=$(git diff --name-only "$base..HEAD" -- 'benchmarks/cve-candidates-*.json' 'benchmarks/gap-notes-*.json' | tail -1)
if [ -n "$batch_json" ] && [ -z "$(git status --porcelain)" ]; then
    used=$(python3 -I tools/research_usage.py --dir "$REPO" --since "$started_ms" --into "$batch_json" 2>&1 | tail -1)
    git add "$batch_json" && git commit -q --amend --no-edit
else
    used=$(python3 -I tools/research_usage.py --dir "$REPO" --since "$started_ms" 2>&1 | tail -1)
fi
say "usage: $used"
echo "$(date '+%F %T') $used" >> "$LOGS/usage.log"

if [ -n "$(git status --porcelain)" ]; then
    # Usually a run stopped at its limit mid-batch. Keep the files for a look, then clean the checkout so the next
    # run can start (it refuses a dirty tree). The unrecorded reads are simply read again by a later run.
    kept="$LOGS/leftover-$(date +%F-%H%M)"
    mkdir -p "$kept"
    say "uncommitted changes left behind, copied to $kept and removed:"; git status --short
    git diff > "$kept/changes.diff"
    git ls-files --others --exclude-standard -z | xargs -0 -r cp --parents -t "$kept"
    git reset -q --hard HEAD && git clean -q -fd
fi
if [ "$(git rev-parse HEAD)" = "$base" ]; then
    say "no commits; nothing to push"
    exit 0
fi
if ! python3 -I benchmarks/reviewed.py guard "$base"; then
    keep="research-rejected-$(date +%F-%H%M)"
    git branch "$keep" HEAD && git reset -q --hard "$base"
    say "check failed (above); commits moved to local branch $keep, not pushed"
    exit 1
fi
if [ -n "$remote" ] && [ "$start" != "$remote" ]; then
    # Afresh after a closed pull request: replace the branch, but only if nobody has pushed to it since we looked.
    git push -q --force-with-lease="$BRANCH:$(git rev-parse "$remote")" origin "$BRANCH" || { say "push failed"; exit 1; }
elif ! git push -q origin "$BRANCH"; then
    # A review pushed to the branch meanwhile: merge its commits, never rewrite them.
    git pull -q --no-rebase --no-edit origin "$BRANCH" && git push -q origin "$BRANCH" || { say "push failed"; exit 1; }
fi
say "pushed to $BRANCH: $(git log --oneline "$base..HEAD" | tr '\n' ';')"
pr=$(open_pr) || { say "gh pr list failed; open the pull request by hand"; exit 1; }
if [ -z "$pr" ] && [ "$KIND" = gaps ]; then
    gh pr create --base "$BASE" --head "$BRANCH" --title "Gap notes waiting to be read" --body \
"Gap notes from the unattended runs (tools/research-batch.sh with CODEWATCH_RESEARCH_KIND=gaps, AGENTS.md section
9): for each open CVE-pair case the last nightly missed, where its source and sink are and why codewatch doesn't
connect them. Each push passed \`benchmarks/reviewed.py guard\` (gap notes about open cases only). A Claude session
reads them, marks each file read, and merges this pull request; rule work follows in its own commits." \
        && say "opened a pull request into $BASE"
elif [ -z "$pr" ]; then
    gh pr create --base "$BASE" --head "$BRANCH" --title "Research batches waiting for review" --body \
"Candidate batches from the unattended research runs (tools/research-batch.sh, following AGENTS.md). Each push
passed \`benchmarks/reviewed.py guard\` (only candidate files and AGENTS.md changed, the project's commit identity,
blind cases described by their entry alone). None has been reviewed.

A Claude session reviews each batch on this branch (CLAUDE.md, 'How work is done here'), commits its decisions here,
and merges this pull request. Later batches are added here until then; the next one after the merge opens a new pull
request. Don't read anything about a blind case beyond its entry." && say "opened a pull request into $BASE"
else
    say "added to pull request #$pr"
fi
