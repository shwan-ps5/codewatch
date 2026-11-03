#!/usr/bin/env bash
# One unattended research batch (AGENTS.md). opencode with a cheap cloud model reads advisories
# and commits candidate files. This script checks those commits (benchmarks/reviewed.py guard) and pushes them to
# detection-gaps only if they pass. A Claude session reviews the batches; the nightly run tests what's added.
#
# Runs on the desktop from its own clone (~/codewatch-research/repo, so it never touches a working checkout),
# from the systemd user timer codewatch-research.timer, off-peak. Needs: the model pulled (`ollama pull NAME`),
# gh logged in, and the clone's credential helper set as in the main checkout. Run it by hand once after a change
# to it, and read the log.
# Settings: CODEWATCH_RESEARCH_MODEL (default ollama/deepseek-v4.1-flash:cloud),
#           CODEWATCH_RESEARCH_MAX_PENDING (default 3: skip while that many batches wait for review).
# Logs: ~/.cache/codewatch/research/; usage.log has one line per run (characters read, tokens used). Commits that
# fail the check are kept on a local research-rejected-* branch, never pushed.

set -uo pipefail
export PATH="$HOME/.opencode/bin:$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
export GIT_TERMINAL_PROMPT=0                  # fail at once on a credential problem instead of waiting
REPO="${CODEWATCH_RESEARCH_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
# Each run fast-forwards this checkout, which can rewrite this file while bash is still reading it: run a copy.
if [ -z "${CODEWATCH_RESEARCH_COPY:-}" ]; then
    mkdir -p "$HOME/.cache/codewatch/research"
    copy="$HOME/.cache/codewatch/research/research-batch.running.sh"
    cp "$0" "$copy" && CODEWATCH_RESEARCH_COPY=1 CODEWATCH_RESEARCH_REPO="$REPO" exec bash "$copy" "$@"
fi
MODEL="${CODEWATCH_RESEARCH_MODEL:-ollama/deepseek-v4.1-flash:cloud}"
MAX_PENDING="${CODEWATCH_RESEARCH_MAX_PENDING:-3}"
BRANCH=detection-gaps
LOGS="$HOME/.cache/codewatch/research"
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
exec >>"$LOGS/$(date +%F-%H%M).log" 2>&1
say() { echo "$(date '+%F %T') $*"; }

cd "$REPO" || exit 1
if [ -n "$(git status --porcelain)" ]; then
    say "working tree not clean (left over from an earlier run?); skipping. Look at: git status"
    exit 1
fi
git checkout -q "$BRANCH" && git fetch -q origin "$BRANCH" || { say "git fetch failed"; exit 1; }
if [ -n "$(git rev-list "origin/$BRANCH..HEAD")" ]; then
    say "local commits not on origin (not checked by this script); skipping until they're dealt with"
    exit 1
fi
git merge -q --ff-only "origin/$BRANCH" || { say "can't fast-forward to origin/$BRANCH"; exit 1; }

waiting=$(python3 -I benchmarks/reviewed.py pending | head -1)
if [ "$waiting" -ge "$MAX_PENDING" ]; then
    say "$waiting batches waiting for review; skipping"
    exit 0
fi
if [ -d "$HOME/advisory-database/.git" ]; then
    git -C "$HOME/advisory-database" fetch -q --depth 1 origin main && git -C "$HOME/advisory-database" reset -q --hard FETCH_HEAD
fi

mkdir -p "$HOME/codewatch-research"
base=$(git rev-parse HEAD)
started_ms=$(( $(date +%s) * 1000 - 5000 ))
say "starting a batch with $MODEL at $base"
timeout 3h opencode run -m "$MODEL" --title "codewatch research $(date +%F-%H%M)" \
"Read AGENTS.md in full and do the next topic in its queue: one batch of about 60 advisories, following
'Carrying on a topic'. Keep your scripts and downloads in ~/codewatch-research/ (the only folder outside this
repository you may write to; ~/advisory-database/ is readable too). Commit only your candidate files
(and AGENTS.md if you mark a topic done), with the identity AGENTS.md gives. Don't push, pull or switch branches:
the script that started you does that. If no topic in the queue is left unfinished, stop without committing and
say so. Shell commands outside an allowlist (git, gh, python3, curl, unzip, jq and simple file viewers) are
refused: run one command at a time (git -C DIR rather than cd DIR && git), and use python3 for anything else.
End with the counts: read, accepted (open, blind), rejected, unsure, candidates left in the topic."
say "opencode exited $?"

# What the run read and spent (characters its tools returned, model tokens): one line in usage.log, and into the
# batch's JSON (amending the batch commit) so the review sees it too.
batch_json=$(git diff --name-only "$base..HEAD" -- 'benchmarks/cve-candidates-*.json' | tail -1)
if [ -n "$batch_json" ] && [ -z "$(git status --porcelain)" ]; then
    used=$(python3 -I tools/research_usage.py --dir "$REPO" --since "$started_ms" --into "$batch_json" 2>&1 | tail -1)
    git add "$batch_json" && git commit -q --amend --no-edit
else
    used=$(python3 -I tools/research_usage.py --dir "$REPO" --since "$started_ms" 2>&1 | tail -1)
fi
say "usage: $used"
echo "$(date '+%F %T') $used" >> "$LOGS/usage.log"

if [ -n "$(git status --porcelain)" ]; then
    say "uncommitted changes left behind:"; git status --short
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
git pull -q --rebase origin "$BRANCH" && git push -q origin "$BRANCH" && say "pushed: $(git log --oneline "$base..HEAD" | tr '\n' ';')"
