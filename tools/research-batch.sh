#!/usr/bin/env bash
# One unattended research batch (AGENTS.md), for the laptop. opencode with a cheap cloud model reads advisories
# and commits candidate files. This script checks those commits (benchmarks/reviewed.py guard) and pushes them to
# detection-gaps only if they pass. A Claude session reviews the batches; the nightly run tests what's added.
#
# First, once: `ollama launch opencode --model deepseek-v4.1-flash:cloud` (registers the model with opencode),
# and `gh auth login`. Run this by hand once and read the log before scheduling it, e.g. every two hours (cron):
#   0 */2 * * * /path/to/codewatch/tools/research-batch.sh
# Settings: CODEWATCH_RESEARCH_MODEL (default ollama/deepseek-v4.1-flash:cloud),
#           CODEWATCH_RESEARCH_MAX_PENDING (default 3: skip while that many batches wait for review).
# Logs: ~/.cache/codewatch/research/. Commits that fail the check are kept on a local research-rejected-* branch,
# never pushed.

set -uo pipefail
export PATH="$HOME/.opencode/bin:$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
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
import json, sys
config = json.load(open(sys.argv[1]))
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

base=$(git rev-parse HEAD)
say "starting a batch with $MODEL at $base"
timeout 3h opencode run -m "$MODEL" --title "codewatch research $(date +%F-%H%M)" \
"Read AGENTS.md in full and do the next topic in its queue: one batch of about 60 advisories, following
'Carrying on a topic'. Keep any scripts and downloads outside this repository. Commit only your candidate files
(and AGENTS.md if you mark a topic done), with the identity AGENTS.md gives. Don't push, pull or switch branches:
the script that started you does that. If no topic in the queue is left unfinished, stop without committing and
say so. Shell commands outside an allowlist (git, gh, python3, curl, unzip, jq and simple file viewers) are
refused: run one command at a time (git -C DIR rather than cd DIR && git), and use python3 for anything else.
End with the counts: read, accepted (open, blind), rejected, unsure, candidates left in the topic."
say "opencode exited $?"

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
