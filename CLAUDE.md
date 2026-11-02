# codewatch: notes for Claude Code sessions

## Commit identity

Commit only as `Shwan <344055753+shwan-ps5@users.noreply.github.com>`, in every session, local or cloud. Before the
first commit, run:

```
git config user.name "Shwan"
git config user.email "344055753+shwan-ps5@users.noreply.github.com"
```

Never commit with another name or email, and never add one to commit messages, files or pull requests.

## How work is done here

- `PLAN.md` is the plan and the record of every decision: read the ground rules at its top before changing a rule.
- Blind sets (`~/.cache/codewatch/blind*`, the `cve-pairs-blind-*` suites) are scanned once, at the end of a round,
  and never used to adjust rules. Held-out suites (SecurityEval Copilot/InCoder, Vulnerable-Code-Snippets JS) are
  measured, never tuned on.
- Every rule change gets a test in `tests/test_detection.py` that fails without it; record in `PLAN.md` and
  `benchmarks/suites.json` which case drove it.
- Before committing: `venv/bin/ruff check .` and `venv/bin/pytest -q -n auto`.
- Benchmarks: `venv/bin/python benchmarks/devtools.py bench [SUITE...]` (parallel; `CODEWATCH_BENCH_WORKERS`
  sets how many at once). Run `git checkout benchmarks/results` afterwards unless the results are meant to be
  committed.
- Day to day, check a change in isolation: its tests, a probe on the files of the case behind it, and
  `venv/bin/python benchmarks/devtools.py cases GHSA-...` for the CVE pairs it targets. The full verification
  (every suite and about 50 apps) runs overnight on the maintainer's machine (`benchmarks/nightly.sh`, report in
  `~/.cache/codewatch/nightly/DATE/summary.txt`). Commit work before the evening so the nightly run measures it.
- Never edit rule or analyzer files while a benchmark is running: it reads them as it goes.
- This repository is public. Never name the maintainer's private projects or their findings in files, commits or
  pull requests.

## Cloud sessions (Claude Code on the web)

A cloud session starts from a fresh clone of the GitHub repository in a sandbox. It has none of the
maintainer's machine: no `~/.cache/codewatch` (learning-set apps, blind sets, nightly reports) and no private
projects. Cloud work is self-contained and comes back as a pull request, which the maintainer's machine
verifies, including the nightly run, before merging.

Setup, before anything else:

```
git config user.name "Shwan"
git config user.email "344055753+shwan-ps5@users.noreply.github.com"
python3 -m venv venv && venv/bin/pip install -q -e '.[dev]'
python3 -m venv tools/semgrep-venv && tools/semgrep-venv/bin/pip install -q --require-hashes -r tools/semgrep.lock
venv/bin/pytest -q -n auto     # check: the detection tests must run, not skip ("semgrep not installed")
```

Without `tools/semgrep-venv` every rule test skips itself and passes, which proves nothing. `npm ci --prefix tools`
adds ESLint and the other Node analyzers, needed only for JavaScript lint work. Setup takes about ten minutes; the
same commands can go in the cloud environment's setup script so each session starts ready.

For the maintainer: push `detection-gaps` (and with it this file and PLAN.md) before starting a cloud session. A
session clones what GitHub has when it starts and never sees later pushes unless it rebases.

Working rules for a cloud session:
- Branch from `detection-gaps` (the session's own branch name, such as `claude/<topic>-<id>`, is fine) and open the
  pull request against `detection-gaps`. Never push to `main` or `detection-gaps` directly.
- Priorities, in order: Python (Django, Flask, FastAPI) and the JavaScript those apps ship; then Node and other JS
  frameworks; then PHP, Ruby, Rust, C/C++ and C#. Always detection of real issues with false alarms as close to
  zero as possible.
- One topic per session, for example "Express/Node injection rules", "FastAPI-specific sources", or "more Python
  front-end CVE pairs".
- New sinks, sources or sanitizers for a weakness that already has a rule go into that rule, in its existing file
  (e.g. more Node file APIs into `javascript-taint.yml`'s `codewatch.js.path-traversal`): no copied sources, no
  line reported by two rules, and no extra rule for the summary passes to multiply. A new file,
  `catalog/codewatch/rules/<language>-<topic>.yml` (loaded automatically), is for a new rule or a language with
  none yet; YAML anchors don't cross files, so it defines its own sources and sanitizers. Tests go in their own file,
  `tests/test_<language>_<topic>.py`; `semgrep_vulnerabilities` from `tests/test_detection.py` is the helper.
- Changes to shared files (`python-web.yml`, `javascript-taint.yml`, `core/analyzers/`) are allowed when needed,
  but the pull request has to say what changed there and why.
- Every rule has a test that fails without it, a vulnerable case and a safe look-alike, as in
  `tests/test_detection.py`. Verdict-mode false alarms must stay at 0% on the suites that measure them.
- Checks in a cloud session: `venv/bin/ruff check .`, the full `venv/bin/pytest -q -n auto` (a few minutes), the
  topic's tests each failing without its rule, and quick probes; `devtools.py cases GHSA-...` for a single CVE pair
  is fine. Leave whole benchmark suites and app scans to the maintainer's machine and the nightly run (an hour or
  more, lots of memory, and a container restart loses them); say in the pull request what to measure. Never run a
  blind suite (`cve-pairs-blind-*`); held-out suites are measured, never tuned on.
- Stop a background process by its PID, never `pkill -f` with a pattern: the pattern matches the shell running the
  command and kills it too.
- New ground truth follows PLAN.md step 22: reviewed GitHub advisories with one small fix commit in application
  code, each read and accepted or rejected with a reason, and split before any scan by the fixed rule (blind when
  `int(sha256(id), 16) % 3 == 0`). The blind half goes in its own `"blind": true` suite and is never scanned in
  the session. Keep GitHub API calls slow (two at a time with pauses): bursts have tripped rate limits before.
- Run `git checkout benchmarks/results` before committing, unless the pull request is about results.
- The pull request says which rules were added, which cases or suites drove them, what the suites measured
  before and after, and which shapes might cause false alarms on ordinary apps, so the nightly run can check
  them. End it with the attribution lines the session provides.
