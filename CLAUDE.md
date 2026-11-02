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
