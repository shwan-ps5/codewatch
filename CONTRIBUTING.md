# Contributing to codewatch

Thanks for looking. codewatch is a work in progress, maintained by one person with help from AI agents, so the
process files (`PLAN.md`, `AGENTS.md`, `CLAUDE.md`, `docs/plan-log.md`) are long and written mostly for those
sessions. You don't need to read them to contribute. This page and the three docs it links are enough.

## What's most useful

1. **False alarms on real apps.** Run `codewatch check --all` on a Python web app you know. A finding that isn't
   a real issue is the most valuable report you can send: open an issue with the rule id and a minimal code
   shape (not your private code).
2. **CVE fix pairs.** Real advisories in Python web apps, each with one small fix commit in application code.
   They become ground truth in `benchmarks/suites.json` after review.
3. **Rule fixes for missed cases.** See [docs/writing-rules.md](docs/writing-rules.md). Each needs a test that
   fails without it.

The focus is Python (Django, Flask, FastAPI) and the JavaScript those apps ship. The JS/TS, PHP and other rules
are earlier-stage.

## Getting started

```
git clone https://github.com/shwan-ps5/codewatch && cd codewatch
python3 -m venv venv && venv/bin/pip install -e '.[dev]'
make tools
venv/bin/pytest -q -n auto
```

- [docs/architecture.md](docs/architecture.md): how a scan flows, and the Semgrep pipeline where most detection
  work happens.
- [docs/writing-rules.md](docs/writing-rules.md): where a rule change goes, and the tests it needs.
- [docs/benchmarks.md](docs/benchmarks.md): how to reproduce the README's numbers.

## Pull requests

- Branch from and target `detection-gaps`, the working branch (it's the default branch). `main` is
  fast-forwarded from it weekly, after a clean nightly run.
- Run `venv/bin/ruff check .` and `venv/bin/pytest -q -n auto` first.
- CI runs those, `codewatch check --all --strict` on codewatch itself (any open issue fails it; fix findings in
  code rather than suppressing them), and the CVE-pair smoke test (`benchmarks/smoke.py`).
- Say which cases drove a rule change and what it might flag on ordinary apps, so the nightly run can check.
- Never run or read the blind suites (`cve-pairs-blind-*`).
