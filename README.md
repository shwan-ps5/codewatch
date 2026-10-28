# codewatch

> **Work in Progress** — usable for local scanning, but the data model, CLI and UI may change without notice. Expect rough edges.

Self-hosted code-quality server: branch analysis, new-code tracking and quality gates over open-source analyzers. Django + SQLite, no containers or JVM.

## Setup

```bash
python3 -m venv venv && venv/bin/pip install -e '.[dev]'
venv/bin/python manage.py migrate
venv/bin/python manage.py addproject claude-quiz ~/dev/claude-quiz
venv/bin/python manage.py scan claude-quiz --all-branches
make run   # http://127.0.0.1:8100
```

Optional: `cppcheck` (apt) for C/C++, Node/npx for duplication (jscpd).

## How it works

- Each project gets a bare mirror in `~/.cache/codewatch/<key>/`; every scan checks the commit out into a throwaway worktree, so your working copy is never touched and only tracked files are analysed.
- **New code**: on a branch, everything changed since the merge-base with the main branch; on main, everything since the previous analysis. An issue is new if it sits on a changed line, or is absent from the reference analysis in a changed file.
- Issues are fingerprinted by rule + file + source text, so they keep their identity (and any won't-fix / false-positive resolution) when code moves.

| Analyzer | Covers |
|---|---|
| ruff, bandit, radon | Python lint, security, complexity, maintainability |
| lizard | complexity for JS/TS, C/C++, others |
| semgrep CE | bugs and security across languages (config per project, default `p/default`) |
| cppcheck | C/C++ |
| jscpd | duplication |
| pip-audit + OSV | known CVEs in Python dependencies (`requirements*.txt`, `pyproject.toml`) |
| coverage | imports Cobertura XML / LCOV |

## Coverage

Run your tests with coverage, then scan. A `coverage.xml`, `coverage/cobertura-coverage.xml` or `lcov.info` in the project's local working copy is picked up automatically when the working copy is at the scanned commit; otherwise pass `--coverage FILE [--coverage-base DIR]`.

## CI / hooks

```bash
venv/bin/python manage.py scan myproj --branch "$BRANCH" --fail-on-gate
```

The web UI has no authentication; keep it bound to localhost.
