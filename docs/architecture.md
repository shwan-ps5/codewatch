# How codewatch is put together

codewatch has two halves that share one package (`core/`): a **scanner** that runs analyzers over a checkout and
turns their output into findings, and a **server** (Django + SQLite) that stores scans, tracks new code, rates
projects and applies the quality gate. The scanner never imports Django, so `codewatch check` and the GitHub
Action run it without a server.

```
codewatch check / scan (core/client.py)
        │
        ▼
core/collect.py ── picks the files (no vendored, minified or third-party code), builds a Context
        │
        ▼
core/analyzers/  ── one module per tool family; each returns a Result of findings
   python_tools.py    ruff, bandit, basedpyright, radon, complexipy
   multi_tools.py     Semgrep: codewatch's own rules + registry rules  ◄── where most detection work happens
   extra.py, ...      ESLint, stylelint, html-validate, checkov, detect-secrets, jscpd, lizard, cppcheck
   dependencies.py    pip-audit, OSV lookups for lockfiles
   accessibility.py   axe-core in headless Chromium (live pages)
        │
        ▼
core/duplicates.py, fingerprint.py ── one issue per problem per line ("also reported by"), stable identities
        │
        ▼
upload (core/api.py) → models.py, ratings.py, gate.py → the web UI (views.py, templates/)
```

## The Semgrep pipeline (`core/analyzers/multi_tools.py`)

Semgrep's open-source engine follows data within one function. codewatch adds two things around it.

**1. Analysis copies.** Python files are rewritten line for line before Semgrep sees them. Every line and column
is kept, so findings map straight back. The rewrites are:

| Rewrite | Module | Why |
|---|---|---|
| dead constant branches blanked | `constant_branches.py` | `if False:` code isn't reachable |
| slices made indexes (`a[1:]` → `a[1, ]`) | `slices.py` | Semgrep loses taint at slices |
| starred targets unstarred | `starred_targets.py` | the same, for `a, *b = ...` |
| constant container keys made attributes | `containers.py` | taint is tracked per key |
| `match` made `if` | `match_statements.py` | Semgrep loses taint in `match` |
| `else:` made `if E:`, `elif` made `if` | `else_branches.py` | so a sanitizer inside a check doesn't cover the branch where it failed |
| Flask converters typed, Django URL args marked, DRF lookups | `route_converters.py`, ... | sources depend on the route |

Rules are written against ordinary Python. `else_branches.rules_for_copies` rewrites rule patterns the same way
before they run, so a rule writes `else:` like any code. To see what the rules actually match, run
`venv/bin/python benchmarks/devtools.py copy FILE.py`, which prints the copy as a diff.

**2. Summaries (`summaries.py`).** Before the main scan, the taint rules run with each function's parameters as
sources, to learn which parameters reach a sink. Calls to those functions then become extra sinks, up to three
calls deep. Other passes find functions that return request data and functions that never pass their argument
on. A call counts only where the function is visible (the same file, or an import that resolves to the defining
file).

The final rule set is the built-in rules plus the variants these passes generate. Results from generated
variants are mapped back to the built-in rule's id.

## Rules

`catalog/codewatch/rules/*.yml` are codewatch's own Semgrep rules, one file per language and topic. Shared
sources and sanitizers are YAML anchors (`&validated-guard`, `&prefix-guard`, ...) inside a file. See
[writing-rules.md](writing-rules.md).

## Benchmarks

`core/benchmark.py` scores suites listed in `benchmarks/suites.json`: the OWASP Benchmark, SecurityEval and real
CVE fix pairs. A fix pair is the vulnerable commit and its fix. Each is scanned on both sides and scored by
whether a finding of the advisory's weakness lands near the lines the fix changed. See
[benchmarks.md](benchmarks.md).
