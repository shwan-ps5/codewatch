# Detection plan

Goal: an open-source scanner that matches or beats SonarQube on detection, with false alarms as close to zero as
possible, without hiding real issues. Python first, JavaScript/TypeScript close behind.

## Ground rules

- Only compare: never change the projects being scanned to satisfy either tool.
- Never tune on held-out suites (SecurityEval Copilot and InCoder answers, Vulnerable-Code-Snippets JS) or on a
  blind repo set. Once a suite or repo is used to write or adjust rules, say so in `benchmarks/suites.json` or
  `benchmarks/compare.json` and in the README.
- Obvious noise (e.g. POST/GET restriction on read-only Django views) is classed as noise, not fixed away. A rule
  change that removes a true finding is a regression even if the score goes up.
- Verdict mode (vulnerabilities) must stay at 0% false alarms on clean code; uncertain cases go to review mode as
  hotspots.
- Every rule change gets a test in `tests/test_detection.py`; run the full suite (`venv/bin/pytest -q`) and
  `venv/bin/ruff check .` before committing. Commit and push only when asked.

## Baseline (commit e4d086c, 2026-10-30)

| Suite | Verdict | Review |
|---|---|---|
| OWASP Benchmark Python (tuned) | 100% found, 0% false alarms | 100%, 35% |
| SecurityEval (tuned) | 50/121 | 74/121 |
| SecurityEval Copilot (held out*) | 34%, 0% | 49%, 6% |
| SecurityEval InCoder (held out*) | 31%, 0% | 44%, 0% |
| Juice Shop (tuned) | 15/35 | 16/35 |
| Vulnerable-Code-Snippets JS (held out) | 11/22 | 13/22 |
| vulnerable-node seeds (tuned) | 11/12, 0 false alarms | 12/12, 1 false alarm |

*Same prompts as SecurityEval's own samples, which were used for rules.

SonarQube Community 26.10 on the same suites: OWASP 20%/0%, SecurityEval 29, Copilot 18%, InCoder 10%/5%,
Juice Shop 5, JS snippets 5, vulnerable-node 4/12 with 1 false alarm. Full comparison:
`benchmarks/results/compare.json` and `compare-report.html`.

Remaining Juice Shop misses are business logic, data files, Solidity and a Docker image; most remaining
SecurityEval misses are design flaws or plain functions with no request source. Don't chase those with rules.

## Next steps, in order

1. **Real-world measurement sets** (do first, before more rules):
   - CVE before/after pairs: Python and JS web projects with a published advisory and a fix commit (GitHub
     Security Advisories / OSV). Scan the vulnerable commit (detection) and the fixed commit (false alarm if
     still flagged at that spot). Add as a suite kind in `core/benchmark.py`, pinned commits in `suites.json`.
   - Ordinary apps: a few popular, well-maintained Django, FastAPI, Express and NestJS projects, to measure false
     alarms on real code. Add to `compare.json` with origin "fresh".
   - Keep a separate blind set (a few of each) that is scanned only at the end of this plan.
2. **Source-returning helpers**: summaries follow data into helpers, not out. Add a pass with request sources
   and `return` as the sink to find functions that return request data, then treat calls to them as sources
   (`core/analyzers/summaries.py`, same visibility rules).
3. **Framework sources**: FastAPI parameters declared with `Query()`/`Path()`/`Body()`/`Form()`/`Header()` or a
   Pydantic body model; NestJS `@Body()`/`@Query()`/`@Param()`/`@Headers()`; Next.js API route `req`; Fastify
   `request.body/query/params`. Rules: `catalog/codewatch/rules/python-web.yml`, `javascript-taint.yml`.
4. **Object fields**: `self.x = request...` in one method reaching a sink in another.
5. **JS dependency vulnerabilities**: add osv-scanner (lockfiles for npm, yarn, pnpm; also Go, Rust, Java) as an
   analyzer alongside pip-audit.
6. Re-run everything, then the blind set; update the README table and the comparison report.

## How things work (non-obvious)

- Semgrep OSS limits, and the workarounds in `core/analyzers/`: taint is intraprocedural (two-pass summaries in
  `summaries.py`, up to 3 calls deep); taint is lost at slices (`slices.py`), on dict keys after any clean write
  (`containers.py` rewrites constant keys to attributes), in dead constant branches (`constant_branches.py`), and
  after a `match` statement Semgrep silently skips the rest of the function (`match_statements.py`). All rewrites
  keep line numbers. Semgrep refuses symlinked targets (exit 2 fails the whole scan), so they're skipped.
- Metavariables are interpolated into messages even in taint mode; summaries use `$FUNC|$PARAM|$VIA_FUNC`.
- String-literal regex patterns `"=~/.../"` match constant-propagated values.
- A registry Semgrep vulnerability whose CWE a codewatch taint rule covers for that language is downgraded to a
  hotspot; rules with `metadata.security-purpose: required` are vulnerabilities only near secret/verification code.
- The bare `request` source excludes a local `request = something(...)`.
- The codewatch server reads rule files on every request: don't edit rules while a comparison run is going.
- A YAML `&` in rule text breaks `test_builtin_rules_load_and_a_broken_custom_file_is_skipped`; use `\x26`.

## Tools

- `venv/bin/python benchmarks/devtools.py bench|rules|repos|owasp|sonar-only` (see its docstring).
- `venv/bin/python benchmarks/compare.py [names]` runs codewatch and SonarQube side by side. Needs the local
  servers (SonarQube :9000, codewatch :8100). Tokens: `~/.sonar/token` and the codewatch MCP server's env in
  `~/.claude.json`; never print them. Both are temporary and to be revoked when this work ends.
- Suites are cached in `~/.cache/codewatch/benchmarks/`, fresh repos in `~/.cache/codewatch/fresh/`, raw
  comparison results in `~/.cache/codewatch/compare/`.
