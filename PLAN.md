# Detection plan

Goal: an open-source scanner with high detection and false alarms as close to zero as possible, without hiding
real issues, measured against published ground truth. Python first, JavaScript/TypeScript close behind.

## Ground rules

- Never change the projects being scanned to make findings go away.
- Measure only against published ground truth and our own labelled sets. Don't run or analyse other vendors'
  scanners as part of this work (some are licensed for non-competitive use only, and exclude AI analysis of their
  output); codewatch uses open rule sets and its own rules. People can run their own comparisons.
- Never tune on held-out suites (SecurityEval Copilot and InCoder answers, Vulnerable-Code-Snippets JS) or on a
  blind repo set. Once a suite or repo is used to write or adjust rules, say so in `benchmarks/suites.json` or
  PLAN.md (repos) and in the README.
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

Remaining Juice Shop misses are business logic, data files, Solidity and a Docker image; most remaining
SecurityEval misses are design flaws or plain functions with no request source. Don't chase those with rules.

## Next steps, in order

1. **Real-world measurement sets** (do first, before more rules):
   - CVE before/after pairs: Python and JS web projects with a published advisory and a fix commit (GitHub
     Security Advisories / OSV). Scan the vulnerable commit (detection) and the fixed commit (false alarm if
     still flagged at that spot). Add as a suite kind in `core/benchmark.py`, pinned commits in `suites.json`.
   - Ordinary apps: a few popular, well-maintained Django, FastAPI, Express and NestJS projects, to measure false
     alarms on real code. Record them under "Repos" below.
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
6. Re-run everything, then the blind set; update the README table.

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
- The codewatch server reads rule files on every request: don't edit rules while a benchmark or repo run is going.
- A YAML `&` in rule text breaks `test_builtin_rules_load_and_a_broken_custom_file_is_skipped`; use `\x26`.

## Tools

- `venv/bin/python benchmarks/devtools.py bench|rules|repos|owasp` (see its docstring); `codewatch benchmark` for
  the full suite run that writes `benchmarks/results/`.
- Suites are cached in `~/.cache/codewatch/benchmarks/`, extra repos in `~/.cache/codewatch/fresh/`.

## Repos

Already learned from (not blind), pinned commits, cloned in `~/.cache/codewatch/fresh/`:

| Repo | Commit | Kind |
|---|---|---|
| https://github.com/anxolerd/dvpwa | a1d8f89fac | deliberately vulnerable (Python) |
| https://github.com/adeyosemanputra/pygoat | 46fef968f3 | deliberately vulnerable (Python) |
| https://github.com/fportantier/vulpy | 5249cc8b05 | deliberately vulnerable, with a fixed `good/` copy |
| https://github.com/OWASP/NodeGoat | c5cb68a708 | deliberately vulnerable (JS) |
| https://github.com/appsecco/dvna | 9ba473add5 | deliberately vulnerable (JS) |
| https://github.com/cr0hn/vulnerable-node | d68f2a3c92 | deliberately vulnerable (JS); its seeds are a suite |
| https://github.com/miguelgrinberg/microblog | a975ef6486 | ordinary Flask app: expect 0 vulnerabilities |
| https://github.com/gothinkster/node-express-realworld-example-app | 30b68e1e88 | ordinary Express app: expect 0 |

The user's own repos in `~/dev` (md2html, kitten-home, claude-quiz, tracker, periplus, spectrum-arcade,
members-public, ProsperoEden, ProsperoStore) are useful false-alarm checks; known real findings: md2html
`load_css` path traversal, claude-quiz `random.choices` session keys, Prospero tools' FTP and unfiltered tar.
