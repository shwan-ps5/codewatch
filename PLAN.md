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

After the standards-gap rules (CWE-209, CWE-434, CWE-915; 2026-10-30): SecurityEval 51/121 verdict, 77/121 review;
Copilot review 51%, InCoder review 47%; no case lost, false alarms unchanged. The rules came from the coverage
gaps, not from these suites.

Remaining Juice Shop misses are business logic, data files, Solidity and a Docker image; most remaining
SecurityEval misses are design flaws or plain functions with no request source. Don't chase those with rules.

## Where things stand (2026-10-31, commit 799955c)

- Step 1 is built: `cve-pairs-python` (14 cases), `cve-pairs-javascript` (10), and blind `cve-pairs-blind-*`
  (run only when named). Ordinary apps (7) give 0 vulnerability false alarms. Standards-gap rules (CWE-208, 209,
  306, 434, 532, 614, 915, 942, 1004, 1336, 90, 643) and the OSV lockfile analyzer are in.
- First CVE-pair run, at commit 6f3739a (before e7c27d4's rules and the scan narrowing in 799955c):

  | Suite | Verdict found / still flagged | Review found / still flagged |
  |---|---|---|
  | cve-pairs-python | 2/14 / 1/14 | 5/14 / 1/14 |
  | cve-pairs-javascript | 1/10 / 1/10 | 4/10 / 4/10 |

  Its result files (`benchmarks/results/cve-pairs-*`) were left uncommitted.
- The CVE suites are slow (Python ~4.5 h on the laptop, which overheated); run them on the desktop:
  `venv/bin/python benchmarks/devtools.py bench cve-pairs-python cve-pairs-javascript`, then commit the results
  as the CVE baseline for 799955c.

What to work on next, from that run (these suites are not held out; note in `suites.json` when a case drives a
rule):

1. Still flagged after the fix: GHSA-9x43-5qcq-h79q (Python open-redirect, same 5 spots) and GHSA-v279-v2xm-whq9
   (JS open-redirect). Find which check the fix added and whether it should count as a sanitizer.
2. JS path traversal: 0 of 5 CWE-22 cases found. Look at what source/sink shapes the misses use (Fastify, Koa,
   static-file helpers, `path.join` with `decodeURIComponent`).
3. Python command injection (GHSA-gjxm, -2689, -xv5p) and SQL injection (GHSA-f2mf, -h6m6; only bandit B608
   hotspots fire) misses: likely sources the rules don't know (steps 2-4 below).
4. Then continue the steps below, re-running the CVE suites after each.

Not filled, by choice: CSRF beyond the existing hotspots; authorization (CWE-862/863/639), which needs app
knowledge.

## Next steps, in order

1. **Real-world measurement sets** (done, see above):
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
5. **JS dependency vulnerabilities**: done for npm, yarn and pnpm lockfiles by the `osv` analyzer
   (`core/analyzers/dependencies.py`), which parses them itself and asks OSV's batch API, so no new binary. Go, Rust
   and Java lockfiles would need the osv-scanner binary in `tools/`; downloading it needs the user's go-ahead.
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
- Rules are dumped for Semgrep without YAML aliases, so `&` in rule text is fine.
- A taint rule whose sources aren't request data (stack traces, upload file names, the request path) sets
  `metadata.interprocedural: false`; otherwise the summary pass treats every parameter as a source and the
  uncalled-entry-point hotspots fire on unrelated code.
- A source inside a sanitizer's region still counts as tainted (`if DEBUG: return format_exc()`); exclude it with
  `pattern-not-inside` on the source instead. Operators can't be metavariables (`$A $OP $B` fails to parse).
- `metavariable-pattern` matches anywhere inside the value; use `metavariable-regex` on the text when the whole
  value must be the thing (mass-assignment rules).
- Don't run two scans at once: one benchmark scan failed with Semgrep exit 2 while another scan ran.
- CVE-pair scans set `Context.focus` to the changed files: summaries, the caller index and other analyzers still
  see the whole scope, only Semgrep's per-file final pass is narrowed. Checked identical on Parsl and mockoon
  (both sides); saves ~50% on JS, only 10-17% on Python, where the summary passes dominate.

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
| https://github.com/django/djangoproject.com | 695eca42ae | ordinary Django site: expect 0 |
| https://github.com/wagtail/bakerydemo | c9b38d7a71 | ordinary Django/Wagtail app: expect 0 |
| https://github.com/fastapi/full-stack-fastapi-template | f4bcfaba7c | ordinary FastAPI app: expect 0 |
| https://github.com/nsidnev/fastapi-realworld-example-app | 029eb7781c | ordinary FastAPI app: expect 0 |
| https://github.com/hagopj13/node-express-boilerplate | 179ae84efe | ordinary Express app: expect 0 |
| https://github.com/lujakob/nestjs-realworld-example-app | c1c2cc4e44 | ordinary NestJS app: expect 0 |
| https://github.com/brocoders/nestjs-boilerplate | 9620f159ee | ordinary NestJS app: expect 0 |

Blind set, cloned in `~/.cache/codewatch/blind/`; scan only in step 6, never use to adjust rules:

| Repo | Commit | Kind |
|---|---|---|
| https://github.com/HackSoftware/Django-Styleguide-Example | a70ef43d7d | ordinary Django app |
| https://github.com/igorbenav/FastAPI-boilerplate | 2d0ca1a79a | ordinary FastAPI app |
| https://github.com/sahat/hackathon-starter | a2e4b4057a | ordinary Express app |
| https://github.com/notiz-dev/nestjs-prisma-starter | 225e5a9068 | ordinary NestJS app |

CVE fix pairs are suites (`cve-pairs-*` in `benchmarks/suites.json`); the `cve-pairs-blind-*` suites are skipped
unless named and follow the same rule.

The user's own repos in `~/dev` (md2html, kitten-home, claude-quiz, tracker, periplus, spectrum-arcade,
members-public, ProsperoEden, ProsperoStore) are useful false-alarm checks; known real findings: md2html
`load_css` path traversal, claude-quiz `random.choices` session keys, Prospero tools' FTP and unfiltered tar.
