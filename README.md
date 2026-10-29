# codewatch

> **Work in Progress** — usable for local scanning, but the data model, CLI, API and UI may change without notice. Expect rough edges.

Self-hosted code-quality server: branch analysis, new-code tracking, quality gates, coverage, duplication, dependency CVEs, security hotspots and accessibility checks, built on open-source analyzers. Django + SQLite, no containers or JVM.

Like sonar-scanner, scans normally run **on the developer's machine** against the local working copy (private repos never leave it) and upload the results. The server can also clone and scan a repository URL itself.

## Server setup

```bash
git clone https://github.com/shwan-ps5/codewatch && cd codewatch
python3 -m venv venv && venv/bin/pip install -e '.[dev,mcp]'
make tools                      # Node analyzers, semgrep and checkov (own venvs), headless Chromium (needs Node 20+)
venv/bin/python manage.py migrate
make run                        # http://127.0.0.1:8100
```

Log in as **admin / admin**; you'll be asked to change the password straight away. Add users under **Users**. Optional: `cppcheck` (apt) for C/C++.

For anything beyond localhost set `CODEWATCH_SECRET_KEY`, `CODEWATCH_DEBUG=0` and `ALLOWED_HOSTS`, and put it behind HTTPS. Only give accounts to people you trust: server-side scans run analyzers (and pip-audit's dependency resolution) over repository content.

## Scanning from your working copy

Each developer installs the client (same checkout, `pip install -e .` plus `make tools`) and creates a token on their **Account** page.

```bash
export CODEWATCH_URL=http://codewatch.example:8100
export CODEWATCH_TOKEN=cw_...            # scan-scope token; never commit it

cd ~/dev/my-app
codewatch init --hook pre-push           # writes codewatch-project.json, installs the hook
codewatch coverage                       # run tests with coverage -> coverage.xml
codewatch scan                           # analyse and upload; creates the project if it doesn't exist
```

`codewatch scan` works without any config: the project key defaults to the folder name and the main branch to origin's HEAD branch. Uncommitted and untracked (non-ignored) files are included, and the branch name comes from git, so every branch gets its own results and quality gate, visible before it is merged.

`codewatch-project.json` (commit it):

```json
{
  "projectKey": "my-app",
  "projectName": "My App",
  "mainBranch": "main",
  "serverUrl": "http://codewatch.example:8100",
  "testCommand": "venv/bin/pytest --cov --cov-report=xml",
  "coverageReport": "coverage.xml",
  "disabledAnalyzers": ["semgrep"]
}
```

All keys are optional. Without `testCommand`, `codewatch coverage` runs `coverage run -m pytest` with the project's `venv/`/`.venv/` Python, or `npm test` under c8 for Node projects.

### Git hook

`codewatch init --hook pre-push` installs a hook that runs `codewatch coverage` (a test failure stops the push) and then `codewatch scan`. By default a failing quality gate is only reported; `--strict` makes it block the push. An existing hook is never overwritten.

### Sharing a project

The project owner adds people under **Settings → Members**:

- **Contributor**: can upload scans of their own clone with their own token, and resolve issues.
- **Viewer**: can see results only.

Administrators see every project.

## Languages

| Language / target | What runs |
|---|---|
| **Python** (incl. Django, Flask, FastAPI) | ruff (bugs, smells, Django rules), bandit (security), basedpyright (type errors such as None access and wrong arguments), radon (cyclomatic complexity, maintainability index), complexipy (cognitive complexity), semgrep registry rules (incl. Django/Flask/FastAPI security), pip-audit (dependency CVEs), codewatch checks |
| **JavaScript / TypeScript** | ESLint core rules plus eslint-plugin-security, lizard (complexity), semgrep, codewatch checks; jsx-a11y for JSX/TSX |
| **HTML / Django & Jinja templates** | html-validate accessibility rules (template tags are blanked, Alpine/Vue bindings understood) |
| **CSS** | stylelint (invalid values, unknown properties, duplicates) |
| **Live pages** | axe-core in headless Chromium: WCAG 2.2 AA including colour contrast |
| **C / C++** | cppcheck, lizard, semgrep |
| **Dockerfile, Terraform, Kubernetes, GitHub Actions** | checkov |
| **Any file** | detect-secrets (hard-coded secrets), jscpd (duplication) |
| **Java, Go, Ruby, PHP, Kotlin, Rust, C#…** | semgrep registry rules and lizard complexity only, for now |

codewatch's own checks (Python and JS/TS): **string literals repeated more than N times** in a file (default 3), and **regexes vulnerable to catastrophic backtracking (ReDoS)**, analysed with recheck. Cognitive complexity is flagged above 15 by default; thresholds are per project.

Issue types: bug, vulnerability, **security hotspot** (security-sensitive code to review), code smell, accessibility. When several tools report the same problem on the same line, it becomes one issue that lists the others ("also reported by").

**New code**: on a branch, everything changed since its merge-base with the main branch (plus uncommitted/untracked files for local scans); on main, everything since the previous analysis by default. Because that window restarts with every scan, a run of small commits can each fall under the 20-line minimum for coverage and duplication checks. Set **New code on the main branch** in project settings to `30d` (since the newest analysis at least 30 days old) or to a tag, branch or commit such as `v1.4` to keep the window open across scans; a ref that doesn't resolve or isn't in main's history falls back to the previous analysis. Issues are fingerprinted by rule + file + source text, so they keep their identity, and any won't-fix / false-positive resolution, when code moves.

## Ratings and the quality gate

Each analysis gets A–E ratings, overall and on new code: **reliability**, **security** and **accessibility** (worst open issue of that type), **maintainability** (SQALE technical-debt ratio) and **security review** (share of hotspots reviewed), combined into a 0–100 **health score**. The `/ratings/` page explains the formulas.

Default gate compared with the "Sonar way" gate as Sonar documents it publicly:

| Condition on new code | codewatch default | Sonar way |
|---|---|---|
| New issues | none that are blocker/critical, no bugs, no vulnerabilities, maintainability A | no new issues (ratings A) |
| Security hotspots | security review A (≥ 80% reviewed) | all reviewed |
| Coverage | ≥ 80% | ≥ 80% |
| Duplication | ≤ 3% | ≤ 3% |
| Small changes | coverage/duplication skipped under 20 new lines | same |
| Dependency CVEs | no critical ones (overall) | not in the free edition |
| Accessibility | no new accessibility issues | not included |

Every condition can be changed per project under **Settings**.

## Rule catalogue

`/rules/` is a public, searchable catalogue of every rule (about 4,100), with what's wrong, how to fix it and examples where the source documentation is freely licensed (ruff, bandit, ESLint, stylelint, jsx-a11y), plus MITRE CWE descriptions, mitigations and example code for security rules. Each rule links to its origin and its standards: CWE, OWASP Top 10 (2025), WCAG 2.2, PEPs. `/standards/` shows coverage of the CWE Top 25, OWASP Top 10 and WCAG A/AA by language, with gaps marked.

The catalogue has three parts:

- `catalog/codewatch/rules/*.yml`: codewatch's own built-in rules (taint rules for Flask/Django/FastAPI request data reaching SQL, shell, eval, file paths, XPath, LDAP, redirects, sessions and HTML responses; weak hashes, insecure cookies, XXE; Django views without method restrictions; `|safe`/`autoescape off` in templates; Angular sanitizer bypasses, NoSQL injection and substring URL allowlists in JS/TS). They ship with codewatch and run in every scan.

The rest of the catalogue has two layers:

- `catalog/imported/` is generated from the analyzers' own metadata and from MITRE, W3C and the Semgrep registry, and is **replaced on every import**. Rules from restrictively licensed sources (Semgrep registry, cppcheck's GPL messages) are recorded by ID, classification and CWE only.
- `catalog/custom/` is **never touched by an import**:
  - `rules/*.yml`: your own checks in [Semgrep rule syntax](https://semgrep.dev/docs/writing-rules/rule-syntax). They run in every scan, including local `codewatch scan` runs (the server sends them with the project config). Add `metadata.cwe`, `owasp` and `references` and they appear in the catalogue and coverage.
  - `mappings.json`: extra CWE / WCAG / OWASP mappings for rules whose tool doesn't publish them, and `equivalent` groups of rules that perform the same check.
  - `overrides.json`: change a rule's severity, type or title, or disable it.

Admins can press **Update rules now** (optionally upgrading the analyzers first) on `/rules/`. Updates also run automatically every `CODEWATCH_CATALOG_UPDATE_DAYS` days (default 7, `0` disables; set `CODEWATCH_CATALOG_UPGRADE_TOOLS=1` to include analyzer upgrades), or from cron with `manage.py updatecatalog [--upgrade-tools]`. A server's imports go to its cache directory; `manage.py buildcatalog` refreshes the snapshot committed in `catalog/imported/`.

## Benchmarks

`codewatch benchmark` scans third-party code with published ground truth, pinned to a commit (never executed), and writes results to `benchmarks/results/`. Two modes are scored: **verdict** counts only findings that claim a vulnerability (data reaching a dangerous call, or a definite flaw such as a weak hash or an insecure cookie), which is what the Security rating uses; **review** adds security hotspots, i.e. everything a reviewer is asked to look at.

| Suite | Verdict | Review |
|---|---|---|
| [OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython): 1,230 labelled cases, 14 CWEs | finds 74%, false alarms 35%, score **+40%** | finds 84%, false alarms 59%, score +25% |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop): 35 marked vulnerable challenges (JS/TS) | 7 flagged (20%) | 15 flagged (43%) |

The score is detection minus false alarms (OWASP Benchmark's own measure), averaged over categories. Known limits: Semgrep's open-source engine doesn't evaluate constant branches, so benchmark cases that switch data off with `if 7 * 42 > 200` style conditions still raise false alarms; many Juice Shop challenges are business-logic flaws (missing ownership checks, weak security questions) that no static analyzer can recognise. Juice Shop measures detection only, since its unmarked code isn't labelled safe.

## Claude / MCP

Create a token for Claude on your Account page (a **read** token lets it list and resolve issues; a **scan** token can also start server-side scans), then:

```bash
claude mcp add codewatch -e CODEWATCH_URL=http://127.0.0.1:8100 -e CODEWATCH_TOKEN=cw_... \
  -- /path/to/codewatch/venv/bin/codewatch-mcp
```

Tools: `list_projects`, `quality_gate`, `list_issues` (filter by branch, new code, type, severity, tool, path), `list_security_hotspots`, `get_issue` (with source snippet and rule summary), `get_rule` (explanation, fix guidance and examples), `resolve_issue`, `start_server_scan`. Paths are repo-relative, so the agent can fix issues in its local checkout and rescan with `codewatch scan`.

## HTTP API

All endpoints take `Authorization: Bearer <token>`.

| Method | Path | |
|---|---|---|
| GET | `/api/projects/` | projects you can see, with latest analysis per branch |
| GET | `/api/projects/<key>/status/?branch=` | latest analysis: gate, metrics, tools |
| GET | `/api/projects/<key>/issues/?branch=&new=1&type=&severity=&tool=&path=&status=&limit=&offset=` | issues, most severe first |
| GET | `/api/issues/<id>/?context=5` | one issue with source snippet and its rule |
| GET | `/api/rules/<rule id>/` | catalogue rule with explanation and CWE fix guidance |
| POST | `/api/issues/<id>/resolve/` | `{"status": "false_positive" \| "wont_fix" \| "reopen", "comment": ""}` |
| GET | `/api/projects/<key>/config/` | scan settings used by the client (scan scope) |
| POST | `/api/projects/<key>/analyses/` | upload a `codewatch scan` payload (scan scope; gzip JSON) |
| POST | `/api/projects/<key>/scan/` | server-side scan: `{"branch", "repo_url" (new projects), "name"}`, optional `coverage` file (scan scope) |

## Server-side scans

For repositories the server can reach (public or with server-side git credentials): create the project in the UI with a repository URL, use `manage.py addproject KEY URL`, or `POST /api/projects/<key>/scan/`. Branches are scanned from a bare mirror in `~/.cache/codewatch/`, never touching a working copy. Only administrators may register server-local paths.

```bash
venv/bin/python manage.py scan my-app --all-branches --fail-on-gate
```

## Development

```bash
make test    # pytest; accessibility tests are skipped if tools/ isn't installed
make lint
```
