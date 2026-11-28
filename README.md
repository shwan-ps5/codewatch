# codewatch

[![codewatch checks itself](https://github.com/shwan-ps5/codewatch/actions/workflows/codewatch.yml/badge.svg?branch=detection-gaps)](https://github.com/shwan-ps5/codewatch/actions/workflows/codewatch.yml)

> **Work in Progress** — usable for local scanning, but the data model, CLI, API and UI may change without notice. Expect rough edges.

Self-hosted code-quality server: branch analysis, new-code tracking, quality gates, coverage, duplication, dependency CVEs, security hotspots and accessibility checks, built on open-source analyzers. Django + SQLite, no containers or JVM.

Scans normally run **on the developer's machine** against the local working copy (private repos never leave it) and upload the results. The server can also clone and scan a repository URL itself.

## How well it works

The fairest numbers are from code the rules were never tuned on, so they come first. Detection is "found" in
verdict mode, i.e. findings that claim a vulnerability.

| Measure (never used to write or tune rules) | Result |
|---|---|
| Python CVE fix pairs, blind, round 2: 40 back-end cases (half of them, run once on 2026-11-28) | 11 of 40 found (28%), 3 still flagged after the fix; review mode 20 found, 9 still flagged |
| Python front-end CVE fix pairs, blind, round 2: 10 cases (the same half) | 1 of 10 found; review mode 6 found, 4 still flagged |
| Python CVE fix pairs, blind, round 1 | 2 of 5 found, 1 still flagged after its fix |
| SecurityEval Copilot answers, Python (held out) | finds 34%, false alarms 0% |
| SecurityEval InCoder answers, Python (held out) | finds 31%, false alarms 0% |
| Vulnerable-Code-Snippets, JS/TS (held out) | 11 of 22 flagged |
| Ordinary apps, three blind sets of four (Django, FastAPI, Express, NestJS) | false alarms in 2, 2 and 4 of the 4 apps |

On the Python CVE pairs the rules were tuned on, codewatch finds 70 of 109 (64%). On advisories it has never
seen, it finds 28% (11 of 40; with this few cases, roughly 15-44%). So most of the tuned number is the tuning,
not the general ability. The blind run had other benchmarks running at the same time, and under load Semgrep can
give up on slow rules, so a case or two may have dropped out. That doesn't come close to closing the gap. On ordinary apps it hasn't seen, expect some false alarms;
[docs/rule-trust.md](docs/rule-trust.md) shows, rule by rule, how often each one is right on the CVE pairs and
how often it fires on clean apps. Everything is in [Benchmarks](#benchmarks).

**Scope.** Python web apps (Django, Flask, FastAPI) are the focus and where the rules are strongest. The
JavaScript/TypeScript and PHP rules are earlier-stage (22 of 103 and 75 of 341 CVE pairs found). Other languages
get the Semgrep registry and complexity checks only.

## Quick start: check a repository

No server needed. Every analyzer runs locally on the files, and nothing is uploaded.

```bash
docker build -t codewatch https://github.com/shwan-ps5/codewatch.git
docker run --rm -v "$PWD:/src" codewatch check --all       # every file; issues are listed, blocking ones marked !
```

As a GitHub Actions step, after `actions/checkout` (pin a commit SHA):

```yaml
- uses: shwan-ps5/codewatch@<commit sha>
  with:
    strict: "false"   # "true": any open issue fails the job
```

As a [pre-commit](https://pre-commit.com) hook, run in the Docker image on the files a commit changes:

```yaml
- repo: https://github.com/shwan-ps5/codewatch
  rev: <commit sha>
  hooks:
    - id: codewatch
```

Or from a clone: `pip install -e .`, `make tools`, then `venv/bin/codewatch check --all`. The server below adds
history, new-code tracking, ratings and the quality gate. To run the server in Docker:
`docker run -d -p 8100:8100 -v codewatch-data:/data -e CODEWATCH_ALLOWED_HOSTS=your.host --entrypoint /opt/codewatch/docker-serve.sh codewatch`.

## Server setup

```bash
git clone https://github.com/shwan-ps5/codewatch && cd codewatch
python3 -m venv venv && venv/bin/pip install -e '.[dev,mcp]'
make tools                      # Node analyzers, semgrep and checkov (own venvs), headless Chromium (needs Node 20+)
venv/bin/python manage.py migrate
make run                        # http://127.0.0.1:8100
```

Log in as **admin**: `migrate` prints where its first password is (`~/.cache/codewatch/admin-password.txt`, readable only by you), or set `CODEWATCH_ADMIN_PASSWORD` before the first `migrate`. You'll be asked to change it straight away. Add users under **Users**. Optional: `cppcheck` (apt) for C/C++.

For anything beyond localhost, put it behind HTTPS and set `CODEWATCH_ALLOWED_HOSTS` (comma-separated host names) and `CODEWATCH_HTTPS=1` (secure cookies, HSTS). The secret key is generated once into `~/.cache/codewatch/secret_key` unless `CODEWATCH_SECRET_KEY` is set; `CODEWATCH_DEBUG=1` turns on Django's debug pages, never on a shared server. Ten wrong passwords in a row lock a username out for 15 minutes.

What the server does on users' behalf is limited to what they could do themselves: their projects clone with none of the server's git credentials, reach only public addresses (repository, accessibility pages) and use only Semgrep registry rulesets; checkouts lose their symlinks, and a repository's own virtualenv and package builds are never run (pip-audit checks pinned requirements as written). Projects an administrator owns, or added with `manage.py addproject`, may use the server's credentials, its local network and local paths. Analyzers still read repository content, so for untrusted code run the server in a container.

## Scanning from your working copy

Each developer installs the client (same checkout, `pip install -e .` plus `make tools`) and creates a token on their **Account** page.

```bash
export CODEWATCH_URL=https://codewatch.example
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
  "serverUrl": "https://codewatch.example",
  "testCommand": "venv/bin/pytest --cov --cov-report=xml",
  "coverageReport": "coverage.xml",
  "disabledAnalyzers": ["semgrep"]
}
```

All keys are optional. `serverUrl` is used only if you trust it: `codewatch init --url` records the server you give it in `~/.config/codewatch/servers.txt` (add others there, or set `CODEWATCH_URL`). The file is part of the repository, so a branch could otherwise send your token and code anywhere. The token only goes over HTTPS, except to localhost. Without `testCommand`, `codewatch coverage` runs `coverage run -m pytest` with the project's `venv/`/`.venv/` Python, or `npm test` under c8 for Node projects.

### Git hook

`codewatch init --hook pre-push` installs a hook that runs `codewatch coverage` (a test failure stops the push) and then `codewatch scan`. By default a failing quality gate is only reported; `--strict` makes it block the push. An existing hook is never overwritten.

`codewatch init --hook pre-commit` installs a hook that runs `codewatch check` on the staged files instead: every analyzer on just those files, locally, with nothing uploaded and none of the code run. A bug, a vulnerability or a blocker/critical issue **on a line the commit changes** stops it; older issues in the same files are listed but don't block (`git commit --no-verify` skips the hook). An analyzer that fails also stops it (exit 2), since the files weren't fully checked. Run it by hand too: `codewatch check` (the changed files), `codewatch check path/to/file.py`, or `--all-lines` to block on every issue in the named files. The project's settings come from the server when one is configured, else the defaults. Checks that need the whole project are left out: the dependency audit, coverage and live accessibility pages. Cross-file taint (input reaching a sink through a helper in another file) needs both files in the check, so the full `codewatch scan` remains the complete answer.

### Sharing a project

The project owner adds people under **Settings → Members**:

- **Contributor**: can upload scans of their own clone with their own token, and resolve issues.
- **Viewer**: can see results only.

Administrators see every project.

### codewatch on its own code

Every push runs [a workflow](.github/workflows/codewatch.yml) that installs the pinned analyzers, runs the lint and the tests, and then `codewatch check --all --strict`: every analyzer over the whole repository, where **any** open issue fails the run, whatever its kind or severity. No thresholds are raised for codewatch. The findings judged safe or false positives after reading them are in [`codewatch-reviews.json`](codewatch-reviews.json), each with its reason, and the run's summary page lists them, so those exceptions are public and can be questioned. The other exceptions are inline comments that switch a rule off for one line (`noqa`, `nosec`, `nosemgrep`, secret-scanner allowlists), each with its reason beside it or on the line above; moving the security ones into the reviews file is the next step. A review that no longer matches any finding fails the run, so the file can't keep reasons for code that has gone. `codewatch check` honours that file in any project, and the pre-commit hook gives the same answer locally before a commit leaves the machine.

## Languages

| Language / target | What runs |
|---|---|
| **Python** (incl. Django, Flask, FastAPI) | ruff (bugs, smells, Django rules), bandit (security), basedpyright (type errors such as None access and wrong arguments), radon (cyclomatic complexity, maintainability index), complexipy (cognitive complexity), semgrep registry rules (incl. Django/Flask/FastAPI security), pip-audit (dependency CVEs), codewatch checks |
| **JavaScript / TypeScript** | ESLint core rules plus eslint-plugin-security, lizard (complexity), semgrep, codewatch checks; jsx-a11y for JSX/TSX; known advisories for the versions pinned in package-lock.json, yarn.lock and pnpm-lock.yaml (looked up in OSV; development-only packages are hotspots) |
| **HTML / Django & Jinja templates** | html-validate accessibility rules (template tags are blanked, Alpine/Vue bindings understood) |
| **CSS** | stylelint (invalid values, unknown properties, duplicates) |
| **Live pages** | axe-core in headless Chromium: WCAG 2.2 AA including colour contrast |
| **C / C++** | cppcheck, lizard, semgrep |
| **Dockerfile, Terraform, Kubernetes, GitHub Actions** | checkov |
| **Any file** | detect-secrets (hard-coded secrets), jscpd (duplication) |
| **PHP** | semgrep registry rules, lizard, and codewatch taint rules (request data from superglobals and the common frameworks' request objects into SQL, OS commands, eval, file paths, HTML, redirects, outgoing URLs and `unserialize`, within one function); views in .phtml, CakePHP .ctp, Drupal .module/.theme and PHP .tpl files are scanned as PHP, and Twig, Blade, Latte and Smarty templates are read for values printed unescaped |
| **Java, Go, Ruby, Kotlin, Rust, C#…** | semgrep registry rules and lizard complexity only, for now |

codewatch's own checks (Python and JS/TS): **string literals repeated more than N times** in a file (default 3), and **regexes vulnerable to catastrophic backtracking (ReDoS)**, analysed with recheck. Complexity is checked two ways: cyclomatic complexity (radon for Python, lizard for other languages) is flagged above 10 and cognitive complexity (complexipy) above 15; either is critical above twice its threshold. Thresholds are per project.

codewatch also ships its own Semgrep rules (`catalog/codewatch/rules/`). Taint rules follow request data (Flask, Django, FastAPI, Starlette, Express, Koa, browser URL APIs) into SQL, NoSQL, OS commands, file paths, templates and HTML, redirects and `Location` headers, outgoing URLs (SSRF), regular expressions, XML parsers, deserializers, template engines (SSTI), LDAP/XPath queries and the session, and stop at validation such as an allowlist check, `int()`, `re.escape()` or a `startswith` guard that returns. Pattern rules catch flaws visible without a request source: quoted values formatted into SQL, tar extraction without a filter, template auto-escaping switched off, recursive merges open to prototype pollution, weak hashes used for passwords or signatures, weak ciphers and static IVs, disabled TLS verification, hard-coded JWT secrets, stack traces sent in responses, CORS that echoes any origin with credentials, HMAC signatures compared with `==`, and credential cookies without the Secure flag. Hotspot rules flag uploads stored under the client's file name without a type check, exception messages from a broad `except` sent to the client, a whole request body written to a model (mass assignment), redirects built from the request's own path, state-changing routes without the authentication middleware or login decorator their neighbours use, uploads without size limits, cookie protection switched off and secrets written to logs.

Issue types: bug, vulnerability, **security hotspot** (security-sensitive code to review), code smell, accessibility. When several tools report the same problem on the same line, it becomes one issue that lists the others ("also reported by").

**New code**: on a branch, everything changed since its merge-base with the main branch (plus uncommitted/untracked files for local scans); on main, everything since the previous analysis by default. Because that window restarts with every scan, a run of small commits can each fall under the 20-line minimum for coverage and duplication checks. Set **New code on the main branch** in project settings to `30d` (since the newest analysis at least 30 days old) or to a tag, branch or commit such as `v1.4` to keep the window open across scans; a ref that doesn't resolve or isn't in main's history falls back to the previous analysis. Issues are fingerprinted by rule + file + source text, so they keep their identity, and any won't-fix / false-positive resolution, when code moves.

## Ratings and the quality gate

Each analysis gets A–E ratings, overall and on new code: **reliability**, **security** and **accessibility** (worst open issue of that type), **maintainability** (the worse of the SQALE technical-debt ratio and the worst open code smell) and **security review** (share of hotspots reviewed), combined into a 0–100 **health score**. The `/ratings/` page explains the formulas.

The default quality gate, mostly on new code, plus a floor for the whole codebase so a first scan (which has no new code) can't pass a project full of old problems:

| Condition | Default |
|---|---|
| New issues | none that are blocker/critical, no bugs, no vulnerabilities, maintainability A |
| Security hotspots | security review A (≥ 80% reviewed) |
| Coverage | ≥ 80% |
| Duplication | ≤ 3% |
| Small changes | coverage/duplication skipped under 20 new lines |
| Dependency CVEs | no critical ones (overall) |
| Accessibility | no new accessibility issues |
| Whole codebase | reliability, security, security review and maintainability ratings C or better |

Every condition can be changed per project under **Settings**.

## Rule catalogue

`/rules/` is a public, searchable catalogue of every rule (about 4,100), with what's wrong, how to fix it and examples where the source documentation is freely licensed (ruff, bandit, ESLint, stylelint, jsx-a11y), plus MITRE CWE descriptions, mitigations and example code for security rules. Each rule links to its origin and its standards: CWE, OWASP Top 10 (2025), WCAG 2.2, PEPs. `/standards/` shows coverage of the CWE Top 25, OWASP Top 10 and WCAG A/AA by language, with gaps marked.

The catalogue has three parts:

- `catalog/codewatch/rules/*.yml`: codewatch's own built-in rules (taint rules for Flask/Django/FastAPI request data reaching SQL, shell, eval, file paths, XPath, LDAP, redirects, sessions and HTML responses; weak hashes, insecure cookies, XXE; Django views without method restrictions; `|safe`/`autoescape off` in templates; Angular sanitizer bypasses, NoSQL injection and substring URL allowlists in JS/TS; uploads, error details and mass assignment in both). They ship with codewatch and run in every scan.

The rest of the catalogue has two layers:

- `catalog/imported/` is generated from the analyzers' own metadata and from MITRE, W3C and the Semgrep registry, and is **replaced on every import**. Rules from restrictively licensed sources (Semgrep registry, cppcheck's GPL messages) are recorded by ID, classification and CWE only.
- `catalog/custom/` is **never touched by an import**:
  - `rules/*.yml`: your own checks in [Semgrep rule syntax](https://semgrep.dev/docs/writing-rules/rule-syntax). They run in every scan, including local `codewatch scan` runs (the server sends them with the project config). Add `metadata.cwe`, `owasp` and `references` and they appear in the catalogue and coverage.
  - `mappings.json`: extra CWE / WCAG / OWASP mappings for rules whose tool doesn't publish them, and `equivalent` groups of rules that perform the same check.
  - `overrides.json`: change a rule's severity, type or title, or disable it.

Admins can press **Update rules now** (optionally upgrading the analyzers first) on `/rules/`. Updates also run automatically every `CODEWATCH_CATALOG_UPDATE_DAYS` days (default 7, `0` disables; set `CODEWATCH_CATALOG_UPGRADE_TOOLS=1` to include analyzer upgrades), or from cron with `manage.py updatecatalog [--upgrade-tools]`. A server's imports go to its cache directory; `manage.py buildcatalog` refreshes the snapshot committed in `catalog/imported/`.

## Benchmarks

`codewatch benchmark` scans third-party code with published ground truth, pinned to a commit (never executed), and writes results to `benchmarks/results/`. Two modes are scored: **verdict** counts only findings that claim a vulnerability (data reaching a dangerous call, or a definite flaw such as a weak hash or an insecure cookie), which is what the Security rating uses; **review** adds security hotspots, i.e. everything a reviewer is asked to look at.

Not tuned on (held out, or blind: scanned once, never used to adjust rules):

| Suite | Verdict | Review |
|---|---|---|
| SecurityEval Copilot answers, manually labelled (held out) | finds 34%, false alarms 0% | finds 51%, false alarms 6% |
| SecurityEval InCoder answers, manually labelled (held out) | finds 31%, false alarms 0% | finds 47%, false alarms 0% |
| [Vulnerable-Code-Snippets](https://github.com/snoopysecurity/Vulnerable-Code-Snippets): 22 JS/TS snippets (held out) | 11 of 22 flagged | 13 of 22 flagged |
| Blind CVE fix pairs, round 2, half of the Python ones (run once on 2026-11-28): 40 back end, 10 front end | back end 11 of 40 found, 3 still flagged; front end 1 of 10 | back end 20 of 40, 9 still flagged; front end 6 of 10, 4 still flagged |
| Blind CVE fix pairs, first round (never looked at before this run): 5 Python, 4 JS/TS | Python 2 of 5 found, 1 still flagged; JS 1 of 4, 1 still flagged | same, JS 2 still flagged |
| Blind ordinary apps (Django, FastAPI, Express, NestJS; expected clean) | false alarms in 2 of 4 apps (12 findings, 10 in the Express app) | |
| Second blind set of ordinary apps (Django, FastAPI, Express, NestJS), after two learning sets | false alarms in 2 of 4 apps (34 findings, 28 in the Django app); 2 real at code level | |
| Third blind set of ordinary apps (Django, FastAPI, Express, NestJS), after three learning sets | false alarms in 4 of 4 apps (24 findings, 13 in the Express app); 2 real | |

Tuned on (rules were written or adjusted from these, so they flatter codewatch):

| Suite | Verdict | Review |
|---|---|---|
| [OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython): 1,230 labelled cases, 14 CWEs | finds 100%, false alarms 0% | finds 100%, false alarms 35% |
| [SecurityEval](https://github.com/s2e-lab/SecurityEval): 121 insecure Python samples filed by CWE | 50 of 121 flagged | 77 of 121 flagged |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop): 35 marked vulnerable challenges (JS/TS) | 15 of 35 flagged | 17 of 35 flagged |
| [vulnerable-node SAST seeds](https://github.com/cr0hn/vulnerable-node/tree/master/sast): 12 seeds and 2 clean controls (JS) | finds 92%, false alarms 0% | finds 100%, false alarms 50% |
| CVE fix pairs, Python: 109 advisories and fixes in web apps (vulnerable commit, then its fix) | 70 of 109 found, 10 still flagged after the fix | 74 of 109 found, 21 still flagged |
| CVE fix pairs, Python front end: 32 advisories fixed in templates or front-end JS | 4 of 32 found | 16 of 32 found, 8 still flagged |
| CVE fix pairs, JS/TS: 103 advisories in web apps | 22 of 103 found, 9 still flagged | 46 of 103 found, 32 still flagged |
| CVE fix pairs, PHP: 341 advisories in PHP apps and CMSs | 75 of 341 found, 27 still flagged | 83 of 341 found, 36 still flagged |
| CVE fix pairs whose input isn't an HTTP request (desktop, bot, agent and MCP tool input): 15 Python, 38 JS/TS | 5 of 53 found, 2 still flagged | 16 of 53 found, 11 still flagged |

The CVE pairs are real projects' advisories: a finding of the advisory's weakness near the lines its fix changed counts as found (or one the fix makes go away, when the fixed side's scan finished every rule), and one that survives the fix as a false alarm. The non-blind pairs were used to adjust rules (which ones, and for what, is in `benchmarks/suites.json`); the blind ones and the blind apps were scanned once, at the end, without adjusting anything, and read case by case the JS blind "find" is the same noise on both sides of its fix. The blind apps show that zero false alarms on the apps used for tuning doesn't carry over: fixed-prefix relative redirects, requests to fixed hosts with an encoded query, and JSON written to an event stream were all flagged. The first two shapes are now handled, learned from five other ordinary apps (flaskbb, outline, proshop-v2 and two Express boilerplates, listed in `PLAN.md`), and five more in the second blind set's frameworks (wger, taiga, dispatch, immich, linkwarden: 86 false alarms down to 1); the second blind set, chosen and pinned before any scan, says it mostly doesn't: the Express and NestJS apps were clean, but the Django app had 28 false alarms of shapes the learning apps never showed (a project's own redirect allowlist function, a `reverse()` URL with a query string appended, session writes as trust-boundary findings, SHA-1 keyed with the secret key). The third blind set, after a third learning set aimed at Django, did worse by apps: Python is now close (3 false alarms in two apps) but every JavaScript app brought shapes of its own (SVG badges and RSS feeds rendered by escaping libraries, cache and Redis lookups keyed by request data, an opt-in TLS bypass, a cookie made secure through config). A fourth learning set, mostly Express apps, took JavaScript's false alarms there from 37 to 27. The focus is now Python web apps and the JavaScript they ship. The CVE pairs have grown from advisories GitHub reviewed (PyPI, npm) and, since 2026-11-03, from advisories it never reviews, which is where apps that aren't published as packages get theirs, since 2026-11-13 from Python and JS/TS app CVEs that have no GitHub advisory at all (read from the CVE list), and since 2026-11-20 from security fixes apps made without any advisory or CVE (found through GitHub's commit search; ids `FIX-OWNER-REPO-SHA`): each fix read and accepted or rejected with a reason, and a third of the accepted ones split off as blind before any scan. The table above is the nightly run of 2026-11-28. PHP has had rules since 2026-11-14, written from the first 197 reviewed PHP app and CMS pairs (where Semgrep's registry rules alone found none); `cve-pairs-php` has since grown to 342, the rest scored only after the rules were written. The blind CVE suites of this round (60 Python and JS/TS suites with 219 cases, and 36 PHP suites with 226) and a fourth blind set of Python apps with JavaScript front ends wait for the end of the round. The pairs without an HTTP request are kept apart because codewatch has no sources for that input yet. Of the Python pairs' still-flagged fixes, the ones read as incomplete fixes are counted as real findings. Details: `PLAN.md` for where things stand, `docs/plan-log.md` for every step and the case behind it.

The score on OWASP is detection minus false alarms (OWASP Benchmark's own measure), averaged over categories. "Held out" suites were never used to write or tune rules, so they are the fairer measure; the others were. The Copilot and InCoder answers respond to the same prompts as SecurityEval's own samples, which were used for rules, so their numbers are not fully independent.

Semgrep's open-source engine follows data within one function and loses it at slices, `match` statements, dict keys and constant-folded branches. codewatch scans a line-for-line rewritten copy of Python files (dead constant branches blanked, slices made indexes, constant container keys made attributes, `match` made `if`), and summarises functions before the main scan: the taint rules run with function parameters as sources to find which parameters reach a sink, then again with calls to those functions as extra sinks, up to three calls deep. A call only counts where the function is visible (same file, or an import that resolves to the defining file), so same-named functions elsewhere don't connect. When only some files count (a CVE pair's changed files and what renders or imports them), the summaries cover just those files and the project files they import, transitively, including modules named in dotted strings such as Django's `ROOT_URLCONF`, and the main scan gives each rule a minute on those files rather than skipping one when rules run past Semgrep's usual five seconds. A parameter that reaches a sink in a function nothing in the project calls (a library entry point, a handler registered elsewhere) is reported as a hotspot, since the danger depends on what its callers pass (unless it is typed as a number, boolean, UUID or date). Data coming out of helpers is followed too: a pass with `return` as the sink finds functions that return request data (`def get_param(name): return request.args.get(name)`), and calls to them become sources where they are visible; what a helper looks up with the request value (a model by id, a decoded token) and a view's response don't count. Request data stored in `self.x`/`this.x` in one method is followed into the others in that file. The opposite case is followed as well: a call to a project function that never returns its argument (`err = require_access(file, user)` returning a fixed message) doesn't pass the request data on, per parameter in Python and per function in JavaScript.

Request data means more than `request`: Flask route parameters (`<name>`; converters such as `<int:id>` are typed on the copy so they don't count), Django function views' URL arguments where their `urls.py` route passes free text (`<path:name>`, `(?P<name>.*)`; not `<int:pk>` or `\d+`), FastAPI parameters typed as text and the text fields of a project's Pydantic/SQLModel body models (and of the models nested in them, or a body model passed whole to a function), Django class-based views' `self.request` and `self.kwargs`, a Django REST framework ViewSet's lookup argument (`pk`, or its `lookup_field`) in its detail methods unless `lookup_value_regex` allows only digits, Flask-AppBuilder and Flask-Admin `@expose` routes' arguments, Frappe's `frappe.form_dict`, the arguments of `@frappe.whitelist()` methods (not numeric ones) and a script report's `filters`, and NestJS `@Body()`/`@Query()`/`@Param()`/`@Headers()` parameters (not with a parse pipe or a number/boolean/Date type). For XSS only, a Django model's text field also counts when the project fills it from request data (`Model.objects.create(field=...)`, `obj.field = ...`, a ModelForm or ModelSerializer, followed through the project's own helpers): reading it back in the model's admin, its own methods, or after `Model.objects...`/`get_object_or_404(Model, ...)` is stored XSS where it reaches `mark_safe`, `format_html`'s format string or a response.

A route parameter is request data where it's declared, so `name = secure_filename(name)` clears it. Templates are read too: request data passed to a variable a template prints with `|safe` or under `autoescape off` is reported as XSS at the `render_template`/`render` call (not for a form field, a value escaped or sanitized first, or an admin-only view). A template that prints request values itself at the start of a link (`href="{{ request.args.next }}"`) or inside an event handler is reported there, since autoescaping doesn't stop a `javascript:` URL. Inline `<script>` blocks in templates are scanned as JavaScript, on the template's own lines.

Most SecurityEval samples are plain functions with no request source, which caps verdict-mode detection there; much of the rest is design flaws (off-by-one, missing authentication, race conditions) outside what pattern and taint rules can see. Log injection is reported as a hotspot rather than a vulnerability, because whether a forged log line matters depends on the log format. Other known limits: Juice Shop measures detection only, since its unmarked code isn't labelled safe, and many of its challenges are business-logic flaws (missing ownership checks, weak security questions) that no static analyzer can recognise.

### Compared with CodeQL

GitHub's CodeQL (2.27.4, its default code-scanning queries for verdict and security-extended for review) was run once on the same CVE pairs, scored by the same fix spots, on 2026-11-14. Cases found, then still flagged after the fix; only cases both tools scored, and only under an OSI-approved licence (16 of 229 skipped):

| Suite | Cases | CodeQL | codewatch verdict | codewatch review |
|---|---|---|---|---|
| Python web apps | 76 | 23 found, 11 still flagged | 47 found, 12 still flagged | 49 found, 16 still flagged |
| Python front end | 31 | 4, 1 | 4, 0 | 14, 8 |
| JS/TS web apps | 65 | 8, 1 | 8, 6 | 23, 19 |
| Input that isn't an HTTP request (Python, JS/TS) | 32 | 2, 2 (review 3) | 2, 0 | 9, 6 |

On Python web apps codewatch finds about twice as many (19 found by both, 28 by codewatch only, 4 by CodeQL only) with about as many false alarms. On JavaScript the two tie in verdict mode with different cases (2 in common), and CodeQL leaves fewer findings on fixed code; the six only it finds are mostly path traversal, codewatch's weakest JavaScript area. CodeQL's results are a measurement only: no rule was written from them. CodeQL's terms allow it only on code under an OSI-approved licence (anything else needs a paid GitHub licence), so `benchmarks/codeql_compare.py` scans a case only when its licence is one; CodeQL itself is not part of codewatch and has to be installed separately (the script's docstring says how). Details in `docs/plan-log.md`, step 71.

Meta's Pysa (open source, follows data across functions) was tried on 2026-11-28 as a second comparison, and not
run on the pairs. Pysa 0.10 now needs Pyrefly for types, and its bundled Flask models name Werkzeug classes
removed in Werkzeug 2.1. On a ten-line Flask app with a shell command and a file path built from `request.args`,
it reported neither, even with current source models added. Its four reports were all inside Flask's own code. A
fair comparison needs Pysa models written for each framework, which is a project of its own.

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

Create the project in the UI with a repository URL, use `manage.py addproject KEY URL`, or `POST /api/projects/<key>/scan/`. An administrator can instead pick a repository folder on the server from **New project**: the page lists folders under `CODEWATCH_BROWSE_ROOT` (the home directory by default; names only, hidden folders left out), takes the title and key from the folder's name, and creates a scan token for `codewatch-scan` in that working copy, shown once on the project's page. The project list has a **Scan** button for each project the server can scan. Branches are scanned from a bare mirror in `~/.cache/codewatch/`, never touching a working copy, one scan of a project at a time and at most `CODEWATCH_MAX_SCANS` (4) across the server. Public repositories work for everyone; the server's own git credentials, server-local paths and hosts on its network only for projects an administrator owns (or added with `addproject`).

```bash
venv/bin/python manage.py scan my-app --all-branches --fail-on-gate
```

## Development

Start with [CONTRIBUTING.md](CONTRIBUTING.md). [docs/architecture.md](docs/architecture.md) explains how a scan flows,
[docs/writing-rules.md](docs/writing-rules.md) where a rule change goes and the tests it needs, and
[docs/benchmarks.md](docs/benchmarks.md) how to reproduce every number here. Work lands on `detection-gaps`, the default
branch. `main` is fast-forwarded from it weekly, after a clean nightly run.

```bash
make test    # pytest across all CPUs (pytest-xdist); accessibility tests are skipped if tools/ isn't installed
make lint
make lock    # new analyzer versions into tools/*.lock (hashed); review, re-run the benchmarks, commit
venv/bin/python benchmarks/devtools.py bench [SUITE...]   # score suites, in parallel
venv/bin/python benchmarks/devtools.py repos DIR...        # Semgrep findings on whole projects, in parallel
venv/bin/python benchmarks/devtools.py cases GHSA-...     # only the CVE pairs a change targets, nothing written
venv/bin/python benchmarks/devtools.py copy FILE.py       # the rewritten copy of a Python file that Semgrep scans
venv/bin/python benchmarks/smoke.py                       # the CVE pairs CI re-scores on every push
venv/bin/python benchmarks/rule_trust.py > docs/rule-trust.md   # per-rule evidence from the latest nightly
benchmarks/nightly.sh [BRANCH]                            # the full verification, unattended, with a dated report
```

Benchmarks and `repos` scan in a third of the CPUs' worth of processes (`CODEWATCH_BENCH_WORKERS`), each Semgrep run with its share of the CPUs: results are identical to one-at-a-time runs, and all suites take about four hours on a 20-thread machine (the CVE pairs, each cloned and scanned twice, nearly all of it). `nightly.sh` checks the branch tip out in its own worktree, runs lint, tests, every suite that isn't blind and the apps listed in `~/.config/codewatch/nightly-apps.txt`, and writes `~/.cache/codewatch/nightly/DATE/summary.txt` (what changed since the last report); a systemd user timer can run it overnight. `make tools` installs the analyzers at the versions and hashes in `tools/*.lock` and `tools/package-lock.json`.

## License

MIT, see [LICENSE](LICENSE). Analyzers and imported rule metadata keep their own licenses.
