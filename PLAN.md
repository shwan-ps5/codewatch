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

  Re-run at commit 112de4c (e7c27d4's rules plus the scan narrowing) gave exactly the same table; those result
  files are the CVE baseline. `pytest -q` there: 134 passed, 1 skipped (cppcheck not installed, a system package
  `make tools` doesn't install).
- The CVE suites are slow (Python ~4.5 h on the laptop, which overheated); run them on the desktop and commit
  the results as the CVE baseline. Fresh machine setup (needs Python 3, Node 20+, git):

  ```
  git clone https://github.com/shwan-ps5/codewatch.git && cd codewatch && git checkout detection-gaps
  python3 -m venv venv && venv/bin/pip install -e '.[dev,mcp]'
  make tools
  venv/bin/python manage.py migrate
  venv/bin/pytest -q                      # should be 135 passed
  venv/bin/python benchmarks/devtools.py bench cve-pairs-python cve-pairs-javascript
  ```

  Suites and CVE repos download themselves into `~/.cache/codewatch/` on first run.
- Re-run after items 1-3 below (commit dfb21c4 plus the Python path-prefix hotspot, since removed), on the
  desktop in about 1 h 20 min for all suites:

  | Suite | Verdict found / still flagged | Review found / still flagged |
  |---|---|---|
  | cve-pairs-python | 5/14 / 1/14 | 6/14 / 2/14 |
  | cve-pairs-javascript | 0/10 / 0/10 | 3/10 / 3/10 |

  Python: Parsl, litellm and changedetection.io are new. Parsl's "still flagged" is a correct finding the fix
  didn't touch: it parameterised the two views named in the advisory, but `queries/pandas.py` still `%`-formats
  `workflow_id` into SQL, reached from `views.py:169,175` (behind a lookup by the same id that injected text would
  fail, which a scanner can't see). litellm's review-only hit at its fix was the uncalled-entry-point hotspot on
  `limit: int = fastapi.Query(...)`; parameters typed int/float/bool/UUID/date are now skipped there. JS: the
  oils-js hit is gone (it was a false alarm) and mockoon is found by `path-prefix-check`; the review drop from 4 to
  3 is oils-js. Quick suites unchanged except OWASP Python review path traversal, below.

What to work on next, from that run (these suites are not held out; note in `suites.json` when a case drives a
rule):

1. Done (2026-10-31), checked on both repos, CVE suites not re-run yet. Grappelli's fix calls
   `url_has_allowed_host_and_scheme(url=...)` with a keyword, now a guard too. The oils-js hit was never the
   advisory's bug: it was an HTTPS-upgrade redirect to `req.headers.host` + `req.url`, now quiet, so JS verdict
   detection should drop to 0/10 and still-flagged to 0/10. What's left on oils-js is `custom-response.js:17`, a
   real trailing-slash redirect of `req.url` (`//evil.com/`) that the fix doesn't cover. Grappelli's fix commit
   still got a trust-boundary hit at `switch.py:73`, which stores a database user's id in the session: noise,
   fixed by treating ORM lookups (`Model.objects.get(...)`, `get_object_or_404`, `Model.query.first()`) as
   sanitizers for that rule.
2. Done (2026-10-31). None of the five JS CWE-22 misses is a source/sink shape a taint rule lacks: both Backstage
   cases (GHSA-7mfx, -9ghw) are flawed checks in front of Express's static/proxy middleware, gitlab-mcp (GHSA-cv3r)
   is missing authentication and its path comes from MCP tool arguments, and fastify-static (GHSA-83w8) is the
   library itself. Mockoon (GHSA-8wqc) is a prefix-only containment check (`resolved.startsWith(base)`), now the
   `path-prefix-check` hotspot for JS. It also flags `own-app-5/packages/server/src/main.ts:57` in the user's own
   repo. A Python version was tried and removed: the OWASP Benchmark for Python labels exactly this check
   (`str((base / name).resolve()).startswith(str(base))`) safe in 29 path traversal cases, review false alarms
   went from 2% to 30%, and no Python case needed it.
3. Done (2026-10-31). Python taint sources were only `request`: Flask route parameters and FastAPI parameters
   are now sources (text-typed only; Flask converters other than string/path are written on the scanned copy as
   annotations by `core/analyzers/route_converters.py`), with pandas `read_sql*`, Prisma `query_raw`/`execute_raw`
   and `exec_driver_sql` as SQL sinks. Checked file by file: Parsl (GHSA-f2mf), litellm (GHSA-h6m6) and
   changedetection.io (GHSA-8whx, XSS) flagged before the fix (confirmed by the re-run above); ordinary apps, the
   user's repos and the Python quick suites unchanged. FastAPI Pydantic body models are not sources yet (a model parameter such as
   `item_in: ItemCreate` looks like `session: SessionDep`; would need the class to be a BaseModel).
   Not chased, no rule can see them: dtale (GHSA-gjxm, a settings flag), Whoogle (GHSA-2689, pickle of a cookie,
   filed as CWE-78), Fugue (GHSA-xv5p, the fix only logs a warning), and the open-redirect misses that are
   bypassable validators (pyload `is_safe_url`, Airflow `get_safe_url`), a stored URL (Superset) or a Referer
   redirect, which codewatch deliberately treats as safe (cg). open-webui GHSA-frvj is an encoding bypass of a
   guard; GHSA-8gh5 is an uploaded HTML file served inline.
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
2. **Source-returning helpers**: done (2026-10-31). Pass 3 in `core/analyzers/summaries.py` runs each taint rule
   with `return` as the sink (per rule, so a helper returning `int(...)` isn't a SQL returner), up to MAX_DEPTH
   deep, and the final rules get a `.from` variant whose sources are calls to those functions, checked for
   visibility like `.via`. Not returners: values looked up with the request data (ORM queries, `find*`/`load*`/
   `decode*`/`get_current_user*`), route handlers (a GET view returning the POST view's response gave 5 OWASP
   XSS verdict false alarms), and handler-named methods (`get`, `post`, `dispatch`...: a Django class-based
   view's `get` made pygoat's `requests.get(settings URL)` an SSRF). Effect: ordinary apps still 0; on the user's
   repos one new finding, `own-app-5/packages/client/src/game.ts:338` (XSS), a real flow from `?server=` through
   `defaultServer()`/`loadOnline()` into innerHTML, but inside a double-quoted attribute with `"` stripped, so not
   exploitable; a rule can't see attribute context, left as is. On the held-out vulnerable-snippets-js, "any
   security" went from 50% to 55% only because `PostMessage Security/challenge1.js` gets an open-redirect for
   `get_domain()` (the page's own origin) in a query string: noise on a sample vulnerable for another reason,
   not a detection, and not tuned on. Cost: the first version made own-app-5 14 s -> 153 s and dvpwa 42 s -> 117 s.
   The JS sink `class $C { ... $FUNC(...) { ... } ... }` was 42 of 45 s per pass on own-app-5 (now
   `$FUNC(...) { ... }`, same results, 4 s), and vendored unminified libraries (dvpwa's 366 KB materialize.js)
   took 23 s per pass (pass 3 now skips JS files over 200 KB). Now own-app-5 27 s, dvpwa 47 s.
3. **Framework sources**: FastAPI text parameters (including `Query()`/`Path()`/`Header()` defaults) done with
   item 3 above. Pydantic/SQLModel body models done (2026-10-31, `core/analyzers/body_models.py`): the project's
   own model classes are read with ast, and a route parameter typed with one has its text fields as sources
   (`item.title`, inherited fields too; `item.limit: int` isn't, nor is a field name that is non-text in any
   model). NestJS done (2026-10-31): `@Body()`/`@Query()`/`@Param()`/
   `@Headers()` parameters are sources (`src-nest-param` in `javascript-taint.yml`), except with a Parse*Pipe or
   a number/boolean/Date/bigint type; `@Req()` isn't, its `req.body` etc. are already covered by name. TypeORM
   `dataSource`/`queryRunner`/`manager`/`*Repository` joined the SQL receivers. nestjs-boilerplate and
   nestjs-realworld stay at 0. No Nest case in any suite, so this is untested against real advisories. Next.js
   API route `req` and Fastify `request.body/query/params` were already sources by name.
4. **Object fields**: done (2026-10-31). The returner pass's first scan also runs each rule with
   `self.x = ...`/`this.x = ...` stores as the sink; the final rules get a `.field` variant whose sources are reads
   of those fields, kept to the file that stores them (by name, not class: the JS class pattern is what made the
   returner pass slow). Found while checking: Django class-based views' `self.request.GET[...]` and
   `self.kwargs[...]` weren't sources at all; now they are (`self.kwargs`/`self.args` only in classes based on
   a `*View`/`*ViewSet`). Two CVE repos store request data in fields (Whoogle `search.py:61`, Grappelli
   `related.py:131`); neither advisory is about those flows.
5. **JS dependency vulnerabilities**: done for npm, yarn and pnpm lockfiles by the `osv` analyzer
   (`core/analyzers/dependencies.py`), which parses them itself and asks OSV's batch API, so no new binary. Go, Rust
   and Java lockfiles would need the osv-scanner binary in `tools/`; downloading it needs the user's go-ahead.
6. Re-run everything, then the blind set; update the README table. Non-blind re-run at fe33054 (2026-10-31):
   quick suites unchanged (OWASP verdict 100%/0%, review 100%/35%; Juice Shop 15/17 of 35); cve-pairs-python
   verdict 6/14 found, 3/14 still flagged (was 5/14, 1/14), review 7/14, 3/14; cve-pairs-javascript unchanged
   (0/10, review 3/10). Two new "still flagged" come from this round's sources, both false alarms:
   - GHSA-g3cm (pyload): `get_redirect_url()` returns `urljoin(flask.request.url_root, url_for(...))`, and the
     returner pass now follows it into `flask.redirect`. `url_root`/`host_url` are the app's own host, like the
     Host header the JS rule already accepts. The vulnerable-commit hits at the same lines are the same noise,
     so that "detection" isn't one either.
   - GHSA-6rmf (django-termsandconditions): `self.request.POST` (new source) goes into
     `self.get_return_to(...)`, which returns it only inside `if self.is_safe_url(x):`, else "/". Semgrep taints
     any call result with a tainted argument, and there's no positive-guard sanitizer.
   Next (after the blind run): a pass-through summary (params as sources, `return` as sink; calls to project
   functions that don't pass a parameter through become sanitizers), a positive-guard sanitizer
   (`if is_safe_url(x): ...`), and `request.url_root`/`host_url` as open-redirect sanitizers. The same
   pass-through gap is behind own-app-10 app.py:793.

   Blind repos at fe33054 (first and only scan, 2026-10-31; not to be used to adjust rules), verdict findings:
   - Django-Styleguide-Example: 3, all real at code level: `CORS_ALLOW_ALL_ORIGINS` with credentials
     (cors.py:4) and two `jwt.decode(..., verify_signature=False)` (defensible there: the token comes straight
     from Google's token endpoint, but it is what the rule says).
   - FastAPI-boilerplate: 2 false alarms: a constant scrypt salt used on purpose to fingerprint configured
     targets (readiness.py:149), and Jinja autoescape off in a CLI that generates code, not HTML (render.py:23).
   - hackathon-starter: 10, all false alarms: four `res.redirect(`/auth/${provider}`)` (fixed relative prefix),
     three XSS through `sendSSE` (JSON on an event stream), two SSRF to fixed hosts with
     `encodeURIComponent`ed queries (Giphy, Wikipedia), and a redirect to the Referer, which the Python rule
     treats as safe by design (JS and Python disagree).
   - nestjs-prisma-starter: 0.
   So 2 of 4 ordinary apps have verdict false alarms (12 in all, 10 in one Express app); the non-blind ordinary
   apps' 0 was partly fitted. The shapes are general (fixed-prefix relative redirects, fixed-host URLs with an
   encoded query, event-stream writes, Referer in JS, CLI Jinja environments), but per the ground rules they
   can't be fixed on this evidence: they need a non-blind case first, and the blind set needs replacing before
   it can measure again.

   Blind CVE pairs at fe33054 (first and only run): cve-pairs-blind-python verdict 2/5 found, 1/5 still flagged;
   cve-pairs-blind-javascript verdict 1/4, 1/4 (review 1/4, 2/4). Read case by case: Python's two are real
   (archivy GHSA-28mg open redirect; GHSA-mcmc XXE), and archivy's fix-commit hit is the positive-guard gap
   above (`if next and is_safe_redirect_url(next): return redirect(next)`), already known from GHSA-6rmf. The JS
   one (medplum GHSA-m44r) isn't a detection: the same lines are flagged either side of the fix (a redirect to a
   URI looked up from the client's registered list, and one after `isValidReturnToUrl(...)`), so honestly 0/4.
   The blind set is now spent; a new one is needed before the next blind measurement.

Also 2026-10-31, the rest of the user's ~/Dev projects (the set differs per machine; list ~/Dev first). New
findings were mostly false alarms that route parameters as sources exposed, now fixed (each in
`test_false_alarms_from_the_maintainers_projects`): a return inside a function nested in a view isn't the
response; `lookup-result` sanitizer for the variable assigned from a bare call to a `get_X`/`fetch_X`/`load_X`/
`find_X` helper, also inside `try:` (not `get_json`/`get_param`-style names; the returner pass's variants drop it
so a real `get_cmd()` returner still counts). It cleans the variable, not the call: a first version cleaned the
call and hid own-app-1's path traversal inside `load_css(...)`, a via-sink among its arguments; `Response(..., mimetype="video/...")` and other media/JSON types aren't XSS, nor is
`return Response(...)` built inline; command injection: `secure_filename()` output and a literal
`https://host/...` argv element are clean; weak-random-token's `$SESSION[...] =` sink needs a session-named
target (any dict matched; pygoat's OTP stored in a plain dict is still flagged by bandit's B311 as a
secret-purpose random); and `cache_key`/`sort_key`-style names no longer make a function security-related for
weak-hash. Real findings (measurement only; fixing those apps is not part of this plan): own-app-10 `/proxy/media?url=` (app.py:815, open proxy: SSRF), own-app-1
app.py:32/39 (path traversal), own-app-11 accounts/views.py:38 (open redirect). Known false alarms left:
own-app-10 app.py:793 (gif_id reaches a helper's Response through Semgrep's call-result propagation) and
own-app-5 game.ts:338 (attribute value with `"` stripped).

Also 2026-10-31: `**/site-packages/**` joined the default exclusions (a committed virtualenv made the user's
own-app-12 9,910 files and timed out the final scan; existing projects keep their saved list).
`devtools.py repos` also scans directories that aren't git working copies, and prints as it goes. A tool
timeout used to kill only semgrep's Python wrapper: semgrep-core kept running (1.6 GB, 30 min) and the next
scans failed with `io_uring_queue_init: Cannot allocate memory`; `Analyzer.exec` now kills the process group.

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

The user's own repos in `~/dev` (own-app-1, own-app-2, own-app-3, own-app-4, own-app-5, own-app-6,
own-app-7, own-app-8, own-app-9) are useful false-alarm checks; known real findings: own-app-1
`load_css` path traversal, own-app-3 `random.choices` session keys, own-app-8 and own-app-9's FTP and unfiltered tar.
