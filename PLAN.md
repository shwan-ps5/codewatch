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
- Every rule change gets a test in `tests/test_detection.py`; run the full suite (`venv/bin/pytest -q -n auto`)
  and `venv/bin/ruff check .` before committing. Commit and push only when asked, as
  `Shwan <344055753+shwan-ps5@users.noreply.github.com>` (see `CLAUDE.md`).

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

## Where things stand (2026-11-02, commit ec6a841)

Detection, measured at this commit (verdict mode first; review mode adds hotspots):

| Suite | Verdict | Review |
|---|---|---|
| OWASP Benchmark for Python (1,230 cases) | finds 100%, false alarms 0% | finds 100%, false alarms 35% |
| SecurityEval (121 samples) | 51 flagged | 77 flagged |
| SecurityEval Copilot / InCoder answers (held out) | 34% / 31%, false alarms 0% / 0% | 51% / 47%, false alarms 6% / 0% |
| Juice Shop (35 challenges) | 15 | 17 |
| Vulnerable-Code-Snippets JS (22, held out) | 11 | 13 |
| vulnerable-node seeds (12 + 2 clean) | 92%, false alarms 0% | 100%, false alarms 50% |
| CVE fix pairs, Python (33; 14 until step 22) | 18 found, 5 still flagged after the fix | 20 found, 7 still flagged |
| CVE fix pairs, Python front end (6, step 22) | 0 found | 4 found, 2 still flagged |
| CVE fix pairs, JS/TS (10) | 2 found, 0 still flagged | 4 found, 3 still flagged |

False alarms on ordinary apps (verdict mode):
- The 30 dev apps (six deliberately vulnerable apps, nine ordinary ones, the user's 15 own projects): unchanged
  from run to run. The vulnerable apps' findings are real; the user's projects have the real findings and the two
  known false alarms listed in the 2026-10-31 notes after step 18.
- Learning sets 1-3 (14 apps): 18 findings left, each classified in steps 13 and 18 (real: recipes api.py:2960,
  outline's four TLS settings; little impact: CTFd's three session writes; the rest need models codewatch
  doesn't have, such as an OAuth manager built from session state).
- Learning set 4 (wiki.js, actual, habitica): 27 findings, all false alarms, grouped by shape in step 19.
- Learning set 5 (netbox, label-studio, lemur): first scanned by the first nightly run (2026-11-03).
- Blind sets: 1 had false alarms in 2 of 4 apps (12), 2 in 2 of 4 (34), 3 in 4 of 4 (24, 13 in one Express app).
  Python is close (3 false alarms in two apps in set 3); JavaScript isn't. Set 4 is pinned and unscanned.

The server: a full security review is done (step 20), each fix tested in `tests/test_security.py`. Still open:
analyzers read repository content, so untrusted code should be scanned in a container (not built yet).

Speed on the 20-thread desktop (step 21): tests 1.5 minutes, quick suites 4, the 30 apps 4, the three
non-blind CVE-pair suites (49 pairs) about 58, the 17 learning-set apps 11; the largest app (immich, 3,488 files)
about 3 minutes alone. Results are identical whether scans run one at a time or in parallel. So, since
2026-11-02 (the user's call), a change is checked in isolation during the day (its tests, a probe on the case's
files, `devtools.py cases ID...` for the CVE pairs it targets) and the full verification runs nightly:
`benchmarks/nightly.sh` from the systemd user timer `codewatch-nightly.timer` at 01:30, over the committed tip of
`detection-gaps`, with the apps in `~/.config/codewatch/nightly-apps.txt` (outside the repository: it names the
user's own projects) and a report in `~/.cache/codewatch/nightly/DATE/summary.txt`, read the next morning.

Focus (2026-11-02, the user's call): Python web apps (Django, Flask, FastAPI) and the JavaScript those projects
ship (templates, static scripts, React/Vue/Angular front ends), to a very good standard first. Node-only back ends
and other languages come later, possibly from cloud sessions, one language or framework each, adding rules in
their own catalog files with tests and ground-truth results, merged only after a full verification here.

Next, in order:
1. Read the first nightly report (2026-11-03): the round-one changes of step 22 on every suite and app, and
   learning set 5 for the first time.
2. Learning set 5 (netbox, label-studio, lemur: Python apps with JS front ends), case by case.
3. The front end (step 22): score a template-only fix against the views that render the template; Whoogle's
   `'http' in q` passing as a guard (the fix exposed paperless-ngx false alarms, so understand that flow first);
   verdict detection for front-end JS (request data into innerHTML or jQuery HTML).
4. The Python miss still in reach: pyLoad's SSRF through its own pycurl wrapper (`get_url`); the rest (stored
   data, settings flags, template-built SQL, `g`-stored state) are recorded as out of reach.
5. End of the round: blind set 4 (redash, InvenTree, pretalx, fief) and the two blind CVE suites
   (`cve-pairs-blind-python-2`, `cve-pairs-blind-python-frontend`), each scanned once, measurement only.
6. A container for server-side scans of untrusted repositories; Semgrep timeouts recorded per run.
7. Other languages and frameworks (Node/Express first), from cloud sessions as pull requests, one topic each,
   following CLAUDE.md's "Cloud sessions" section; merged only after local verification and a nightly run.

Not filled, by choice: CSRF beyond the existing hotspots; authorization (CWE-862/863/639), which needs app
knowledge.

### Record of 2026-10-31 (commit 799955c)

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
   `path-prefix-check` hotspot for JS. It also flags one real prefix-only check in the user's own projects.
   A Python version was tried and removed: the OWASP Benchmark for Python labels exactly this check
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
   own projects one new XSS finding, a real flow from a query parameter through two helpers into innerHTML, but
   inside a double-quoted attribute with `"` stripped, so not exploitable; a rule can't see attribute context,
   left as is. On the held-out vulnerable-snippets-js, "any
   security" went from 50% to 55% only because `PostMessage Security/challenge1.js` gets an open-redirect for
   `get_domain()` (the page's own origin) in a query string: noise on a sample vulnerable for another reason,
   not a detection, and not tuned on. Cost: the first version made one of the user's TypeScript projects 14 s -> 153 s and dvpwa 42 s -> 117 s.
   The JS sink `class $C { ... $FUNC(...) { ... } ... }` was 42 of 45 s per pass on that project (now
   `$FUNC(...) { ... }`, same results, 4 s), and vendored unminified libraries (dvpwa's 366 KB materialize.js)
   took 23 s per pass (pass 3 now skips JS files over 200 KB). Now 27 s and 47 s.
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
   pass-through gap is behind a known false alarm in one of the user's own projects.

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

7. **After step 6** (2026-10-31, from non-blind cases only): a positive-guard sanitizer (`checked-inside`: a
   value used inside `if is_safe_url(x):` or `if a and is_valid(x):`, not `if not ...`), `request.url_root`/
   `host_url` as open-redirect sanitizers, and a pass-through summary for Python: the returner pass's first scan
   also finds which project functions can return a parameter, and the variable assigned from a call to one that
   can't (and isn't summarised or a returner) is clean. Driven by GHSA-6rmf and GHSA-g3cm at their fixes.
   Python CVE pairs after it: verdict 5/14 found, 1 still flagged (was 6/14 and 3); review 6/14, 1 (was 7 and 3).
   GHSA-6rmf is now found at the vulnerable commit and quiet at its fix. GHSA-g3cm went quiet on both sides:
   its vulnerable code redirects only to values that passed the project's own `is_safe_url()`, and the advisory
   is that check being incomplete, so trusting a validator by name loses it (the old "find" was the same two
   lines on both sides of the fix, so it never told the commits apart). Considered and dropped: making a value
   cleared only by a project-defined check (not a library one like `url_has_allowed_host_and_scheme`) a review
   hotspot. GHSA-6rmf's fix also clears its redirect with a project-defined `is_safe_url`, so the hotspot would
   be a review false alarm there for every one it found. The names of clean functions are split into regexes of 400: one regex listing all of
   them (`cg`, GHSA-w228, about 70K characters) made Semgrep exit with an error.

8. **Speed** (next, asked for 2026-11-01): the Python CVE suite took 1h45m and one large project's scan took
   minutes per pass. A profile of one `cg` pass showed 12.7 s of 13.3 s loading the generated rules and 0.55 s
   scanning. Budget: a typical project of around 100k lines scans in under 5 minutes; a run that misses it
   fails like a new false alarm. In order: time each pass on `cg`; shrink generated rules (list the few
   functions that do return a parameter instead of the thousands that don't; fewer variant copies); start
   Semgrep fewer times (merge passes; skip summaries for files identical between the two commits of a pair).
   Every change is checked against the same detection numbers.
   Profile of `cg` (1,023 Python files, about 6 cores): summaries 9 s, 123 s, 161 s; returners 65 s; final
   198 s; 567 s in all. Depth 1, with no generated names, takes 9 s. Done: one via-sink per call shape whose name
   regex lists every function called that way (it was one sink per function), and every generated name list
   split into regexes of 400. `cg` now takes 304 s (summaries 49 s and 61 s, final 108 s). It also finds more:
   the old rules hit Semgrep's per-file timeout 97 times in the final scan and 6-7 times per summary pass, each
   one silently skipping that rule for that file; now 12 and 1-2. Quick suites and the 30 apps unchanged; those
   apps scan in 8-53 s each, so the time is a large-project problem.
   Also done: deeper summary and returner passes rescan only the files that name a function the previous pass
   added (a file that names none gives what it gave before: 755 then 437 of `cg`'s 1,075 files), and via-sinks for
   a parameter passed by keyword are dropped when nothing in the project passes that keyword (`cg`'s
   path-traversal via-variant had 309 keyword names, 107 used). `cg`: 259 s (summaries 9, 40, 39 s; returners
   65 s; final 96 s). Quick suites 619 s to 508 s, results unchanged; 30 apps unchanged. Tried and reverted: one
   keyword sink per callee kind with a `metavariable-comparison` naming each (keyword, function) pair; it is
   evaluated on every keyword call and made the final scan slower (129 s).
   Also done: the returner pass spent 60 of its 65 s on the pass-through rules' 32,868 results (1,982 functions
   times 16 rules; Semgrep's matching was 10 s, the rest writing results out). Pass rules now ask only about
   functions that take a parameter and whose result some code assigns (`x = f(...)`, the only form the
   pass-through sanitizer cleans), and that same set bounds the sanitizer, so a function outside it is never
   clean. `cg`: 160 s (summaries 10, 41, 41 s; returners 32 s; final 29 s, which also lost its timeouts because
   the sanitizers list fewer names). Semgrep timeouts are now reported in the tool's status detail (and by
   `devtools.py repos`) rather than dropped. Quick suites and 30 apps unchanged.
   Also done: Python keyword via-sinks are one pattern per kind of callee whose regexes name every summarised
   function and keyword; the message carries the (function, keyword) pair and a pair no summary names is dropped
   after the scan (`test_keyword_arguments_to_summarised_functions`). This replaced the unused-keyword filter.
   Only 160 s to 153 s: what remains in the summary passes is taint itself (every parameter is a source there,
   so log-injection's and path-traversal's many via-sinks are checked against every call), not pattern count.
   CVE suites re-run after all of this (2026-11-01): Python 90 min (was 1 h 45 min), JavaScript 22 min; every
   number unchanged (Python verdict 5/14 found, 1 still flagged; review 6/14, 1; JavaScript verdict 0/10; review
   3/10, 3). Large-project scans are 3-4 times faster, yet the suite is only 15% faster, so most of the suite's
   time is elsewhere. Timing each case and tool (90 min in all): litellm alone took 46 min, 23 per side, of which
   15 in Semgrep and 7 in codewatch's ReDoS check, nearly all on twelve minified Next.js chunks committed under
   `litellm/proxy/_experimental/out/_next/` (one 100 KB line each, hundreds of regexes, each check allowed 3 s).
   Done: `collect` skips JavaScript files of 20 KB or more whose lines average over 500 characters (bundler output,
   whatever its name or folder) and logs how many. Across the 30 apps, ~/Dev and every benchmark checkout it
   matches only bundles (Next.js, Astro, TinyMCE, archivy's static editor). litellm: 2,736 s to 476 s, its
   codewatch check 435 s to 0.6 s per side. The whole Python CVE suite: 90 min to 48 min, every number unchanged;
   quick suites and the 30 apps unchanged (`test_minified_bundles_are_recognised_by_content`). Left: Semgrep is now most of every case (open-webui 222 s and
   litellm 229 s per side; dtale 135 s); Grappelli's check still takes 58 s per side on vendored, unminified
   jQuery, jQuery UI, TinyMCE and select2 (done 2026-11-01, see below). Every case side now scans within the 5-minute budget (largest open-webui 4.3 min,
   litellm 4.0). Measured on open-webui's first returner scan (178 files, 85 s): the pass-through rules are 50 s of
   Semgrep's core time (9,066 results), the returns rules 4 s, the fields rules none beyond the scan's own cost. The
   16 Python pass rules have 11 distinct sanitizer sets (six rules share one). Done: one pass rule per group of
   rules alike apart from sources and sinks, its message naming the rules it answers for; open-webui's first
   returner scan 78 s to 65 s, its side 252 s to 237 s, quick suites and 30 apps unchanged. Done: the deeper returner and summary passes
   take only what the previous depth added as their extra sources or sinks (semi-naive evaluation), so they no
   longer re-report what it found; open-webui's side 237 s to 206 s. Quick suites and 30 apps unchanged; CVE pairs
   Python 48 to 40 min, JavaScript 22 to 11 min, findings unchanged.
   Done (2026-11-01, at the user's direction: analyse the app's own code file by file, dependencies only through
   the audit): vendored libraries are skipped by content. A JS/CSS file opening with a library banner (name and
   version, `/*! jQuery v1.11.3`; a licence header alone matches Airflow's own files), and JS/CSS under a folder
   inside static/, public/ or assets/ that holds a licence file (TinyMCE has no banner; monorepo packages have
   licence files, but none inside an asset folder). Across the 30 apps, ~/Dev and the benchmark checkouts both
   matched only third-party libraries. Grappelli's case 305 s to 41 s (per side: codewatch check 58 s to 0.6 s,
   Semgrep 85 s to 15 s); CVE pairs
   Python 40 to 35 min; quick suites, 30 apps and both CVE suites unchanged.

9. **JavaScript CVE misses** (2026-11-01, non-blind cases only; verdict 0/10 before this). Added:
   - GHSA-p849 (NocoBase, SQL injection): `Sequelize.literal()`/`sequelize.literal()` as a SQL sink, NocoBase's
     `ctx.action.params` (also `ctx.action?.params`, which a plain pattern doesn't match) as a request source, and
     names destructured with a default (`const { filter = {} } = req.body`), where Semgrep's taint drops the
     value. The last is general: an Express handler with a defaulted query field was invisible too.
     `test_sequelize_literal_and_resource_action_params`.
   - GHSA-79wm (claude-code-templates, command injection): with `shell: true`, `spawn`/`spawnSync` join the
     argument array into the shell command, so request data anywhere in it is a sink, not only in the command.
     `test_spawn_with_a_shell_joins_its_argument_array`.
   Not rules: GHSA-w6x9 (MagicMirror, SSRF) is paired with the wrong fix commit (58c2a5e fixes GHSA-w26r, an IP
   allowlist for Socket.IO, not the calendar fetch), so it can't be found as listed; GHSA-vmg4 (Apostrophe,
   prototype pollution) is a deny-list that missed inherited properties such as `toString.call`, a judgement
   about which keys are safe rather than a source reaching a sink. The five CWE-22 misses are in step 2 above.
   JavaScript CVE pairs after it: verdict 2/10 found, 0 still flagged (was 0/10); review 4/10, 3 (was 3/10, 3).
   Both found cases are quiet at their fixes; GHSA-79wm is also found where the request's prompt is passed to
   the functions that spawn it. Quick suites and the 30 apps unchanged.

10. **Ordinary-app learning set** (2026-11-01; five new apps, cloned in `~/.cache/codewatch/fresh/`, see Repos).
   Verdict findings before: flaskbb 22, outline 23, node-express-mongoose-demo 3, express-rest-boilerplate 1,
   proshop-v2 1. Fixes, each in a test:
   - Python (flaskbb, `test_sqlalchemy_statements_and_safe_redirect_helpers`): a SQLAlchemy
     `select()/insert()/update()/delete()` chain binds its values (`sa.text("..." + x)` is still a sink); a
     project helper named `*safe_url`/`safe_redirect`/`*_safe_next` (`get_first_safe_redirect_url`) cleans an
     open redirect.
   - JS open redirect (outline, `test_js_redirects_within_the_site_are_not_open`): a template or concatenation
     with a fixed relative prefix (`/auth/${x}`, not `//`) or with the value after `?`/`#` stays on the site; a
     `getValidated...` helper is a sanitizer. The request's own path (`req.url`, `ctx.path`) moved to a separate
     review-only rule, `open-redirect-path`, as in Python (`//evil.com` is a valid path). This also cleared seven
     false alarms in dvna and vulnerable-node (fixed-path redirects such as `"/products/" + id`).
   - JS summaries (outline, `test_returner_calls_and_handlers_in_javascript`): from-source rules use `exact: true`
     (a `perform(context)` call was both the source and, through another class's `perform`, the sink of itself),
     and Koa/Express handlers taking `next` aren't returners of request data (`renderShare`).
   - JS SSRF and stack traces (proshop-v2, express-rest-boilerplate,
     `test_js_ssrf_to_a_fixed_host_and_stack_traces_dropped_outside_development`): a URL whose host is fixed
     (`https://host/...`, `${PAYPAL_API_URL}/...`, `${config.x}/...`) is not SSRF; a `stack` field deleted from
     the response object outside development is not exposed.
   - Weak hash (`test_the_crypto_module_name_is_not_a_security_purpose`): `crypto` (Node's module name, in every
     `crypto.createHash('md5')`) no longer makes a call security-related.
   - Measurement: `devtools.py repos` now skips bundles and vendored libraries as real scans do
     (`collect.without_third_party`); flaskbb 78 s to 33 s.
   After: flaskbb 0, express-rest-boilerplate 0, proshop-v2 0, node-express-mongoose-demo 2 (real: `err.stack` in
   the 500 page), outline 8: six real (four `rejectUnauthorized: false`, two md5 of the JWT secret) and two known
   false alarms: `plugins/passkeys/server/auth/passkeys.ts:266` (`getPasskeyLoginRedirect` returns a fixed
   string; JS has no pass-through analysis) and `server/routes/app.ts:320` (`share.canonicalUrl` from a lookup
   by request id; JS has no lookup-result sanitizer). Those two are the next JS candidates.
   Then a JS `lookup-result` sanitizer (`san-lookup-result`, every JS taint rule; outline's
   `const result = await loadPublicShare({id: ctx.params...})`): the variable assigned from a bare
   `getX`/`fetchX`/`loadX`/`findX`/`lookupX` call, not the call, and not request- or redirect-shaped names
   (`getQuery`, `getRedirectUrl`, `findNext`); the summary passes drop it as they do Python's, so a project helper
   found returning request data still counts. `test_what_a_javascript_helper_looks_up_is_stored_data`. outline
   7 (6 real). Left: passkeys.ts:266, a call inline in the sink to a helper that returns a fixed string; JS
   pass-through would not reach it either (Python's cleans only assigned results, because cleaning the call hid
   a real path traversal in one of the user's own projects), so one case doesn't justify it.
   Quick suites unchanged; CVE pairs unchanged (Python verdict 5/14, 1; review 6/14, 1; JavaScript verdict 2/10,
   0; review 4/10, 3); the 30 apps lose only the seven dvna/vulnerable-node redirects above.

11. **Second ordinary-app learning set** (2026-11-01; Django, FastAPI, NestJS and Next.js to match blind set 2's
   frameworks without using it; cloned in `~/.cache/codewatch/fresh/`, see Repos). Verdict findings before:
   taiga-back 52, immich 11, wger 9, dispatch 8, linkwarden 6 (86). Fixes, each in a test:
   - Python summaries (taiga, `test_view_actions_builtins_and_orm_chains_are_not_returner_calls`): DRF's
     `ViewSet.list`/`create` were returners, so every bare `list(...)` and, through `$MODULE.$RET_FUNC(...)`,
     every `Project.objects.create(...)` became request data (52 importer and SQL findings). A returner named like
     a Python builtin no longer counts; the module form takes one name, not a chain; a `return` of a response
     (`Response(...)`, `response.Ok(...)`, `HttpResponse*`, `render`, `jsonify`, `redirect`) isn't data for a
     caller. Taiga's scan went from 151 s to 109 s with fewer returners.
   - Python sources (taiga, wger, `test_signed_in_user_model_metadata_and_compiled_django_sql`): `request.user`
     (the signed-in account) and `Model._meta` are the server's data (`known-safe`); Django's
     `queryset.query.where.as_sql(...)` is SQL with placeholders (`str(queryset.query)` stays tainted); a quoted
     `_meta.db_table` isn't a `sql-value-formatting` value.
   - Python redirects (wger, `test_django_redirect_replaced_after_a_failed_check_and_reverse`):
     `checked-or-replaced`, `if not url_has_allowed_host_and_scheme(x, ...): x = reverse(...)`; Django's
     `reverse()` and `get_absolute_url()` join `url_for()` in `known-safe`.
   - SQLAlchemy (dispatch): a session's ORM `query(...)` chain binds values like `select()`.
   - `sql-value-formatting` (dispatch, `test_sql_value_formatting_skips_migrations_and_constant_identifiers`):
     not in Alembic's `upgrade`/`downgrade`/`run_migrations_*` or Django `migrations/` folders, and not an
     upper-case constant interpolated (`"{CORE_SCHEMA_NAME}"`, an identifier).
   - JS (linkwarden, immich): `Math.random()` for a username or other display value isn't a secret even inside an
     auth function (`test_a_generated_username_is_not_a_secret`); the Host and X-Forwarded-* headers aren't XSS
     sources (a victim's browser sends the real host) and `http.request({...})` is SSRF only through
     host/hostname/url, not path or headers (`test_host_headers_and_request_option_paths`); the request getter
     source is exact and the `request` library sink only matches its verbs, since Semgrep resolves a function
     imported from a project's `utils/request` module as `request.$NAME`
     (`test_a_request_getter_argument_is_not_request_data`).
   - JS weak hash (immich, `test_a_javascript_hash_is_judged_by_its_own_function`): the security-purpose context is
     the enclosing function by indentation (through if/for blocks), not a ±10-line window that reached a
     neighbouring signature check.
   - Test files: `e2e/`, `specs/`, `cypress/` folders and `.e2e-spec.ts`/`-spec.js` names are test code (hotspots).
   - Tools: `devtools.py repos --messages` prints each finding's message tail (via/from/field helper names).
   After: wger 0, taiga-back 0, linkwarden 0, immich 0 (its e2e findings are now hotspots), dispatch 1;
   taiga's scan 151 s → 111 s. Quick suites and CVE pairs unchanged (Python verdict 5/14, 1; JavaScript 2/10, 0);
   the 30 apps lose only pygoat `challenge/views.py:383` path-traversal (an image name cut to `[A-Za-z0-9_-]` and a
   build path from the lab's own config, not a real path); learning set 1 unchanged. Known false alarm left: dispatch
   `plugins/dispatch_core/plugin.py:225` (JWT `kid` in the path of `https://public-keys.auth.elb.{region}.amazonaws.com/{kid}`; a regex can't tell which interpolation is
   tainted, and a tainted region would be real).

12. **Second blind run** (2026-11-01, at 81ce0e3; first and only scan of blind set 2, not to be used to adjust
   rules). Verdict findings:
   - express-typescript-boilerplate: 0.
   - ghostfolio: 1, real at code level: `request.originalUrl` interpolated unescaped into
     `<meta content="${rootUrl}${path}">` (html-template.middleware.ts:185; browsers percent-encode `"` in a path,
     so hard to exploit, but nothing escapes it).
   - mealie: 7. Real at code level: the session cookie is `httponly=False` (auth.py:163; commented as needed by
     the SPA). False alarms: 4 path traversal via `_save_recipe_asset()` (the name goes through `slugify()` and
     the extension through an allowlist; two lines, each reported twice), a `window.open` of a group-configured
     action URL (stored settings, not a redirect), and `sql-value-formatting` of a value the database itself
     returned (`PRAGMA`/`session_replication_role` state).
   - healthchecks: 28, all false alarms: 10 open redirects (7 behind the project's own `_allow_redirect()`
     check, which rejects any netloc and resolves the path against a list of routes, 3 `url = reverse(...);
     url += query`), 7 trust-boundary session writes (OAuth state, a project code, a form's cleaned values),
     6 weak-hash (SHA-1 of a code, or of a value plus `SECRET_KEY`, used as a key or unsubscribe token, not a
     password), an insecure cookie (`secure=bool(settings.X)`, `httponly=True`, value "1"), and XSS
     (`HttpResponse(csrf.get_token(request))`).
   So 2 of 4 apps have verdict false alarms (34 in all, 28 in one Django app), the same rate as blind set 1
   (2 of 4, 12). The two learning sets fixed the frameworks' common shapes, but each new app brings its own
   helpers. Lessons (to act on only with non-blind cases): a positive guard is often a project function, so a
   guard-shaped call (`if x and f(x): redirect(x)`) where `f` returns a bool might be better as a hotspot than
   a verdict; trust-boundary on ordinary apps is almost always noise and might be review-only; weak-hash needs
   a password-shaped context, not just a security-sounding function. The blind set is now spent.

13. **Third ordinary-app learning set** (2026-11-01, after blind set 2; two Django apps since Django was the
   weak framework there, plus Flask and Next.js; cloned in `~/.cache/codewatch/fresh/`, see Repos; blind set 3
   pinned before any of this). Verdict findings before: CTFd 23, paperless-ngx 13, recipes 12, umami 0 (48).
   Fixes, each in a test:
   - Stored rows (`test_orm_rows_and_self_lookups_are_stored_data`): lookup-result now covers an ORM query run to
     its row (`Users.query.filter_by(...).first()`, `manager.only(...).filter(id=v).first()`, also in the
     returner pass), `x, created = Model.objects.get_or_create(...)`, and `self._get_X()` methods (paperless's
     version resolver made every document path request data: 8 path traversals). Not `self.get_serializer`,
     `get_form`, `get_success_url`/`get_redirect_*`/`get_next_*`, which hand back the request's own data.
   - Python (`test_site_urls_session_ids_equal_values_and_plain_text`): a `reverse()`/`url_for()` URL (or
     `build_absolute_uri(request, reverse(...))`) followed by text that doesn't start with "/" stays on the
     site (recipes; a bare `reverse("index") + x` is still open, "/" + "/evil.example"); `request.script_root`
     is the server's mount point (CTFd); trust-boundary: a record's `.id`/`.pk` and a hash or signature aren't
     request data (CTFd's `login_user(user)` after sign-up); validated-guard: `if x != expected: abort(...)`/
     `return`/`raise` (CTFd share.py), plain comparisons only; XSS: `HttpResponse`/`Response` typed as plain
     text, CSV or a download (`application/force-download`), or re-typed on a later line (`r.mimetype =
     "text/plain"`), isn't HTML; insecure-cookie: only a missing or literal-False `secure=`, not a value from
     config (CTFd's session interface); SQL: a model's `__table__.select()/insert()/...` binds values (CTFd).
   - JS (`test_same_page_jumps_and_the_configured_root_are_not_open_redirects`): `location.href.split("#")[0]`
     plus anything is this page (its path is included, so nothing appended moves the host; `location.origin` is
     not cleaned, "@evil.example" would); the configured base URL (`*.urlRoot`, `baseUrl`, `rootUrl`, ...)
     followed by a fixed path or "?"/"#" is the fixed-prefix case (CTFd).
     The prefix is matched deep in the left operand of each value after it, so a long `+` chain counts.
   - Python, also: Django `Model.objects.*(...)` rows are stored data wherever used (a `for` over a query), not
     `raw()`/`extra()`; `mimetypes.guess_extension()`/`guess_type()` are known-safe (recipes). The equality guard
     needs an expected value that is neither a bare variable nor request data: the first version hid vulpy's
     real SQL injection behind `if password != password_again: return`.
   - Bundles: a JS file of 1-20 KB on one line is a bundler chunk (CTFd's Vite pages: 27 files skipped, was 11),
     not source.
   After: CTFd 7, paperless-ngx 9, recipes 3, umami 0 (19 of 48). Quick suites and CVE pairs unchanged; the 30
   apps lose two trust-boundary findings that store a user's database id after login or sign-up (dvpwa
   sqli/views.py:42, pygoat insecure_design_lab app.py:80) and a known XSS false alarm in one of the user's projects;
   learning sets 1 and 2 unchanged. Left:
   - Real: recipes api.py:2960 (`traceback.format_exc()` in the response). CTFd git.py:132/150/169 store a route
     parameter in the session: the rule's shape, little impact.
   - paperless views.py:1461-1479: a DRF view's whole `request` is a source, so any helper called with it
     returns tainted data (`resolve_requested_version_for_root(root_doc, request)` only reads an int from it).
     Pass-through summaries are per function; per-parameter ones (a call is clean when only arguments that
     aren't passed through are tainted) would fix it. Fixed in item 14.
   - Objects built from request data taint every attribute (paperless_mail: an OAuth manager made with the
     session's state, then its configured redirect URL); a serializer's related-object field is a model
     (paperless views.py:4226); a file-like result of a project function given to send_file (CTFd exports);
     an Angular bypass after an origin allowlist (safeurl.pipe.ts); Jinja for LLM prompts (render.py); a
     quote check before formatting a table name (CTFd exports:416); rows read back from a cache
     (recipes automation_helper.py:221/222); `${location.pathname}?...` (CTFd submissions.js:122, which a
     "//host" path could in principle turn into another host).

14. **Per-parameter pass-through** (2026-11-02; the paperless-ngx shape from item 13,
   `test_arguments_a_helper_does_not_hand_back_are_not_its_result`). The pass rules now report which parameter
   comes back (`$FUNC|$OWNER|$PARAM`), and each call to a project function cleans the arguments at positions or
   keywords that no def of that name hands back: `self._resolve_file_doc(root_doc, request)` is the document's
   data when only an int is read from the request. It is a fixpoint (a helper that hands its argument to one that
   drops it doesn't pass it either; up to 4 rounds, each asking again only about functions that call one whose
   answer changed), and the returner pass now uses it too. Guards (the first and third in tests):
   - Only an argument without a call is cleaned: one with a call can hold a sink (a first version lost 6 OWASP
     Benchmark path traversals, `escape_for_html(p.read_text()[:1000])`).
   - Never builtins, handlers, names in the rule's sinks, or (in the final scan) summarised functions.
   - `*args`/`**kwargs` and differing defs of one name keep their arguments.
   Speed: a straightforward version made Python apps 30-90% slower (djangoproject.com 30s -> 56s, paperless 154s
   -> 260s). Now within 2-10%: the first round shares pass 1's first scan; the pass rules are one variant with the
   sanitizers every rule shares (was eleven; fewer sanitizers can only mean more pass-through, the safe side);
   keyword arguments are one sanitizer with a `metavariable-comparison` pairing function and keyword (was a
   pattern per keyword); and outside the pass rules only functions that hand back some parameter get argument
   sanitizers (one that hands back none keeps the cheaper result sanitizer).
   After: paperless views.py:1461-1479 gone (4); quick suites, both CVE-pair suites, the 30 apps and learning
   sets 1-3 otherwise unchanged.

15. **Weak hash only where it stores a password or vouches for data** (2026-11-02; item 12's lesson, acted on with
   non-blind cases only: outline Team.ts:327/User.ts:337, `test_a_weak_hash_of_a_secret_is_not_a_password_hash`).
   A weak-hash verdict now needs a password, salt, credential, encryption, certificate, signature, integrity or
   verification context; a token or code derived from a secret, an HMAC, an OTP or a cache key is for review
   (MD5/SHA-1 preimages are still out of reach; speed and collisions are what break them). Ground truth checked
   first: all 151 OWASP Benchmark hash cases write a password file; SecurityEval's are a certificate and
   passwords. After: quick suites unchanged; outline's 2 deletion-code hashes and vulpy's S/KEY hash chain
   (utils/skey.py:11/16/25, never recorded as real; an S/KEY chain relies on preimage resistance) moved to
   review; nothing else changed.

16. **Four learning-set false alarms by shape** (2026-11-02; learning sets only, each with a test):
   - Prompt templates aren't HTML (`test_prompt_templates_are_not_html`, paperless paperless_ai/prompts/render.py:29):
     an `Environment(autoescape=False)` whose loader names prompts, SQL, queries, plain text, Markdown, YAML or
     code generation renders no page.
   - A value checked for quotes isn't SQL value formatting (`test_a_value_checked_for_quotes_is_not_sql_value_formatting`,
     CTFd utils/exports/__init__.py:416): `if "'" not in name:` guards the formatted string.
   - A regex with a timeout isn't regex injection (`test_a_regex_with_a_timeout_is_not_regex_injection`, recipes
     helper/automation_helper.py:221/222): the `regex` module's `timeout=` bounds the ReDoS.
   - A path's name or extension isn't a file opened (`test_a_path_name_or_extension_is_not_a_file_opened`,
     paperless documents/views.py:4226): `Path(x).suffix`/`.suffixes`/`.stem`/`.name`/`.parts` read the string only.
   After: those 5 gone; quick suites, both CVE-pair suites, the 30 apps and the other learning-set findings unchanged.

17. **A named check that ends the request** (2026-11-02; item 12's guard lesson, from Django's documented idiom,
   no ground-truth case; `test_a_named_check_that_ends_the_request_guards_what_follows`). `if not
   url_has_allowed_host_and_scheme(nxt, ...): abort(400)` was a verdict open redirect: only `return`/`raise` ended
   the request there, and a project's own `if not is_safe_url(nxt): return ...` wasn't a guard at all (only its
   yes-branch form, item 7). Now both clear what follows, with the same check names as item 7; the no-branch itself
   isn't cleared. After: quick suites, both CVE-pair suites, the 30 apps and the learning sets unchanged. Known gap
   in the older guards: their `if <... check(x) ...>: ... return` form also clears the branch body, so
   `if not url_has_allowed_host_and_scheme(x): return redirect(x)` is missed.

18. **Third blind run** (2026-11-02, at 293fdba; first and only scan of blind set 3, not to be used to adjust
   rules). Verdict findings (first scan; 26):
   - babybuddy (Django): 2, both false alarms. The Home Assistant ingress middleware prefixes a redirect's path
     with the `X-Ingress-Path` header (`"/" + x.lstrip("/")`, host kept: open-redirect) and writes it into HTML
     (xss); the header is set by the proxy in front, which a victim's browser can't send cross-site.
   - papermerge-core (FastAPI): 2. Real: `allow_origins=["*"]` with `allow_credentials=True` (app.py:20;
     Starlette then echoes any Origin). False alarm: sql-injection via `create_document()`, whose helpers only
     build SQLAlchemy `select(...).where(col == value)` statements for `session.execute(stmt)`.
   - uptime-kuma (Express): 13, all false alarms. 4 xss of SVG badges from `makeBadge()` (badge-maker escapes
     its text); 2 xss through status-page helpers whose slug is only a parameterised lookup key; ssrf and xss of
     an RSS feed (the `feed` library builds XML; the request's Host is only a link in it; nothing is fetched);
     a response cache's stored body (looked up by a key built from the request); 2 tls-verification-disabled
     behind a per-notification opt-in (`if (notification.teltonikaUnsafeTls)`); DES-ECB in a vendored
     `server/modules/axios-ntlm` (with its own LICENSE; NTLM requires it).
   - postiz-app (NestJS): 9. Real: ssrf, `fetch(query.url)` in an authenticated webhook test endpoint
     (webhooks.controller.ts:59). False alarms: 5 cookie-without-secure where `secure: true` is spread in unless
     `process.env.NOT_SECURED`; ssrf and path traversal of an AI image result's URL (`generateImage()`); ssrf of
     a URL read from Redis by a key from the request.
   So 4 of 4 apps have verdict false alarms (24, 13 in one Express app), worse than blind sets 1 and 2 (2 of 4
   each). Python is now close (3 false alarms in two apps); JavaScript isn't. Also: a second scan of uptime-kuma
   gave two more badge findings (api-router.js:744/827), so a scan isn't fully deterministic on large files
   (suspect per-file timeouts; check on non-blind apps). Lessons (to act on only with non-blind cases):
   - A value looked up by a key from the request (Redis, Map, cache stores) is stored data, as Python's
     lookup-result already says.
   - A JS cookie's `secure` from config or env, including a conditional spread, isn't a missing flag (Python has
     this since item 13).
   - An opt-in TLS bypass behind a per-record or per-config flag is the user's choice: review, not verdict.
   - SQLAlchemy Core/ORM statements built with `select()/where()` passed to `execute()` bind their values.
   - Vendored modules inside the app tree (`server/modules/<lib>` with a LICENSE) aren't app code.
   - Libraries that escape what they render (SVG badges, RSS/XML feeds) need to be known as sanitizers.
   The blind set is now spent. Next: a fourth learning set weighted to JS/Express and Node apps, cloned and
   pinned along with a fourth blind set before any scan.

19. **Fourth learning set and JS pass-through** (2026-11-02; wiki.js, actual, habitica, cloned with blind set 4
   before any scan, see Repos; kitchenowl's clone stalled and was dropped). Verdict findings before: wiki 20,
   actual 17, habitica 8 (45), all false alarms. First fix, `test_a_javascript_helper_that_never_returns_its_argument_cleans_its_result`:
   item 7's pass-through for JS, per function. A call to a project function that can't return a parameter
   (`const err = requireFileAccess(file, userId); res.send(err)`, which returns a fixed string or null) is
   clean. Only a plain or `this.` call; only shapes the pass rule sees into (functions, `const` arrows, class and
   object methods, `obj.f = ...`), never a class field, a reassigned name or an object literal's property;
   only names whose result is assigned in a file that reads the request. Matching every object literal and every
   assigned call made actual's scan 92s -> 142s; with those limits 91s -> 97s. After: actual's 8 sync-server XSS
   gone (37 left); everything else unchanged. Then, each with a test (`test_a_javascript_check_that_ends_the_request_guards_what_follows`,
   `test_a_signed_cookie_is_the_servers_own_data`, `test_input_escaped_for_a_regex_is_not_regex_injection`,
   `test_a_url_that_starts_as_a_path_on_this_site_stays_there`):
   - JS `san-guard` takes a named check that ends the request (`if (!isValidRedirectUrl(url)) return`; names
     starting is/check/can and containing safe/valid/allowed/permitted/trusted/whitelist/allowlist), not in its
     own branch, and not a bare `if (!url)`.
   - `req.unsignCookie(...)` is a sanitizer and `req.signedCookies` no longer a source: what the server signed is
     its own data, like a session.
   - regex-injection: `x.replace(<regex>, '\\$&')` escapes the value.
   - open-redirect: a `let`/`var` that starts as a same-site path stays clean through appends (`url += ...`);
     known gap, in the rule: a variable set to request data and then appended to would be missed.
   After: 27 left (wiki's five auth-flow redirects, actual's OpenID redirect, CORS-proxy SSRF and one sync XSS,
   habitica's Apple redirect and admin regex gone); quick suites, CVE pairs, the 30 apps and learning sets 1-3
   unchanged. With the focus now on Python (see "Where things stand"), the rest waits. Shapes left:
   - A fixed same-site path built in a helper: `` `/login?${params}` `` (wiki 1272); an OAuth provider's
     authorization URL from a library call (wiki 1268).
   - A value hashed by a project helper before it names a file (habitica content.js, `hashForFilter()` with
     `charCodeAt` arithmetic): the summary pass treats a helper's result as carrying its argument, so this needs
     pass-through in pass 1 too; and a value used only inside `if (x && allowed.includes(x)) { ... }` in JS.
   - A hash digest isn't markup (wiki notifications.ts:156, an ETag); `path.relative()` containment (actual
     serve-build.mjs:87); an opt-in TLS bypass (wiki hooks.ts:95) is review, as blind set 3 said.
   - `WIKI.models.x.y(...)` model-registry lookups and summaries through `this.getEntry(...)` (wiki
     navigation.ts:705, feedback.ts:754, assets.ts:951); PayPal's approval link (habitica paypal.js:41/105).

20. **Security review of the server** (2026-11-02; a review at the user's work found the first four, the rest from
   a full review; `tests/test_security.py`, each test failing without its fix):
   - Uploaded commits were git options: `reference_commit = "--output=/path"` made `git diff` overwrite any file
     the server could write, and through the project config the same on developers' machines. Uploads now
     need full hashes and a branch name; every revision passed to git follows `--end-of-options`.
   - Symlinks: a repository's `a.py -> ~/.ssh/id_rsa` was linted, flagged and its content stored and shown.
     Server checkouts lose their symlinks; files resolving outside the project are never scanned or uploaded.
   - Server scans ran repository code: basedpyright ran the repo's `venv/bin/python`, pip-audit built its
     packages. Both only for the developer's own copy (`Context.local`, codewatch-scan); the server checks
     pinned requirements as written (`--no-deps --disable-pip`). A container is still the real answer.
   - The server's git credentials: anyone could register a private repository the server's keys or credential
     helper could read. Only projects an administrator owns (or added with `addproject`) clone with them; others
     get no global config, an empty HOME and no SSH keys or agent.
   - A deleted project's mirror served the next project with its key (another user's repository): deleting a
     project deletes its cache, and a mirror whose remote differs is re-cloned.
   - Requests to the server's own network: repository and accessibility URLs must resolve to public addresses
     (checked when saved and again at scan time) and `semgrep_config` must be a registry ruleset, unless an
     administrator owns the project. Axe had echoed internal pages back as findings.
   - The client sent its token to a `serverUrl` named by the repository's committed config, and over plain http:
     now only to a server its user chose (`codewatch init --url`, `~/.config/codewatch/servers.txt` or
     `CODEWATCH_URL`), and only over https except to localhost; the MCP server likewise.
   - Defaults: DEBUG off, allowed hosts from `CODEWATCH_ALLOWED_HOSTS`, secure cookies and HSTS with
     `CODEWATCH_HTTPS=1`, a secret key generated once (0600), the first admin password random (or
     `CODEWATCH_ADMIN_PASSWORD`) instead of admin/admin, ten wrong passwords lock a username out for 15 minutes.
   - Tool upgrades install from hashed locks (`tools/*.lock`, `npm ci`), pinned at the installed versions;
     `make lock` makes new ones to review.
   - Scans per branch (main included) and across the server (`CODEWATCH_MAX_SCANS`, 4) are limited, scans of one
     project take a lock, coverage uploads are capped, uploaded severities and types are checked, uploaded
     results are marked self-reported, a path starting with "-" reaches tools as `./-...` (ruff took
     `--output-file=x.py` as an option), API numbers are checked and issues sorted in the database, and the MCP
     server tells agents that issue text and snippets are data.

21. **Parallel tests and benchmarks** (2026-11-02, asked for: 20 threads, 64 GB). pytest-xdist (`-n auto`): tests
   9m41s -> 1m06s. `devtools bench` and `codewatch benchmark` scan suites and CVE cases in a process pool, and
   `devtools repos` the apps (`CODEWATCH_BENCH_WORKERS`, a third of the CPUs); scoring and output are unchanged.
   Two things went wrong first:
   - Concurrent Semgrep runs failed with `io_uring_queue_init: Cannot allocate memory`: semgrep-core gives each
     worker an io_uring, charged to the user's 8 MB locked-memory limit. Semgrep now runs with
     `EIO_BACKEND=posix` (paperless 169s -> 172s alone).
   - Six scans each with a job per CPU stretched rules past Semgrep's timeouts and dropped findings silently
     (litellm's SQL injection, recipes api.py:2960) while running slower than one at a time. Each parallel
     Semgrep run now gets its share of the CPUs (`CODEWATCH_SEMGREP_JOBS`).
   After: identical results to sequential runs everywhere; quick suites 470s -> 250s, Python CVE pairs 36 -> 13
   min, learning sets about 25 -> 10 min, check.sh (lint, tests, quick suites, 30 apps) about 25 -> 7 min.

22. **More Python ground truth** (2026-11-02, the focus on Python web apps). From GitHub's reviewed pip advisories
   since 2021 with CWE 22, 79, 89, 94, 502, 601, 611, 78, 918 or 1336 (2,321), those with exactly one fix commit
   (1,019, 1,003 fetched), at most three non-test source files and 120 changed lines touching web code (189),
   each fix read by hand: 41 accepted, the rest rejected for being library or framework code (Authlib, aiohttp,
   urllib3, Django's own ORM...), Tornado apps, stored data with no request path, validator bypasses no rule can
   see, settings flags, missing authentication, or a fix mixing unrelated changes. Excluded too: InvenTree's
   advisory (InvenTree is in blind set 4). The 41 were split before any scan by a fixed rule (blind when
   `int(sha256(id), 16) % 3 == 0`): 19 joined `cve-pairs-python` (now 33), 6 template and front-end JS cases form
   `cve-pairs-python-frontend` (new `python-web` language: templates and scripts count as source), and 11 + 5
   form `cve-pairs-blind-python-2` and `cve-pairs-blind-python-frontend` (scanned once, at the end of a round).
   The old blind CVE suites were spent in step 6.
   Baseline at this commit (none of the new cases used for rules yet):
   - cve-pairs-python: verdict 14/33 found, 7 still flagged after the fix (was 5/14, 1); review 16/33, 8.
     New finds: DB-GPT, TinyScientist and pyLoad upload path traversal, and six that stay flagged at their fix
     (MindsDB zip slip, pyLoad CNL, LLaMA Factory, label-studio file:// import, MLflow XSS and path traversal),
     each to be read: an unrecognised guard shape is a false alarm to fix, an incomplete fix is a real finding.
   - cve-pairs-python-frontend: verdict 0/6; review 4/6 (template `|safe`, jQuery HTML), 2 still flagged.
   Next: the six still-flagged fixes, then the misses whose flow is visible (changedetection.io's filter that
   keeps ".", Fides and CodeRed paths, Scout and pyLoad SSRF), then the front end. (This line first listed
   Gerapy's shell commands too: Gerapy, GHSA-9w7f, is in the blind suite `cve-pairs-blind-python-2`, so it was
   struck on 2026-11-02 without being looked at.)

   First round on the new cases (2026-11-02), each change with a test in `tests/test_detection.py`:
   - Still-flagged fixes read one by one. Real (kept): MindsDB (the request's `file` still reaches a path),
     label-studio (only `file://` blocked), LLaMA Factory (`os.path.isfile(url)` runs before the new check),
     Scout (its fix is an allowlist check whose name, `check_session_tracks`, says nothing about URLs). False
     alarms fixed: a validator that raises named for what it checks (`check_lfi_path(url)`,
     `validate_path_is_safe(path)`; GHSA-527m, GHSA-wc6j); `abspath/realpath/normpath(p).startswith(base +
     os.sep)` (GHSA-48rp; not without the separator); Flask `make_response({...})` is JSON (GHSA-vwhf); a record
     looked up through a store or call chain, `_get_tracking_store().get_run(id)` (GHSA-wc6j).
   - Misses found: Django URL arguments are request input when their urls.py route passes free text
     (`route_converters.py` marks them on the scanned copy; `<int:pk>`, `<slug:...>`, `\d+` stay clean; CodeRed
     GHSA-h454); route parameters are tainted where declared (`focus-metavariable`), so `name =
     secure_filename(name)` clears them (changedetection.io GHSA-9jj8, which also needed `re.sub(r'[^a-z0-9_]+',
     '', x)` as a path sanitizer; `[^\w.-]` keeps ".." and doesn't count); FastAPI/Starlette `FileResponse(path)`
     and `sanitise_*` (British spelling) as a validator name (Fides GHSA-r25m); `requests.request(...,
     url=...)` (Scout GHSA-g53g); and a new rule, `codewatch.python.web.template.xss`: request data passed to a
     variable a template prints with `|safe` or under `autoescape off` (`template_sinks.py`; Whoogle
     GHSA-mxvc). Whoogle's vulnerable view still passes for checked, because a forbidden-character guard
     (`if "'" in x: return`) accepts any literal, `'http' in q` too; requiring non-word characters fixed it but
     exposed four false alarms in paperless-ngx (views.py:1461-1479, a document resolved through several
     helpers), so it was reverted until that flow is understood.
   - False alarms these exposed on the 30 apps, fixed: a session key with a fixed prefix (`f"player_{code}"`)
     isn't a trust-boundary sink; a model's own `render_to_string(request=request)` isn't request data
     (djangoproject.com); `{{ form.field|safe }}` renders an escaping widget (pygoat). On the learning sets: an admin-only view (`@admins_only`) renders the administrator's own HTML (CTFd's page preview). New real findings: four
     XSS in pygoat's labs, and djangoproject.com docs/views.py:57 (a `[\w./-]*` URL part reaches
     `docroot / Path(*bits)`: any `.fjson` file outside the docs root).
   - Result: cve-pairs-python verdict 18/33 found (was 14), still flagged 5 (was 7); review 20/33, 7. Front
     end unchanged at 0/6 verdict: Whoogle's flow needs the guard change above, and its fix changes only error.html,
     while a pair is scored only in the files its fix changed. Scoring a template fix against the views that render
     the template is next for the front-end suite.
   Faster loop from here (the user's call): during the day, each change is checked in isolation (its tests, a
   probe on the case's files, `devtools.py cases ID...` for the CVE pairs it targets); the full verification runs
   nightly (`benchmarks/nightly.sh` from a systemd user timer at 01:30, the app list in
   `~/.config/codewatch/nightly-apps.txt`, a dated report in `~/.cache/codewatch/nightly/`) and is read the next
   morning.

Also 2026-10-31, the rest of the user's ~/Dev projects (the set differs per machine; list ~/Dev first). New
findings were mostly false alarms that route parameters as sources exposed, now fixed (each in
`test_false_alarms_from_small_flask_apps`): a return inside a function nested in a view isn't the
response; `lookup-result` sanitizer for the variable assigned from a bare call to a `get_X`/`fetch_X`/`load_X`/
`find_X` helper, also inside `try:` (not `get_json`/`get_param`-style names; the returner pass's variants drop it
so a real `get_cmd()` returner still counts). It cleans the variable, not the call: a first version cleaned the
call and hid a real path traversal inside a `load_X(...)` call, a via-sink among its arguments; `Response(..., mimetype="video/...")` and other media/JSON types aren't XSS, nor is
`return Response(...)` built inline; command injection: `secure_filename()` output and a literal
`https://host/...` argv element are clean; weak-random-token's `$SESSION[...] =` sink needs a session-named
target (any dict matched; pygoat's OTP stored in a plain dict is still flagged by bandit's B311 as a
secret-purpose random); and `cache_key`/`sort_key`-style names no longer make a function security-related for
weak-hash. Real findings in those projects (an open proxy, a path traversal, an open
redirect) are measurement only: fixing them is not part of this plan. Two known false alarms are left: an id
reaching a helper's Response through Semgrep's call-result propagation, and an attribute value with `"` stripped.

Also 2026-10-31: `**/site-packages/**` joined the default exclusions (a committed virtualenv made one of the user's
projects 9,910 files and timed out the final scan; existing projects keep their saved list).
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
- Scans at once (parallel benchmarks) need two things, both in place: Semgrep on POSIX I/O (`EIO_BACKEND=posix`;
  io_uring rings count against an 8 MB locked-memory limit and concurrent runs failed with exit 2), and each run
  limited to its share of the CPUs (`CODEWATCH_SEMGREP_JOBS`): with a job per CPU each, rules ran past their
  timeouts and findings disappeared without an error (step 21). Don't run anything else heavy alongside a run
  whose results will be compared.
- CVE-pair scans set `Context.focus` to the changed files: summaries, the caller index and other analyzers still
  see the whole scope, only Semgrep's per-file final pass is narrowed. Checked identical on Parsl and mockoon
  (both sides); saves ~50% on JS, only 10-17% on Python, where the summary passes dominate.

## Tools

- `venv/bin/python benchmarks/devtools.py bench|rules|repos|owasp` (see its docstring); `codewatch benchmark` for
  the full suite run that writes `benchmarks/results/`. `bench`, `repos` and `codewatch benchmark` run in parallel
  (`CODEWATCH_BENCH_WORKERS`, default a third of the CPUs); `CODEWATCH_BENCH_WORKERS=1` for one at a time.
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
| https://github.com/flaskbb/flaskbb | 737d76f14e | ordinary Flask forum (step 10) |
| https://github.com/outline/outline | 91bf8f5f6d | ordinary Koa/React app (step 10) |
| https://github.com/madhums/node-express-mongoose-demo | 8a134ab5de | ordinary Express app (step 10) |
| https://github.com/danielfsousa/express-rest-boilerplate | b8bed6d7cf | ordinary Express app (step 10) |
| https://github.com/bradtraversy/proshop-v2 | e23e3a897e | ordinary Express/React app (step 10) |
| https://github.com/wger-project/wger | dde740753e | ordinary Django app (step 11) |
| https://github.com/kaleidos-ventures/taiga-back | 8309789629 | ordinary Django/DRF app (step 11) |
| https://github.com/Netflix/dispatch | dd2837e82a | ordinary FastAPI app (step 11) |
| https://github.com/immich-app/immich | b7510e79ac | ordinary NestJS app (step 11) |
| https://github.com/linkwarden/linkwarden | eff7c6b735 | ordinary Next.js app (step 11) |
| https://github.com/paperless-ngx/paperless-ngx | 5b63c9a0ff | ordinary Django app (step 13) |
| https://github.com/TandoorRecipes/recipes | cbb96e151f | ordinary Django app (step 13) |
| https://github.com/CTFd/CTFd | eccab90318 | ordinary Flask app (step 13) |
| https://github.com/umami-software/umami | 559e3c607c | ordinary Next.js app (step 13) |
| https://github.com/requarks/wiki | 54cda2cb48 | ordinary Express/GraphQL app (step 19) |
| https://github.com/actualbudget/actual | 741d1615b7 | ordinary Express app (sync server; step 19) |
| https://github.com/HabitRPG/habitica | 12091ca029 | ordinary Express app (step 19) |
| https://github.com/netbox-community/netbox | 6955afbac5 | ordinary Django app with JS (learning set 5, unscanned) |
| https://github.com/HumanSignal/label-studio | 60b7f987b7 | ordinary Django app with a React front end (learning set 5, unscanned) |
| https://github.com/Netflix/lemur | 3a3c2c201d | ordinary Flask app with an Angular front end (learning set 5, unscanned) |

Blind set, cloned in `~/.cache/codewatch/blind/`; scan only in step 6, never use to adjust rules:

| Repo | Commit | Kind |
|---|---|---|
| https://github.com/HackSoftware/Django-Styleguide-Example | a70ef43d7d | ordinary Django app |
| https://github.com/igorbenav/FastAPI-boilerplate | 2d0ca1a79a | ordinary FastAPI app |
| https://github.com/sahat/hackathon-starter | a2e4b4057a | ordinary Express app |
| https://github.com/notiz-dev/nestjs-prisma-starter | 225e5a9068 | ordinary NestJS app |

Second blind set, chosen and cloned 2026-11-01 before any scan (the first is spent), in `~/.cache/codewatch/blind2/`;
scanned once at 81ce0e3 (step 12) and now spent, never use to adjust rules:

| Repo | Commit | Kind |
|---|---|---|
| https://github.com/healthchecks/healthchecks | ab4b5c46d6 | ordinary Django app |
| https://github.com/mealie-recipes/mealie | bc21069738 | ordinary FastAPI app |
| https://github.com/w3tecch/express-typescript-boilerplate | 17727010f7 | ordinary Express app |
| https://github.com/ghostfolio/ghostfolio | 841ff112c4 | ordinary NestJS app |

Third blind set, chosen and cloned 2026-11-01 before any scan, in `~/.cache/codewatch/blind3/`; scanned once at
293fdba (step 18) and now spent, never use to adjust rules:

| Repo | Commit | Kind |
|---|---|---|
| https://github.com/babybuddy/babybuddy | 2bd0461f5a | ordinary Django app |
| https://github.com/papermerge/papermerge-core | c0f22f1ac1 | ordinary FastAPI app |
| https://github.com/louislam/uptime-kuma | cbd357eb39 | ordinary Express app |
| https://github.com/gitroomhq/postiz-app | 4d13c6a2a8 | ordinary NestJS app |

2026-11-02: full-stack-fastapi-template and node-express-realworld-example-app were in this set at the same
commits as the dev-set apps every run scans (expected 0 since the start), so they weren't blind. Replaced, before
any scan, by papermerge-core and uptime-kuma (cloned at their latest commits; neither is used anywhere else).

Fourth blind set, chosen and cloned 2026-11-02 with learning set 4 and before any scan of either, in
`~/.cache/codewatch/blind4/`; scan only at the end of the next round, never use to adjust rules:

| Repo | Commit | Kind |
|---|---|---|
| https://github.com/getredash/redash | 4e62d11000 | ordinary Flask app with a React front end |
| https://github.com/inventree/InvenTree | 2629cde722 | ordinary Django app with a React front end |
| https://github.com/pretalx/pretalx | 887b50ac22 | ordinary Django app |
| https://github.com/fief-dev/fief | a77e7fb65f | ordinary FastAPI app |

2026-11-02, still before any scan: NodeBB (Express) and hedgedoc (NestJS) were swapped for redash and InvenTree
when the focus moved to Python web apps and the JavaScript they ship (see "Where things stand").

CVE fix pairs are suites (`cve-pairs-*` in `benchmarks/suites.json`); the `cve-pairs-blind-*` suites are skipped
unless named and follow the same rule.

The user's own projects in `~/Dev` (the set differs per machine; they are private and not named here) are useful
false-alarm checks. Their known findings are tracked locally, not in this repository.
