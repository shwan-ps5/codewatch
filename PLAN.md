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

## Where things stand (2026-11-02, commit ceb95ca)

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
| CVE fix pairs, Python front end (6, step 22; 27 since the second batch, not yet measured here) | 0 found | 4 found, 2 still flagged |
| CVE fix pairs, JS/TS (10) | 2 found, 0 still flagged | 4 found, 3 still flagged |

False alarms on ordinary apps (verdict mode):
- The 30 dev apps (six deliberately vulnerable apps, nine ordinary ones, the user's 15 own projects): unchanged
  from run to run. The vulnerable apps' findings are real; the user's projects have the real findings and the two
  known false alarms listed in the 2026-10-31 notes after step 18.
- Learning sets 1-3 (14 apps): 18 findings left, each classified in steps 13 and 18 (real: recipes api.py:2960,
  outline's four TLS settings; little impact: CTFd's three session writes; the rest need models codewatch
  doesn't have, such as an OAuth manager built from session state).
- Learning set 4 (wiki.js, actual, habitica): 24 findings, all false alarms, grouped by shape in step 19 (27
  until PR #1, 2026-11-02: a JS helper named like a loader, `loadIdea(req, reply)`, returns the record it looked
  up, not request data, which removed wiki.js feedback.ts:754 (twice) and comments.ts:670).
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
3. The front end (step 22): template-only fixes are now scored at the views that render the template (step 26);
   Whoogle's `'http' in q` passing as a guard, which is now the only thing between GHSA-mxvc and a verdict find (the fix exposed paperless-ngx false alarms, so understand that flow first);
   verdict detection for front-end JS (request data into innerHTML or jQuery HTML).
4. The Python miss still in reach: pyLoad's SSRF through its own pycurl wrapper (`get_url`); the rest (stored
   data, settings flags, template-built SQL, `g`-stored state) are recorded as out of reach.
   Also from step 24 (MobSF GHSA-8m9j at its fix): `redirect(auth.login(return_to=x))` is flagged, though
   python3-saml's login() returns the identity provider's URL with x only as RelayState, a library call's
   result taken for the request value. And the 53 Python pairs (49 + 4) get their first full measurement
   in the nightly run.
5. End of the round: blind set 4 (redash, InvenTree, pretalx, fief) and the blind CVE suites
   (`cve-pairs-blind-python-2` to `-7`, `-python-nonhttp`, `cve-pairs-blind-python-frontend`, `-frontend-2`, `-frontend-3`, and from step 29
   `cve-pairs-blind-javascript-2` to `-6` and `-javascript-nonhttp`), each scanned once, measurement only. The fixes in `-python-5` and the
   JavaScript ones were never sized (steps 27 and 29), so report them with that caveat. Two are partly seen: GHSA-hh2q (`-python-2`, its diff read in step 23) and GHSA-h8pc
   (`-frontend-2`, PR #5's description says what its fix leaves open); report each suite with and without them.
6. A container for server-side scans of untrusted repositories; Semgrep timeouts recorded per run.
7. Other languages and frameworks (Node/Express first), as local rule work. Cloud sessions (CLAUDE.md) gather
   their ground truth and do self-contained engineering. The first cloud PR (#1, Express sinks) showed that rule
   changes need the local app sets to judge false alarms: it added three false alarms in wiki.js the session
   couldn't see.

Not filled, by choice: CSRF beyond the existing hotspots; authorization (CWE-862/863/639), which needs app
knowledge.

### Record of 2026-10-31 (commit 1959106)

- Step 1 is built: `cve-pairs-python` (14 cases), `cve-pairs-javascript` (10), and blind `cve-pairs-blind-*`
  (run only when named). Ordinary apps (7) give 0 vulnerability false alarms. Standards-gap rules (CWE-208, 209,
  306, 434, 532, 614, 915, 942, 1004, 1336, 90, 643) and the OSV lockfile analyzer are in.
- First CVE-pair run, at commit bd6b53a (before be61622's rules and the scan narrowing in 1959106):

  | Suite | Verdict found / still flagged | Review found / still flagged |
  |---|---|---|
  | cve-pairs-python | 2/14 / 1/14 | 5/14 / 1/14 |
  | cve-pairs-javascript | 1/10 / 1/10 | 4/10 / 4/10 |

  Re-run at commit 26e7dd2 (be61622's rules plus the scan narrowing) gave exactly the same table; those result
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
   Second batch of front-end cases (2026-11-02, a cloud session; no rules changed). The same advisory source, widened
   to all years, to fixes over three files or 120 lines when every change is the same weakness (OctoPrint's Jinja2
   escapes, Indico's confirmation prompts, changedetection.io renaming `.jinja` templates to `.html` so Flask
   autoescapes them), and to advisories whose extra commits are backports of one fix (the main-branch commit is
   used). 123 advisories read: 30 accepted, 93 rejected, each with its reason in
   `benchmarks/reviews-python-frontend-2.md` (blind cases there only by app and file kind). Split before any scan by
   the same sha256 rule: 21 joined `cve-pairs-python-frontend` (now 27), 9 form `cve-pairs-blind-python-frontend-2`
   (scanned once, at the end of a round). Rejections were mostly frameworks and libraries (Django REST framework,
   Flask-AppBuilder, NiceGUI, Dash, Bleach), apps on other servers (Jupyter and WebSSH on Tornado, CherryMusic,
   Maloja, Roundup, Synapse, copyparty), fixes only in Python, and fixes only in `.svelte` files (Open WebUI five
   times, Fava): `.svelte` isn't in `SOURCE_EXTENSIONS["python-web"]`, so such a pair can't be scored; adding it is
   a scorer change for a later session. Baseline: not measured in the cloud session (`devtools.py cases` over the
   20 large-repository pairs hit the session's two-hour limit; only cabot GHSA-mqwh-r366-4224 finished: verdict
   missed, review found by `codewatch.templates.unescaped-output`, quiet after the fix). The nightly run measures it.
   Faster loop from here (the user's call): during the day, each change is checked in isolation (its tests, a
   probe on the case's files, `devtools.py cases ID...` for the CVE pairs it targets); the full verification runs
   nightly (`benchmarks/nightly.sh` from a systemd user timer at 01:30, the app list in
   `~/.config/codewatch/nightly-apps.txt`, a dated report in `~/.cache/codewatch/nightly/`) and is read the next
   morning.

23. **More Python ground truth, second batch** (2026-11-02, cloud session; no rules changed). The same rule as
   step 22, aiming for about 30 more cases. GitHub's advisory API isn't reachable from a cloud session, so the
   candidates came from OSV's PyPI export (`osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`), which
   carries GitHub's reviewed advisories with their CWEs and references: reviewed, published since 2021, CWE 22,
   78, 79, 89, 94, 502, 601, 611, 918 or 1336, exactly one fix-commit link, not already in a suite: 960 (step 22
   had 1,003 from the API). Each fix was fetched (`git fetch --depth=2 --filter=blob:none`) and sized: at most
   three non-test source files (`.py`, templates, scripts) and 120 changed lines: 627. Of those, the ~500 in
   libraries, frameworks, CLIs, ML toolkits and servers that aren't Django/Flask/FastAPI (aiohttp, Tornado,
   CherryPy, Twisted, http.server, gRPC, Gradio, Streamlit, NiceGUI, Mesop...) were set aside by repository
   without reading the diff; the 120 in web applications were read one by one, plus 9 of the 46 pre-2021
   advisories (the only ones in applications), 129 in all. Every decision and reason is in
   `benchmarks/cve-candidates-2026-11-02.tsv`.
   - Accepted 22 (3 of them pre-2021: xmpp-http-upload, graphite-web, Superset). Split before any scan by the
     sha256 rule: 16 joined `cve-pairs-python` (now 49), 6 form the new `cve-pairs-blind-python-3` (their reasons
     are withheld in the TSV). Only 22, not 30: the pool under this rule ran out; the rest were rejected for the
     step 22 reasons (validator and allowlist changes, stored data, missing authentication or authorization,
     settings flags, library code, mixed or refactoring commits), plus several advisories sharing one fix commit
     (one case per commit) and a few fixes over the size rule once short commit ids were resolved.
   - GHSA-q97g-c29h-x2p7 (Whoogle) was accepted, then dropped: its fix commit, 3a2e0b262e, is already the blind
     case GHSA-hh2q-qv66-jcqg in `cve-pairs-blind-python-2` (two more advisories, GHSA-3q6g and GHSA-phg6, share
     it too). The diff of that blind case was read in this session before the overlap was noticed; nothing was
     done with it, but say so if that case is ever discussed. Later batches should drop candidates whose fix
     commit is in any suite before reading them.
   - Scopes are the app's package folder, or the two folders a flow crosses (Dagster webserver and log manager,
     Langflow API and `lfx/custom`). Nothing was scanned in the session; the nightly run measures
     `cve-pairs-python`. Shapes likely to matter there (open cases only): Quart's Flask-like `request` (AstrBot),
     flows into a store class (MLflow FileStore, Dagster log manager), an upload into `ZipFile.extractall`
     (Gramps), `cursor.execute` with `str.format` behind Flask-RESTful (postgraas), and code reaching `exec`/`eval`
     (Langflow, pgAdmin).

24. **More Python ground truth, third batch, widened rule** (2026-11-02, cloud session; no rules changed). Step 23's
   pool ran out at 22, so the rule was widened, each widening recorded here:
   - Weaknesses: CWE 23, 36 and 73 (path variants), 77, 90 (LDAP), 113 (header injection), 643 (XPath), 943
     (NoSQL) and 1333 (ReDoS from request data), still request input reaching a sink in the app's own code.
   - Fix size: up to five non-test source files and 200 changed lines, when the vulnerable flow is still clear
     from the diff (step 22: three and 120).
   - Frameworks: Quart, Starlette and Flask-RESTful/Flask-AppBuilder apps count as Flask/FastAPI (step 23 already
     did this); Tornado, aiohttp, Gradio and Streamlit stay excluded.
   - Pre-2021 advisories in Django/Flask/FastAPI apps, read the same way.
   Method as in step 23 (OSV's PyPI export of GitHub's reviewed advisories, fixes sized with a blobless fetch),
   with one change from CLAUDE.md: candidates whose fix commit is already in any suite, blind ones included, were
   dropped before reading (6). Only candidates a widening newly admits were considered; ones step 22 or 23's rule
   already covered were not re-read (step 23's two size rejections were reconsidered: GHSA-j74f was read and
   rejected). 1,103 candidates, 228 within the widened size rule and newly admitted, about 60 of them in web apps
   and read one by one (59 lines in `benchmarks/cve-candidates-2026-11-02-batch3.tsv`); the rest are libraries,
   CLIs and other servers, set aside by repository. Eleven LoLLMS advisories and a few others couldn't be
   fetched (their commits are gone or their ids are short), so they weren't read.
   - Accepted 11, not the 30 aimed for: the widened pool is mostly libraries and validator changes too. Split by
     the sha256 rule: 4 joined `cve-pairs-python` (now 53), 7 form `cve-pairs-blind-python-4` (an uneven split
     for so few cases; reasons withheld in the TSV). By widening: 7 through the new CWEs, 4 through the size limit,
     pre-2021 none (the nine pre-2021 app advisories read were frameworks, libraries or stored data).
   - Open cases: django-wiki's search keyword into `re.compile` (CWE 1333, through a template tag), MLflow's model
     name into the model-registry FileStore path (36), MobSF's `next` behind `startswith("/")` (601), pgAdmin's
     backup/import file name into the storage path (22, five files).
   - Probed with `devtools.py cases` (two allowed): django-wiki found in review mode only (`regex-injection` at
     the `re.compile`), quiet at the fix; MobSF found in verdict mode, but still flagged at the fix, at saml2.py:146,
     `redirect(auth.login(return_to=redirect_url))`: the target is the identity provider's URL from python3-saml,
     so that's a false-alarm shape (a library call's result treated as the request value). Separately, the fix's
     `sanitize_redirect` still accepts `/\host`, which browsers read as `//host`, so a finding on the login view
     at the fix would be an incomplete fix, not a false alarm. The nightly run measures `cve-pairs-python`.

25. **Express/Node sinks** (PR #1, 2026-11-02, the first cloud session; rules finished after local review). New sinks
   in `javascript-taint.yml` for module shapes the rules missed: `node:` specifiers, fs-extra/graceful-fs,
   `fs/promises`, inline `require('fs').x`, move/copy destinations, `res.sendFile` without `root`, promisified
   `exec`, execa with a shell, superagent/needle/ky/undici. Creating a directory isn't a path-traversal sink.
   multer's generated `req.file.path`/`filename` aren't request data (`originalname` is). `summaries.py`'s returner
   pass gained `JS_LOOKUP_SANITIZER`, the JS twin of Python's lookup-result. Driven by probes of common shapes, not
   benchmark cases; the first version added three false alarms in wiki.js that the cloud session couldn't see, the
   reason rule work now stays local. Verified locally: quick suites, 30 apps and cve-pairs-javascript unchanged;
   learning set 4 down from 27 to 24. Open question from the session: a one-line
   `require('fs').createReadStream(req.query.f).pipe(res)` was missed in one probe file but not another.

26. **Template-only fixes scored at the rendering call** (2026-11-02, cloud session; no rules changed). A CVE pair was
   scored only on findings in the files its fix changed, and Semgrep's per-file pass was narrowed to them. When the
   fix changes only a template (Whoogle GHSA-mxvc drops `|safe` from `app/templates/error.html`), the finding is at
   the Python call that renders it, `render_template('error.html', error_message=...)` (rule
   `codewatch.python.web.template.xss`), in an unchanged file, so the pair could only count as missed. Now, in
   `core/benchmark.py`, for Python suites (`python`, `python-web`):
   - each non-test template the fix changes is named as a view names it (`template_sinks.template_name`), and the
     Python files in the checkout that render it by that name are found with `ast` (`render_template` /
     `render_to_string` first argument, Django `render` / `TemplateResponse` second, or `template_name` keyword);
   - those files join the scan focus and are kept in the scored findings on each side, but only for findings of the
     template rule inside a call that names a changed template (`spots["renders"]`): an unrelated finding in a
     rendering file, or the template rule on another template, isn't counted;
   - a finding that survives the fix still counts as still flagged, as before.
   It also turned out the template rule could never be scored at all: it's built at scan time, has no catalogue
   entry, and so carried no CWE. The scorer now gives it the XSS rule's CWEs (`DERIVED_RULES`). Its catalogue gap
   (no title or CWE on the finding page) is left for a local session. Tests: `tests/test_benchmark.py` builds a
   Whoogle-like pair in a temporary git repository (found at the render call, quiet after the fix; another
   template's `|safe` and a direct echo in the same file not counted), and `semgrep_vulnerabilities(...,
   full_ids=True)` in `tests/test_detection.py` keeps the whole rule id where the last part is ambiguous (`.xss`).
   - Probe, `devtools.py cases GHSA-mxvc` (cve-pairs-python-frontend): still missed in verdict mode, quiet at the fix;
     review mode finds `codewatch.templates.unescaped-output` in error.html, as before. The scorer now looks in the
     right place: it finds the four `render_template('error.html', ...)` calls in `app/routes.py`, but the template
     rule fires on none of them at the vulnerable commit. The vulnerable call (routes.py:446) is in the `else` of
     `if len(q) > 0 and 'http' in q: return redirect(q)`, which passes as a guard (next step 3, rule work); the
     others pass `session['error_message']`, a translation string, and an exception message.
   - May change other pairs' scores: any Python pair whose fix touches a template now also counts the template rule
     at that template's render calls. The nightly run measures it.

27. **More Python ground truth, fourth batch** (2026-11-03, research session; no rules changed). Step 24's rule,
    read from OSV's PyPI export of GitHub's reviewed advisories (published since 2021, one fix commit, not already
    in a suite or read before). Most candidates were libraries, frameworks, CLIs and servers, set aside by repository
    without reading. 74 read, 5 accepted: 2 open and 3 blind. The pool under step 24's rule is nearly used up. The
    research session didn't add them to the suites. That happened at review the same evening, after checking the
    open fix commits on GitHub:
    - Arches GHSA-gmpq joined `cve-pairs-python`. It's 244 changed lines, but most are re-indented SQL: 147
      ignoring whitespace, in 2 files, so within step 24's limits.
    - Modoboa GHSA-wwv8 was rejected: its fix touches 10 source files.
    - The three blind cases form `cve-pairs-blind-python-5`. Their fixes weren't sized (that would mean reading
      them).

    Decisions are in `benchmarks/cve-candidates-2026-11-03.tsv`.
28. **Flask's extension-based autoescape** (2026-11-03; from the front-end inventory, driven by
    GHSA-pwgc-w4x9-gw67 (changedetection.io) in `cve-pairs-python-frontend`). Flask only autoescapes
    `.html/.htm/.xml/.xhtml/.svg`, so a `.jinja/.jinja2/.j2` template prints every `{{ }}` raw. The template analyzer
    treated those extensions as autoescaping, and the Semgrep analyzer never scanned them at all (its targets ended
    at `.html`), so both the `|safe`/autoescape-off hotspot and the generated template rule missed them. Now:
    `.jinja/.jinja2/.j2/.djhtml` are Semgrep targets (the last was already in the hotspot's paths but unscanned);
    the generated template rule treats every variable in a Flask-raw extension as a sink for
    `render_template`/`flask.render_template` only, so Django's `render` calls stay safe (its Jinja backend
    autoescapes); and a new hotspot, `codewatch.templates.not-autoescaped`, reports the raw variable in those
    extensions for stored data (review, since Django's Jinja backend autoescapes them too). Test:
    `test_flask_jinja_templates_are_not_autoescaped` (the hotspot, the taint rule at the Flask render call, and
    `|e`/`.html`/Django render quiet). The suite is not held out; the nightly run measures GHSA-pwgc.
29. **JavaScript ground truth from npm** (2026-11-03; candidates gathered in a separate local research session,
    then reviewed here; no rules changed). Four batches from OSV's npm export (first batch, Next/React/Vue and DOM
    XSS, long tail, non-HTTP sources), each fix read and split by step 22's rule before any scan: 49 accepted,
    32 open and 17 blind (`cve-pairs-blind-javascript-2` to `-5`). Reviewed the same day, still before any scan,
    by checking each open fix commit on GitHub against step 22's limits. Ten were dropped: six fix commits over
    the limits (Tutanota GHSA-24v3, RSSHub GHSA-2wqw, lobe-chat GHSA-2xcc, claudecodeui GHSA-7fv4, NocoBase
    GHSA-p853, tts-api GHSA-jx6q), three sanitizer-denylist or renderer-setting fixes in Joplin (GHSA-cgc7, -mrmf,
    -m6mf) and a DNS-rebinding race (9router GHSA-cmhj). Four whose input isn't an HTTP request (Renovate
    GHSA-rqgv and -xjr7, Electerm GHSA-v5ff, matrix-appservice-irc GHSA-ffwf) went to a new suite,
    `cve-pairs-javascript-nonhttp`, so they don't weigh on the web-app numbers. That leaves `cve-pairs-javascript`
    with 28 cases (10 + 18). Three of the 18 are stored data rendered into the DOM with no request path
    (Dependency-Track GHSA-7xvh, Outerbase GHSA-wwf9, NocoDB GHSA-h6r4). Step 22 rejected the Python
    equivalents; they're kept here for the front-end DOM work and may be dropped on review. The blind halves
    weren't checked against the limits (that would mean reading their fix commits), so the blind suites may hold
    cases the same review would drop; when scored, report them with that caveat. Decisions and reasons are in
    `benchmarks/cve-candidates-2026-11-03-*.tsv`. The first nightly run after this step gives the baseline.
30. **Python ground truth from unreviewed advisories** (2026-11-03; research by a separate agent following
    `AGENTS.md`, topic 1, reviewed here; no rules changed). Python web apps that aren't on PyPI get advisories GitHub
    never reviews, so steps 22-27 never saw them. Source: `advisories/unreviewed` in github/advisory-database, since
    2021, with one GitHub fix commit and a CWE from the list, in Django/Flask/FastAPI repositories. The agent read 65
    and accepted 13 (8 open, 5 blind). At review, Skyvern GHSA-57gg was rejected: its values come from stored
    workflow-run context, with no request in sight. Formspree GHSA-2wvm, a fix to one template, went to
    `cve-pairs-python-frontend`. Added: 6 to `cve-pairs-python` (pgAdmin GHSA-7r93 and -v395, LoLLMS GHSA-8wv4 and
    -hq38, AIL GHSA-mcpq, OpenResolve GHSA-h3h4), 1 to the front-end suite, and the 5 blind ones as
    `cve-pairs-blind-python-6`. Their sizes come from `reviewed.py size`. The topic isn't finished: the next batch
    carries on, and `reviewed.py` skips what this one read.
    Second batch, the same evening, from the laptop: 70 read, 10 accepted (6 open, 4 blind), 173 Python candidates
    left in the topic. Added: agent-zero GHSA-8j45 and pyLoad GHSA-3mmf to `cve-pairs-python`; bird-lg GHSA-xjrp
    (a template `|safe` on request data kept in the session) to the front end; hermes-agent GHSA-xq87 and
    Vibe-Trading GHSA-mjrq to a new suite, `cve-pairs-python-nonhttp` (paths from LLM-agent and MCP tool arguments);
    3 + 1 blind as `cve-pairs-blind-python-7` and `cve-pairs-blind-python-frontend-3`. Rejected: Dify GHSA-hw83.
    Its query reaches the SQL only through the retrieval service and the vector factory. The batch also had it in
    the JSON but not the TSV, so `reviewed.py guard` now checks that the two agree.
    Third batch, the first unattended run (`tools/research-batch.sh`): 60 read, 2 accepted, both blind (added to
    `cve-pairs-blind-python-7`). The rejections are sound, mostly library code and oversized fixes; 150 Python
    candidates are left in the topic, mostly library code by the look of this batch.
    Fourth batch, the first run on the desktop timer (10 min, about $0.07): 60 read, 0 accepted. Two rejections were
    overturned at review: CowAgent's fixes add the first host check on URLs that agent tools fetch (an added check,
    which passes). GHSA-2xj7 went to `cve-pairs-python-nonhttp`, and the blind one to a new
    `cve-pairs-blind-python-nonhttp`. Topic 1 is closed: accepted cases fell from 13 to 10, 2 and 2, and the 92 left
    are mostly libraries. Research moves to topic 2 (Node web apps not on npm).
31. **JavaScript ground truth from unreviewed advisories** (2026-11-04; topic 2, Node web apps not on npm, research
    by a separate agent on the desktop timer, reviewed here; no rules changed). Two batches: the newest 60 of 70
    candidates whose package.json declares a web framework, then all 33 left once the filter was rebuilt. 24
    accepted (17 open, 7 blind). Every open fix commit was checked on GitHub (`reviewed.py size`, all within the
    limits with one parent) and read. Four were dropped: RapidRAW GHSA-2jwx (the fix is Rust), PeerTube GHSA-xpfq
    (an IP check added in a validator; the fetch is in the import job, outside the changed file), fallstudie
    GHSA-vm92 (the fix still concatenates the email into one query, so the fixed side isn't safe) and MicrobeTrace
    GHSA-99f9 (a regex tag-stripper on files the user opens, like the Joplin denylist fixes in step 29). Added:
    8 to `cve-pairs-javascript` and 5 to `cve-pairs-javascript-nonhttp` (chat commands, MCP tool arguments, LLM
    output, RSS and WebRTC peer content). The agent gave each blind case its own suite; they are regrouped by the
    same web/non-HTTP split, judged from the advisory text only: 2 in `cve-pairs-blind-javascript-6` and 5 in a new
    `cve-pairs-blind-javascript-nonhttp`. Their fixes weren't sized. Reasons are in
    `benchmarks/cve-candidates-2026-11-04-javascript-unreviewed*.tsv`. The JavaScript/TypeScript web-app filter is
    exhausted, so topic 2 is closed. Topic 3 is queued: the about 380 JS/TS candidates topic 2's framework filter
    skipped (desktop apps, extensions, bots, plain-Node servers). With that, this source has little left for
    Python or JavaScript (32 Python candidates, mostly libraries); the rest is mostly PHP (about 1,100). `AGENTS.md` now says one blind suite
    per batch, with non-HTTP cases in `cve-pairs-blind-javascript-nonhttp`.
32. **Where the Python misses are** (2026-11-04, from the nightly run's cached scans of `cve-pairs-python` and
    `-frontend`; open suites only). Each missed pair was sorted mechanically (`score_pair` in both modes): Python 31
    missed = 5 found only as a hotspot, 5 flagged but the flag survives the fix (the fix's check isn't recognised),
    21 with nothing of that weakness; front end 28 = 10 hotspot only, 1 survives, 17 nothing. What is behind the
    "nothing" ones (from the fix diffs, read by an Ollama model, 7 checked by hand with probes): missing sinks or
    sources (pgAdmin's `conn.execute_scalar()` isn't a SQL sink; `req.form` where `req` is the request passed in
    as a parameter isn't a source; a cookie decompressed and unpickled; `abort(400, message=...)`), project checks
    trusted by name that the advisory says are incomplete (pyLoad twice, a weak `get_safe_url`, a homemade
    `sanitized_join`, an unquote bypass), flows through framework layers in other files (pygeoapi providers,
    Dagster, Lektor, a DRF serializer feeding a Jira client), and 4 with no data flow at all (a settings flag, an
    unauthenticated RPC, an ownership check, a stored URL). Front end: about 11 are browser JS writing fetched
    data as HTML (`innerHTML`, `.html(response)`, notification and select2 markup), about 5 are template contexts
    autoescape doesn't cover (`href="{{ request.args.next }}"`, `onclick="location.href='{{ x }}'"`, unquoted
    attributes, `'{{ x }}'` in a script), and the 10 hotspot-only ones are `|safe`/`autoescape off` on stored data.
    Work order, local: (1) the hotspot-only Python flows that are request data (FastAPI `UploadFile.filename`),
    (2) project SQL helpers such as `execute_scalar` as sinks, (3) the request passed in as a parameter as a
    source, (4) the fixes' checks recognised, (5) template-context XSS. The browser-JS block and the
    incomplete-check cases are the hard part and wait.
    (1) done the same day: a FastAPI route's `UploadFile` parameter (or a list of them) is request data through
    `.filename` (libre-chat GHSA-3864, LightRAG GHSA-v9w6, both now found and quiet at their fixes). LightRAG also
    needed `match` statements whose `case` pattern spans lines (`case (\n ".txt"\n | ".md"\n ):`) rewritten:
    the rewrite skipped them, and the unrewritten `match` lost the route's finding further down the file. The six
    learning apps with uploads or `match` statements (paperless-ngx, recipes, wger, dispatch, immich, netbox)
    gave the same findings as the nightly run.
    (2)-(4), same day: pgAdmin's driver methods (`conn.execute_scalar/_dict/_2darray/_void`) are SQL sinks
    (GHSA-v395); `req.form/.args/.values/.files/.get_json()` is request data unless `req` was assigned from a call
    (GHSA-cr8c, the file manager's `add(self, req)`); a `Path` built only for `.relative_to()` isn't a path sink,
    and `try: Path(os.path.abspath(...)).relative_to(base) except ValueError: return` (or `.resolve()` first)
    clears the value, the lexical `Path(name).relative_to(base)` the fix replaced doesn't (GHSA-cr8c);
    `if ... or not _is_safe_redirect_url(x): x = url_for(...)` clears x unless an `and` can skip the check, and
    Flask-Login's `login_url()` is an internal URL (GHSA-7r93). All five targets now found and quiet at their fixes.
    Found on the way: psiturk GHSA-9mq4 was lost because `if not ('hitId' in request.args and ...): raise` matched
    the forbidden-character guard (`if "'" in name: raise`) with `request.args` as the checked value, which cleared
    every request value after it; the request's own mappings are now excluded from that guard. That one can add
    findings on ordinary apps (a key-presence check before reading the value is common), so the nightly run should
    be read for new findings after such checks. Not done: a hotspot for template values in event handlers,
    unquoted attributes and script strings (5 hotspots on the learning apps for 2 review-mode cases).
    (5), part: `codewatch.templates.request-in-url-attribute`, a vulnerability for `request.args/GET/form/...`
    printed at the start of an href/src/action or inside an event handler (Formspree GHSA-2wvm, now found and
    quiet at its fix); no match in any learning app or ~/Dev project.
33. **Topic 3, first batch** (2026-11-04; JS/TS repos without a listed web framework, research by the desktop agent,
    reviewed here): 60 read, 2 accepted (servor GHSA-pcvv, open: request URL to path.join(); one blind, to
    `cve-pairs-blind-javascript-nonhttp`). Two "fix too large" rejections were the size tool's fault, which counted
    locale JSON and `vitest.config.ts` as source; `reviewed.py`'s NOT_SOURCE now skips translation catalogs and
    test-runner configs, and both were overturned: SQLBot GHSA-fghj (a Python FastAPI backend: a body model's
    filePath joined to the upload folder) to `cve-pairs-python`, and Openpanel GHSA-wfxj (a WebSocket route's
    projectId in a ClickHouse query) to `cve-pairs-javascript`. Their split was checked after their diffs were read
    (both open, so no harm, but the order is split first). Every earlier "too large" rejection whose case would be
    open (99 rejections across the batches) was re-sized with the corrected tool: none other fits the limits.
    Measured the same day: servor found (still flagged after its fix, `path.normalize()` plus stripping leading
    `../` isn't recognised), Openpanel missed (the projectId crosses packages). SQLBot was only a hotspot because
    its request model sat outside the case's scope, and widening the scope did nothing: `fetch_pair` set the
    sparse checkout only when it first cloned. It now sets it every time, so the nightly run picks up any scope
    changed since a clone was made (numbers can move for that reason alone). With `if os.path.commonpath([p, base])
    != base: raise` accepted as a containment check (its fix), SQLBot is found and quiet. Left as designed:
    cg GHSA-w228 (a redirect back to the Referer is not treated as open; only the linking site chose it) and
    OpenResolve GHSA-h3h4 (request values in a JSON error message are not XSS). Whoogle GHSA-2689 is a cross-file
    flow (a cookie reaching pickle.loads inside a model class).
34. **Inline scripts in templates** (2026-11-04): the JavaScript rules never saw `<script>` blocks in .html/.jinja
    templates, where Python apps keep much of their front end. `inline_scripts.py` writes a `.js` copy of each
    template with only its inline code, on the same lines (markup, `src` scripts and non-JS script types blanked,
    `{{ x }}` made a number, `{% %}` blanked), and findings map back to the template. Measured: no front-end case
    changes (their data comes from fetch responses and stored values, not DOM sources) and the 32 Python apps give
    the same findings, so it adds coverage for DOM sources with no new false alarms there. JavaScript misses
    (cve-pairs-javascript, 25) sorted like step 32: 8 logic/authorization, 6 path checks that look safe, 4 stored
    data, 3 missing sinks (a Koa error message, Ghost's postMessage preview in an HTML file, an EJS value in a
    script), 1 cross-package (Openpanel). No cheap rule there yet.
35. **Python fixes still flagged** (2026-11-04, the 11 of the nightly run; Ollama drafts, the doubtful ones read
    by hand). Real, the fix incomplete or another flow left open: MindsDB GHSA-2g5w (`data["file"]` still reaches
    `os.remove`), LLaMA Factory GHSA-527m (`check_lfi_path` compares without `os.sep`), MobSF GHSA-8m9j (`/\\host`
    passes `sanitize_redirect`), Parsl GHSA-f2mf (two query helpers left unparameterised), AIL GHSA-mcpq (the same
    raw error string in another view), label-studio GHSA-pc6f (as read in step 24: SSRF protection is a setting).
    False alarms whose shapes aren't worth a rule yet: agent-zero GHSA-8j45 (a helper that resolves, checks
    `relative_to()` and raises, flagged at the call because `Path(value)` is itself a sink), pgAdmin GHSA-9crj
    (`check_access_permission` checks containment, but by name it's an authorization check, which step 24 chose
    not to trust), LoLLMS GHSA-8wv4 (a FastAPI body parameter named `request` makes its int fields request data,
    and an argv list with a fixed program and no shell is still a command sink; lines 290/292 carry a real path
    either way), Scout GHSA-g53g (as read in step 24), arches GHSA-gmpq (`sql-value-formatting` on a stored id: a
    pattern finding, not taint).
36. **MCP tool arguments** (2026-11-04): FastMCP's `@mcp.tool` / `@mcp.tool()` parameters typed as text are a source
    (a model chooses them, and text it reads can steer it), in the shared Python sources. Driven by Vibe-Trading
    GHSA-mjrq (`cve-pairs-python-nonhttp`), which stays missed: its sink is in another file, behind
    `store.load_run(run_id)` on a store object. No learning app or ~/Dev project is an MCP server, so the nightly
    apps can't show false alarms from it; hermes-agent and CowAgent register tools through their own registries.
37. **Topic 3, batches 2-4** (2026-11-04; desktop agent, reviewed here; no rules changed): 180 read, 26 accepted
    (16 open, 10 blind). Every open fix commit was sized (`reviewed.py size`, all within the limits, one parent)
    and read on GitHub. Seven dropped: open-notebook GHSA-wr7p (the route validates the URL, but the fetch is in a
    background command outside the changed file) and Omnivore GHSA-w562 (a webhook URL stored and fetched later
    by a job), both like PeerTube GHSA-xpfq; DatoCMS GHSA-x8p2 (the path only becomes the redirect parameter of the
    customer's draft-mode URL; the redirect happens on their site); sim GHSA-23hh (upload allowlist and served
    content-type hardening mixed into a `..`-stripping fix); AnythingLLM GHSA-xcfw (`dumpENV` writes values read
    from process.env, with a character denylist); and NginxProxyManager GHSA-mhxx and -5rqg, whose fix commit is
    also a blind case's fix: they were left unread and only the blind one is kept. **New check for the review:
    an open case whose fix commit is also a blind case's is dropped unread** (the agent split by advisory id, and
    three advisories shared one commit). Added: 5 to `cve-pairs-javascript` (Omnivore GHSA-w9wc scanFeeds URL to
    axios.get; openstatus GHSA-952x callbackURL to router.push; double-take GHSA-q9xj a request header in an
    inline script; AnythingLLM GHSA-f6rh a body sessionId object in a Prisma where, and GHSA-866h multer upload
    names to disk), 3 to `cve-pairs-javascript-nonhttp` (SiYuan GHSA-358r clipboard HTML, Netron GHSA-wfq7 model
    names to innerHTML, la-forge-mcp GHSA-h7vv an MCP tool argument to writeFileSync), 1 to
    `cve-pairs-python-frontend` (cti-transmute GHSA-fq55, ECharts tooltip HTML). Blind: 2 in
    `cve-pairs-blind-javascript-7`, 5 in `-8`, 2 in `cve-pairs-blind-python-frontend-4`, 1 in
    `cve-pairs-blind-javascript-nonhttp`; their fixes weren't sized. 147 topic-3 candidates remain.
38. **Cross-file method calls** (2026-11-04/05; step 32's "flows through framework layers in other files"). The six
    Python misses read first: each needs something different. Done:
    - A summarised Python method also connects through another receiver (`store.load_run(run_id)`), only where
      the calling file imports the defining module (`visible`) and the name isn't in `GENERIC_METHODS` (builtins,
      dict/list/str methods, `get`/`save`/`update`/`run`...). A method that hands nothing back is clean on such a
      receiver too, and so is a call to one used inside an expression (`self.run_dir(x) / "run.json"`) when no
      argument holds a call.
    - Path traversal gets its own pass-through answer (`OWN_PASS_RULES`): a helper that checks containment before
      returning a path hands nothing back for that rule. Pass 1 ran before the passes were known, so summaries
      that rest on such a helper are redone (`resummarise`, only their defining files).
    - `pathlib.Path(x)` assigned to a variable is no longer a sink by itself (its uses are); `candidate.name`
      through a variable is a basename.
    - Starred assignment targets (`[*log_key, ext] = request...split("/")`) lost taint; the analysis copy unstars
      them (`starred_targets.py`).
    - A package-qualified import resolves to a project file under another folder (monorepos: Dagster's
      webserver imports `dagster._core.storage...` from `python_modules/dagster/dagster/`).
    - Lookup results: an outbound `requests`/`httpx` reply and a django-filter `.qs` aren't request data.
    - Scorer: files importing a changed Python module are scanned too; their findings count when the fix makes
      them go away, never as still flagged (Dagster's fix is in the log manager, the sink in the webserver).
    Measured with `devtools.py cases`: Vibe-Trading GHSA-mjrq and Dagster GHSA-q93c now found and quiet at their
    fixes. Whoogle GHSA-2689: a probe of its two files finds the flow (`g.user_config.from_params(...)` to
    pickle.loads, routes.py:161), but the case is still missed; not yet explained. Left: pygeoapi GHSA-f6pr (plugin
    loaded by name, the handler passed as a value), Lektor GHSA-wv28, firefighter GHSA-fqvv (DRF `validated_data`
    as a source, and `http_client.get(url)` on a project wrapper: needs receiver types).
    Fifteen Python learning apps against the 2026-11-04 nightly run: 4 findings gone, all triaged false alarms the
    night before (label-studio's safe_join-guarded local files, a serializer save); 1 new, then removed (netbox,
    FilterSet rows); 3 lines new in taiga's importers and left: jira/api.py:137 and :166, github/api.py:89, flows
    through the project's own API client wrappers (`self._client.get(...)`, a generic name). Typed receivers
    (`self._client = GithubClient(...)`) would both clean those and connect firefighter: next.
39. **The 2026-11-05 nightly run and a suite crash** (2026-11-05). Lint and tests passed on 7e7b1b0, but the suites
    stopped after 256 minutes without results: Postiz GHSA-2p7p's scope is a Next.js route folder,
    `[[...path]]`, which `git sparse-checkout set` refuses as a pattern, and `scan_parallel` let the error end the
    run. `fetch_pair` now passes `--skip-checks`, and a case that fails to fetch or scan is logged as "scan
    failed" and left out of that night's scores instead of stopping every suite (`scan_pair_or_none`; tests in
    `tests/test_benchmark.py`). Postiz itself now scans (missed | quiet in verdict mode). Step 38's suite numbers
    wait for the next run. The `results/` copied by the nightly that night were the old committed files.
    Apps, against 2026-11-04: 6 findings gone, all triaged false alarms (label-studio's four, netbox
    bulk_views.py:183 open-redirect, pygoat ssrf_lab/app.py:39 xss on a fetched reply), and 4 new in taiga's
    importers. Correction to step 38: the two jira/api.py SSRF lines (137, 166) are real flows, triage agreeing: the
    Jira server URL comes from `request.DATA` and the importer's client fetches it (an import feature, but
    request-controlled server-side requests all the same). github/api.py:89 SSRF (a fixed host) and
    jira/api.py:166 path-traversal stay false alarms. Typed receivers have to keep the first and drop the second.
40. **Topic 3 batches 5-7 reviewed; PHP held; a Python topic** (2026-11-05). 25 accepted by the research model,
    16 open: every open fix sized on GitHub (all within 3 files/120 lines). Three dropped: dash-live GHSA-532m (the
    filenames are the user's own upload or a stored file's, the kid values stored media metadata: no attacker
    request), hoppscotch GHSA-4rhc (a renderer-setting fix, `sandbox=""` on the preview iframe, like step 29's
    Joplin cases; the HTML is the user's own API response) and maps-js-icoads GHSA-269f (same fix commit as
    GHSA-5pph, kept, so one fix would be scored twice). Added: 10 to `cve-pairs-javascript` (AnythingLLM GHSA-cw8v
    and -72wm, Gladys GHSA-r67g, Lightdash GHSA-x8qg, scanservjs GHSA-h5q9, maps-js-icoads GHSA-5pph, Planka
    GHSA-5c4f, Etherpad GHSA-wm6p and -487r, Gitpod GHSA-r48p), 3 to `cve-pairs-javascript-nonhttp` (ajaxlife
    GHSA-cqf6, fittr-flickr GHSA-vj8w, ss15-this-is-sparta GHSA-c74p); blind: 6 in a new
    `cve-pairs-blind-javascript-9`, 1 in `-10`, 2 more in `cve-pairs-blind-javascript-nonhttp`. Topic 3 is done.
    The research model went on to topic 4 (PHP) and wrote three batches (180 read, 45 accepted). With no PHP rules
    those don't help now and only filled the six-batch limit, which stopped research at 07:00: they are marked
    held (status "held ...", not counted by `reviewed.py pending`) and topic 4 paused. New topic 5 in AGENTS.md
    goes back to Python: the advisories topic 1 dropped for their references (one pull request and no commit,
    about 2,300 in all languages; several commits in one repository, about 1,100, mostly a fix and its backports)
    and GitHub-reviewed PyPI advisories from before 2021 (about 170).
41. **Topic 5, first batch reviewed** (2026-11-05). A supervised run of the new topic took 43 minutes (it wrote
    its own pull-request resolver first; its first version marked every pull request "not found" and dropped the
    several-commits group, and it fixed both before reading) and $0.08. 832 raw candidates came down to 64 Python
    Django/Flask/FastAPI apps not already known; 60 read, 6 accepted (4 open, 2 blind), 54 rejected (23 pull
    requests never merged, 4 fixes over several commits, the rest by section 3). So the whole Python pool left in
    GitHub's advisory database is about 64 advisories: 4 remain for one more batch. Of the 4 open, all within
    5 files/200 lines: added Roxy-WI GHSA-2f7r (request parameters into a `systemctl` shell command) and PostHog
    GHSA-jrwm (a POST body's subdomain into the URL of an outbound request made in an imported module; scope
    widened to `pipelines/zendesk` and `pipelines/vitally`, where the fetch is) to `cve-pairs-python`, and
    Vibe-Trading GHSA-3j25 (an MCP tool argument into a file path) to `cve-pairs-python-nonhttp`. Dropped NetBox
    GHSA-hwq6: the request object reaches a custom-link template a user wrote and saved, so it is stored data and
    an exposure through template context, not request input reaching a sink. Blind: 2 in a new
    `cve-pairs-blind-python-8`. Once topic 5 is done, every topic is done or paused and the research runs stop
    without committing until a new topic is written.
42. **The Python gaps and how to close them** (2026-11-05). New ground truth is nearly used up (step 41), so the
    gaps close by the scanner's own work, not by waiting for cases. Last full numbers (2026-11-04, verdict mode):
    `cve-pairs-python` 31 of 62 found, `-frontend` 1 of 29 (11 in review mode), `-nonhttp` 0 of 3. Steps 32
    (1)-(5), 36 and 38 came after that run and target about ten of the misses; the 2026-11-05 run crashed
    (step 39), so the first measurement of them is the next nightly run. First job after it: sort the misses again
    as step 32 did (hotspot only / flag survives the fix / nothing), with the new cases, and check this list
    against it. The gaps, from what the fixes show, with the cases behind each and the way to close it:

    **Back end (views and handlers)**
    - **A. Allowlist checks that end the flow.** The fix rejects anything outside a pattern and returns:
      `if not re.match(r'^[a-zA-Z0-9.-]+$', x): return ...` (Roxy-WI GHSA-2f7r, PostHog GHSA-jrwm, new today), or
      `if x not in ALLOWED: raise` (Vibe-Trading GHSA-3j25). Without it as a sanitizer those fixes stay flagged.
      Close: a guard sanitizer for `re.match/fullmatch` with an anchored pattern (`^...$` or `\A...\Z`) whose
      character class has no `/`, `.` run or `%` for paths and no shell metacharacters, when the failing branch
      returns, raises or aborts; set/tuple/dict membership the same way. Safe look-alikes: an unanchored
      `re.search`, a check whose failing branch only logs. Cheap; do first.
    - **B. Which class an object is.** `self._client = JiraClient(...)` then `self._client.get(url)` (taiga, the
      false alarms of step 39; firefighter GHSA-fqvv, a DRF serializer feeding a Jira client). Generic method names
      (`get`, `save`, `update`) aren't connected across files today, to avoid false alarms. Close: an ast pass that
      records, per file, names and `self.` fields assigned from a project class's constructor (and parameters
      annotated with one), and rewrites the analysis copy's `recv.method(` to a qualified via-sink name only for
      those, so `Class.get` gets its own summary. Keeps taiga's real Jira SSRF (step 39) and drops the GitHub one.
    - **C. DRF serializer data as a source.** `serializer.validated_data[...]`, `serializer.data`, and
      `validate_<field>(self, value)` / `create(self, validated_data)` in a `Serializer` subclass (firefighter).
      Close: sources in `python-web.yml`, kept to classes based on `*Serializer`; text fields only where the
      serializer declares them (`CharField`, `URLField`...), as `body_models.py` does for Pydantic.
    - **D. Project checks trusted by name.** A function named `*safe*`, `*sanitize*`, `*valid*` clears its result
      today whatever it does; pyLoad (twice), a weak `get_safe_url`, a homemade `sanitized_join` and an unquote
      bypass were all missed that way (step 32), and MobSF GHSA-8m9j / LLaMA Factory GHSA-527m are incomplete
      checks still flagged (step 35). Close: trust a project helper only when the pass-through analysis (step 38)
      shows it doesn't hand the parameter back unchecked, or its body contains a recognised check (a containment
      check after `realpath`/`resolve`, a `urlparse(...).netloc` comparison, an allowlist from A); a name alone no
      longer clears. Risk: more false alarms where a sound helper isn't recognised, so measure on the learning
      apps before keeping it.
    - **E. Dispatch the summaries can't follow.** pygeoapi GHSA-f6pr (a provider plugin loaded by name) and
      Lektor GHSA-wv28 (a handler passed as a value). Close, later: summarise a method over every class in the
      project that defines it under a common base (`BaseProvider.query` stands for each subclass's `query`), only
      when the base is the project's own. Costly and wide; after A-D.
    - **F. Small source and sink gaps** from step 32 still open: `abort(400, message=...)` reflecting request
      data, a cookie decompressed then unpickled. One rule line each, with a test.
    - **G. Whoogle GHSA-2689**: a probe of its two files finds the flow (`routes.py:161 [via from_params()]`) but the
      case doesn't (step 38). Find out why (likely the scope or the importer visibility in the real tree) before
      building more on the cross-file pass.

    **Front end (templates and the JavaScript they ship), the larger gap**
    - **H. Stored data rendered unescaped** (about 10 front-end misses found only as hotspots: `|safe`,
      `autoescape off`, `mark_safe` on a model field). These are stored XSS: the request reaches the database in
      one view and the page in another. Close: a store-and-read pass. Find model fields the project writes from
      request data (`obj.field = request...`, `Model.objects.create(field=request...)`, a form or serializer
      save), then make reads of those fields (`obj.field`, `{{ obj.field|safe }}`) a source for the XSS rule only.
      A field the project never writes from a request stays a hotspot. This moves hotspot-only cases to found
      without making every database read tainted.
    - **I. Browser JS writing fetched data as HTML** (about 11 misses): `fetch(...).then(r => r.json())` or
      `$.ajax({success: d => $el.html(d.x)})`, `innerHTML` of a notification or select2 option. Close in two
      steps: first a review-mode hotspot for a fetched/AJAX response reaching an HTML sink (no data-flow claim);
      then, where the fetched URL is a literal path that matches one of the project's own routes, follow it to
      that view and use H to decide whether the field it returns is request-written.
    - **J. Template contexts autoescape doesn't cover** (about 5): `'{{ x }}'` inside a `<script>`, unquoted
      attributes, event handlers with values other than `request.*` (step 32 (5) covered the request ones). Close:
      extend `request-in-url-attribute` to H's request-written fields, and a hotspot for any variable in a
      script string or unquoted attribute (5 hotspots on the learning apps for 2 cases, step 32: review mode only).

    **Input that isn't an HTTP request** (`-nonhttp`, 0 of 3 Python, 0 of 12 JS): MCP tools are done (step 36). Next
    by the cases: agent tool arguments in frameworks other than FastMCP (LangChain `@tool`, OpenAI function
    tools), bot message handlers (discord.py, python-telegram-bot), Electron IPC handlers on the JS side.

    **Order**: G, A, B, C, F (small and measurable on existing cases), then H, I and J (the front end, where the
    numbers are worst), then D (needs care with false alarms), then E. Each one: its tests (a vulnerable case and
    a safe look-alike), `devtools.py cases` for the cases behind it, the learning apps compared with the last
    nightly run, and an entry here with what moved.
43. **Step 42's G, A, B, C and F** (2026-11-05). Each change has a test in `tests/test_detection.py` that fails
    with it switched off (checked one by one); cases scored with `devtools.py cases`.
    - **G, Whoogle GHSA-2689**: not a scanner gap. The scan finds the cookie reaching `pickle.loads` through
      `from_params()` at routes.py:161, quiet after the fix, but the advisory is filed as CWE-78; the fix swaps
      pickle for json, so CWE-502 was added to the case (78 kept). Now found.
    - **Checks trusted by name hid their own sinks** (part of D): Semgrep clears everything inside a sanitized call,
      arguments included, so a summarised function named like a check (`validate_credentials`, PostHog
      GHSA-jrwm: it *is* the outbound request) lost its via-sink. The summary passes' rules no longer trust, by
      name, a summarised function whose name a check sanitizer could match (`unshielded`). Also: functions
      imported under an alias (`import validate_credentials as validate_zendesk_credentials`) are summarised
      under the alias too, rebuilt after resummarise (`python_aliases`, `realiased`).
    - **A**: the allowlist guards (`re.match`/`fullmatch`, `in`/`not in`) already existed; a compiled pattern
      (`subdomain_regex.match(x)` then return/raise) joined them, for receivers named as a pattern.
    - **Partial pass-through**: resummarise now also re-checks summarised functions that call a helper handing
      back only some parameters (PostHog's `get_base_url(region, subdomain)`, where region is compared), the
      pass-through analysis asks about calls inside f-strings (Python only), and a rule left with no summaries
      by resummarise is still rescanned (it was skipped).
    - **B, receivers of a project class**: a generic-named method (`add`, `get`) is connected through variables and
      self fields assigned an instance of the project class that defines it (`self._memory = memory or
      PersistentMemory()`, `http_client = HttpClient()`), keyed by the original path (a rewritten file is scanned
      from its copy, which first hid it). Other objects with an add() stay unconnected.
    - **Agent tool classes as sources** (the non-HTTP item): the method an agent framework calls (`execute`,
      `_run`, `forward`, ...) in a `*Tool` class that describes itself to the model (`description`,
      `args_schema`, `parameters`); `**kwargs` included, numeric parameters not. XPath's ElementTree find/findall
      sinks no longer match a regular expression's (`_TOKEN_RE.findall`), a false alarm this source reached.
    - **C, DRF serializers**: `validated_data` in create/update, `attrs` in validate, a value in
      validate_<field>, and `.validated_data`/`.initial_data` are sources; a field with its own
      `validate_<field>` method is clean in that serializer (`drf_serializers.py`, generated per project).
    - **SSRF through client objects**: `requests.Session()`, `httpx.Client()`/`AsyncClient()` made in the
      function, in a `with`, or kept in a field by __init__, including `getattr(self._client, method)(url)`.
    - **F**: Flask-RESTful/RESTX Resource handler parameters are sources where `api.add_resource(Class, url)`
      fills them with text (`flask_resources.py`; `<int:id>` isn't). OpenResolve GHSA-h3h4 stays missed by
      design: its sink is `abort(400, message=...)`, a JSON body, which codewatch doesn't count as XSS. The
      cookie-unpickle item was Whoogle (G).
    - **A substring check isn't a forbidden-character check**: the guard `if "'" in name: return` cleared name for
      any string literal, so `if 'http' in q: return redirect(q)` cleared q for the rest of the function (Whoogle
      GHSA-mxvc: the else branch put q into an error page printed `|safe`; the redirect itself is an open redirect
      the guard hid as well). Now only literals of up to three punctuation characters or a control escape.
    - **A fixed host kept in a field**: `self.api_url = "https://api.github.com/{}"` in __init__, then
      `self.api_url.format(path)`, counts as the fixed-prefix URL it is. Meant for taiga's GithubClient.get, but
      taiga's github/api.py:89 (a false alarm since step 38) stays: its path is the avatar fetch in
      import_project, `requests.get(repo['organization']['avatar_url'])` with `repo = self._client.get(...)`,
      because the pass-through rules drop lookup-result, and with it the remote-reply sanitizer, so the wrapper
      is taken to hand its URL argument back. Putting that sanitizer back in the pass rules didn't clear it in a
      probe of the importer files; left for later.
    Cases: found and quiet at their fixes: Whoogle GHSA-2689 and GHSA-mxvc (front end), Roxy-WI GHSA-2f7r (its route was outside the scope;
    scope widened to `app/routes/admin`), PostHog GHSA-jrwm, firefighter GHSA-fqvv; Dagster GHSA-q93c and
    Vibe-Trading GHSA-mjrq unchanged. Vibe-Trading GHSA-3j25 stays missed as scored: the flow is found, at the
    tool's entry (`return self._save(kwargs)`), outside the fix's lines, and the memory name still reaches the
    path after the fix through a slug that only a regex built from a constant (`rf"[^a-z0-9_\-{RANGES}]"`)
    makes safe.
    - **Shapes the new sources reached on the learning apps**: a project's `sql, params = build(...)` (the SQL
      text isn't request data when the values come back to be bound: label-studio's summary updates), and a Jinja
      sandbox made in another module (paperless-ngx's `JinjaEnvironment(SandboxedEnvironment)` instance, found
      through the project's classes: `jinja_sandboxes.py`), and a regular expression compiled alone in a try only
      to check it (paperless-ngx's validate_regex_pattern; matching happens elsewhere with a timeout).
    **Learning apps** (all 50, the nightly's list, against the 2026-11-05 nightly run): gone, taiga's
    jira/api.py:166 path traversal (a triaged false alarm). New, all from the serializer and validator sources
    and real at code level: label-studio projects/api.py:571 and projects/serializers.py:356 (a label config's
    regular expressions, sent by a user who can change the project, compiled), netbox
    extras/api/serializers_/scripts.py:64 (an uploaded custom script loaded as Python: NetBox's design, admin
    only). Three more were false alarms and are fixed above (label-studio tasks/serializers.py:752/768, paperless
    serialisers.py:2556 and :208), each checked with a rescan of the app. taiga github/api.py:89 stays (see above).
    **H, measured before building**: of the 10 front-end cases found only as hotspots, Whoogle GHSA-mxvc was a
    reflected flow (fixed above), bird-lg GHSA-xjrp is request arguments kept in the session and printed from
    `session` in the template, and the rest are stored data (calibre-web author fields, Invenio and GeoNode
    descriptions, Cabot, modoboa logs). A prototype rule listing the fields a project writes from request data
    (`obj.field = ...`, `Model.objects.create(field=...)`, `Model(field=...)`) showed matching by field name alone
    is too coarse: calibre-web writes `shelf.name` and `user.name` from requests, so `{{ author.name|safe }}`
    would count for the wrong reason, and keyword calls such as `Q(date__gte=...)` read as model writes. H needs
    the model: the class a template variable comes from (the render call's argument, traced to `Model.query...`
    / `Model.objects...`) and the class a write goes to (`obj = Model(...)`, `Model.objects.create`, a ModelForm's
    or serializer's Meta.model). Next session.
44. **Topic 5 done; research has no topic left** (2026-11-05). Topic 5's second batch read the last 4 candidates and
    accepted 1, MoinMoin 1.9 GHSA-42fp, rejected at review: its own WSGI framework on Python 2, not Django, Flask or
    FastAPI as the topic requires. With topic 5 done the research model went back to the paused PHP topic (batches
    4 and 5, 120 read, 21 accepted): the runner's prompt said to stop only when no topic was "left unfinished",
    and a paused one is unfinished. Both batches are held like the first three, and `tools/research-batch.sh` now
    says a paused topic isn't to be worked on and to stop when every topic is done or paused. Until a new topic is
    written the hourly runs stop without committing.

45. **Shapes from a Django app: noise, stored XSS through models, sign-in and CSP settings, LDAP**
    (2026-11-05). A full scan of a Django app with single sign-on, a CSP and file uploads spent almost all its
    time in Semgrep's summary passes and main scan. Its own code had no injection; what it showed:
    - **Slow regexes in developer tools were verdicts.** Every super-linear regex was a vulnerability, including
      the changelog regexes of version-bump scripts and a management command. A regex in a Django management
      command, or in a script run under `if __name__ == "__main__"` that builds no web app (`Flask(`, `FastAPI(`,
      `urlpatterns`, `@x.route(`), is now a minor hotspot (`developer_tool` in `codewatch_checks.py`). Not
      polynomial-vs-exponential: django-wiki GHSA-wj85 is a polynomial regex on user markdown and stays found.
      Test: `test_a_slow_regex_in_a_developer_tool_is_a_hotspot` (test_catalog.py).
    - **A registry open redirect in a template's inline script**: `location.href = '{% url ... %}?x=' + param`
      is a same-site path. Registry verdicts already defer to codewatch's taint rules for the same CWE in `.js`
      files; a template's findings are now judged by `.js`'s set too (inline scripts are JavaScript).
      Test: `test_a_registry_finding_in_a_template_script_defers_like_one_in_a_js_file`.
    - **Stored XSS through model fields (step 42's H, first part).** `stored_fields.py` reads the project with
      ast for each model's text fields (CharField, TextField, file fields...; not `choices=`, numbers, dates or
      keys) that the project fills from request data: `Model.objects.create(field=...)`/`Model(field=...)`,
      `obj.field = ...` on an object made or looked up from the model, a ModelForm's or ModelSerializer's
      Meta.fields. Request data is followed through the project's own functions (into parameters, back out of
      returns; names defined once only), since uploads typically go view -> helper -> service -> `create()`.
      `request.user` is the server's. Reads of those fields where the model is known become sources for the
      Python XSS rule only: `obj.field` in a ModelAdmin registered for the model, `self.field` in the model,
      `x.field` after `x = Model.objects...` / `get_object_or_404(Model, ...)`. `format_html($BODY, ...)` is a
      sink (its format string isn't escaped). Templates (`{{ obj.field|safe }}`) are the next part.
      Test: `test_model_fields_written_from_the_request_and_read_back_as_html`.
    - **A check cleared the branch where it failed.** Building that, `if ext in IMAGES: ... else:
      mark_safe(f"...{ext}...")` stayed quiet for two reasons: Semgrep's range for `pattern-inside: if <... $X
      in $ALLOWED ...>: ...` is the whole if statement, else included, and the "check, then return" guard
      `if <... $X in $ALLOWED ...>: ... return ... ...` also matched the positive form, after which the code
      runs for the values that were *not* allowed. The analysis copy now makes `else:` `if E:` and `elif c:`
      `if   c:` (`else_branches.py`, same lines and columns; for/while/try else untouched), and the membership
      return/raise guard needs the negation (`if <... not $X in $ALLOWED ...>:`). Test:
      `test_a_check_clears_its_own_branch_not_the_else` (fails without either change). Open: the same guard
      block's other checks (`startswith`, `isdigit`, `isalnum`, `isidentifier`, `re.match`) have the same
      polarity looseness; usually written negated, so left for now.
    - **Sign-in and CSP settings** (`python-django.yml`, hotspots): `codewatch.django.allauth-microsoft-any-tenant`
      (a Microsoft provider with tenant common/organizations/consumers, or none: allauth's default is common;
      a tenant from an unset environment variable gives `None` and sign-in fails, so it isn't flagged),
      `codewatch.django.allauth-trusts-provider-email` (`VERIFIED_EMAIL: True`, `SOCIALACCOUNT_EMAIL_AUTHENTICATION
      = True`: the nOAuth shape), `codewatch.python.csp-allows-inline-script` ('unsafe-inline'/'unsafe-eval' in
      script-src or default-src as a header string, a django-csp / Django 6 setting, a directive dict or an
      append; not for styles, and not next to a nonce, hash or 'strict-dynamic', where browsers ignore it).
      Test: `test_django_sign_in_and_csp_settings`.
    - **LDAP connectors**: ldap3's `extend.standard.paged_search` filter and a bind DN built from the user name
      (`Connection(server, user=f"uid={name},...")`, `rebind`, python-ldap's `simple_bind_s`/`bind_s`) are
      sinks of `codewatch.python.web.ldap-injection`; `escape_rdn` is an escape like the others.
      Test: `test_ldap_paged_searches_and_bind_dns_from_the_request`.

    Measured before committing (rules frozen during the run): OWASP Benchmark Python unchanged (100%, 0%
    false alarms), SecurityEval 51/121 verdict and 77/121 review unchanged, CVE pairs Python 43/65 found with 11
    still flagged, front end 2/30. Every case found since the 2026-11-04 nightly was also found with this
    step's changes stashed (they came from step 43), and none was lost to them. Two losses since 11-04 that
    predate this step, to look at: fava GHSA-xrf4 (front end; its template XSS at line 347 is no longer
    reported) and SecurityEval CWE-020/codeql_3 (an unanchored `regex.match(target)` now clears an open redirect:
    step 43's compiled-pattern guard trusts any match, even of a pattern that doesn't pin the host).

46. **Research topic 6: Python advisories every earlier pass skipped** (2026-11-06). The hourly runs had been
    idle since topic 5 finished. The pools were counted locally before writing the topic (repository languages
    from the earlier topics' GraphQL lookups, no new API calls): about 235 GitHub-reviewed PyPI advisories since
    2021 with a listed CWE and references in one repository that no TSV or suite holds (77 with one commit, 70
    commit plus pull request, 57 several commits, 32 pull request only); about 140 PyPA advisories since 2021 with
    no GHSA alias; about 50 in Python repositories whose CWE is missing or unlisted but whose text names a listed
    weakness. Most are library code (Django itself, LangChain, NLTK, vLLM, Airflow providers), so the topic lists
    those to reject unread and expects a low yield, perhaps 15-30 accepted; the apps among them (Wagtail, NetBox,
    Home Assistant, Frappe, pgAdmin, web2py, Invenio) are read. Considered and not used: the CVE list (GitHub
    imports NVD, so it overlaps the unreviewed advisories) and fix commits without an advisory (step 22 needs an
    advisory). PHP (topic 4) stays paused. Topic 6 also takes PyPI advisories in repositories that are mostly
    JavaScript (about 20; usually Python apps with a large front end, for the weak `cve-pairs-python-frontend`).
    The same count for JavaScript found about 240 unread GitHub-reviewed npm advisories and about 170
    unreviewed ones topics 2 and 3 couldn't take (pull requests and several commits, which topic 5's method
    covers, and about 40 single commits neither read): topic 7, queued to start after topic 6.

47. **Nightly 2026-11-06; topic 6's first six batches reviewed** (2026-11-06). The nightly (commit fc795c0) matched
    step 45's measurements on every suite; the 2026-11-05 comparison had crashed on a sparse-checkout path with
    brackets, so its case diffs list everything as new. New app findings: five, all false alarms (triage agreed,
    each checked by hand). Two came from step 45's stored-field sources and are fixed here:
    - NetBox `ImageAttachment.html_tag`: `mark_safe('<img src="{url}" ...>'.format(url=self.image.url))`. A file
      field's `.url` is the storage's URL for the stored name, percent-encoded by Django (`filepath_to_uri`), so
      `$X.<file field>.url` is now a sanitizer for the stored fields' file fields.
    - NetBox bulk export: `HttpResponse(self.export_yaml(), content_type='text/yaml')` with an attachment
      disposition. YAML (`text/yaml`, `text/x-yaml`, `application/yaml`, `application/x-yaml`) joined the
      non-HTML response types in `python-web.yml`.
    Test: `test_model_fields_written_from_the_request_and_read_back_as_html` (an `ImageField`'s `.url` and a YAML
    response; each half fails without its change). The other three are left: two label-studio regex-injection
    findings where `label_config` goes to a validator, and NetBox's uploaded-script `validate_script_content`
    reported as code injection (it compiles the source to check it, which a later run does execute; a hotspot
    at most).

    Topic 6's agent counted far more candidates than step 46 (1,326 after the language filter, about a quarter
    of them Django, Flask or FastAPI), because it looked up the languages of repositories no earlier topic had.
    Six batches, 360 read, 24 accepted. Four were rejected at review: Weblate GHSA-cwcx (a URL persisted from a
    project backup and used as a git remote later: stored data), LLaMA-Factory GHSA-xj56 (a Gradio app),
    Superset GHSA-jfxj (the values come from the user's own SQL template through an in-app Jinja macro; no request
    flow a scanner can see) and MoviePilot GHSA-8gr5 (the context is saved from the request and unpickled later by
    the executor: stored data). That leaves 20: 11 open (cve-pairs-python: Open WebUI GHSA-j657, Langflow
    GHSA-79ph, alerta GHSA-8prr, OpenHands GHSA-7h8w, Swing Music GHSA-pj88, Horizon GHSA-f8fh, -rhjj and -j72v;
    cve-pairs-python-frontend: Fava GHSA-q8hg; plus bbot GHSA-m54h and -3mp7 for cve-pairs-python-nonhttp) and
    9 blind ones, unread. The 11 open ones are in suites.json (8 in cve-pairs-python, 1 front end, 2 nonhttp),
    first measured by the nightly run; the 9 blind ones went into cve-pairs-blind-python-9 to -13 and
    cve-pairs-blind-python-nonhttp unread, for the end of the round. The research runs had
    stopped at 09:00 on their cap of 6 batches waiting for review (`CODEWATCH_RESEARCH_MAX_PENDING`, set in the
    maintainer's systemd override); it is now 12, about a day of hourly runs between reviews.

48. **Topic 6 done; topic 7's first six batches reviewed** (2026-11-07). Topic 6's seventh batch read the last 46
    framework-confirmed candidates and accepted none: of the ~970 Python-repository candidates left on 2026-11-06,
    most are in repositories that declare none of Django, Flask or FastAPI (Zope, OpenStack, IPython, LangChain,
    pylint...), which the topic's framework check drops without a row. Topic 6 in all: 7 batches, 406 read, 20
    kept. Topic 7 (JavaScript) started on its own at 20:00: six batches, 360 read, 11 accepted. Two were rejected at
    review: Eclipse Che GHSA-7c8p (the private-host check already existed; the fix closes an IPv4-mapped IPv6
    bypass: a validator made stricter) and NoteGen GHSA-4fc4 (the path comes from synced conversation data in the
    app's store; no input source in the code the fix touches). Added to suites.json: cve-pairs-javascript Openwhyd
    GHSA-224m and Waline GHSA-jf75 (NoSQL operator objects from the body), Claw Orchestrator GHSA-95f6 (request
    pattern into new RegExp); cve-pairs-javascript-nonhttp jupyterlab-git GHSA-f962 (file names into diff header
    HTML); cve-pairs-python lollms GHSA-37c2 (SPA catch-all path joined to the static directory) and FTS3 Web
    Monitoring GHSA-xf3h (query parameters %-formatted into SQL; both Python apps in JavaScript-primary
    repositories). Three blind ones went unread into cve-pairs-blind-javascript-11 and -nonhttp. Topic 7 yields
    about 2 per batch against topic 6's 3-4, as expected for a pool that is mostly npm library code.

49. **Where the gaps are; topic 8; the front-end misses sorted** (2026-11-07). From the 2026-11-06 nightly
    (verdict mode, found/cases): Python server-side path traversal 19/26 and SQL 5/6, open redirect 4/9, XSS 3/7;
    Python front end 2/30; JavaScript path traversal 3/19, XSS 1/11, redirect and SSRF 0/8; JavaScript non-HTTP
    0/15. The front end, redirects and JavaScript have enough cases: those gaps are rule work. What research can
    fill is the weaknesses with almost no Python cases (SSRF 5, command injection 5, code injection 3, ReDoS 1,
    deserialization 1; template injection, XXE, LDAP and header injection none), so rules for them are tested by
    unit tests only. Topics 1, 5 and 6 used up the Django/Flask/FastAPI advisories, so topic 8 (queued after topic
    7) takes only those weaknesses and widens two filters for them: the framework may be declared in a nested
    dependency file (`backend/requirements.txt`), and Starlette, Litestar, Quart, Falcon, Pyramid, Bottle and
    agent/MCP tool input count. About 430 unread advisories in Python repositories matched on 2026-11-07, mostly
    library code (picklescan, vLLM, LangChain, NLTK, Keras), across about 200 repositories.

    The 28 missed front-end cases, sorted by the cheap model from their fix diffs (a few quotes checked by hand):
    - Template output marked safe: `|safe` on a model field 5 (calibre-web, modoboa, invenio-communities,
      GeoNode, fava), `|safe` inside a script string 1 (bird-lg), `{% autoescape off %}` 2 (cabot,
      changedetection.io), a template variable in a JS string or inline handler 2 (pgAdmin layout, Airflow
      onclick), an unquoted attribute 1 (nautobot). Most read a stored field: the templates half of step 45's
      stored XSS (`{{ obj.field|safe }}` with obj from the view's context) would reach about 5.
    - Shipped JS writing HTML: jQuery `.html()`/`html:` 6 (modoboa x2, indico, horizon, calibre-web, OctoPrint),
      `innerHTML` 2 (pgAdmin, fava), a template literal returned to a chart tooltip 1 (cti-transmute), an
      `href` from data 2 (Weblate, pyload), library options that render HTML 2 (PNotify text, select2
      escapeMarkup). The data is mostly an API response or a form field's value: step 42's gap I (fetched data
      written as HTML in JS).
    - Other: Graphite query parameters, Airflow ANSI link allowlist, MLflow `yaml.load` (not XSS as such), and
      one Python string built into HTML (OctoPrint).
    Next rule work, by cases reached: stored fields into `|safe`/autoescape-off templates (about 7), then fetched
    or form data into jQuery `.html()`/`innerHTML` (about 8).

50. **Topic 7 batch 7 reviewed** (2026-11-07). 60 read, 11 accepted, 3 rejected at review, all OpenClaw:
    GHSA-r39h (plugin setup code loaded from the working directory; the fix removes a lookup location, no input
    reaches a sink), GHSA-f7fh (the CDP WebSocket target comes from the endpoint's own response and the
    operator's config) and GHSA-c9h3 (the fix adds a key to the parameter list an existing sandbox check covers).
    Added: cve-pairs-javascript MCPHub GHSA-p3h2 (an upload's manifest name in the extraction path);
    cve-pairs-javascript-nonhttp Summarize GHSA-2r69 (a page's link URL reaches the daemon's fetch), OpenClaw
    GHSA-c4qg (a chat image URL fetched for upload) and GHSA-jf25 (a tool's outPath written without the workspace
    check); 4 blind ones unread into cve-pairs-blind-javascript-12 and -nonhttp. Agent apps like OpenClaw now
    supply many advisories; their tool arguments and chat messages are the nonhttp suite's input.
51. **Nightly 2026-11-07 (commit 52d3e4b) and a scorer fix** (2026-11-07). The netbox false alarms of step 47
    are gone and no app finding is new. New cases found: Langflow GHSA-79ph and Swing Music GHSA-pj88 (the
    latter still flagged after the fix); missed: Open WebUI, alerta, OpenHands, Horizon x3, Fava, bbot x2.
    mlflow GHSA-wqmh showed as detected in review mode only, by 6 hotspots away from the fix that were missing
    from the fixed side; re-run alone it is missed and quiet in both modes, as on every earlier night. Semgrep
    gives up on rules in a file under load and drops their findings without an error (only a note), so a
    finding "the fix made go away" is now counted only when the fixed side's scan didn't give up; the case's
    result says `gave_up` when either side did (test_a_finding_gone_from_an_incomplete_fixed_scan_is_not_detection).
    Front-end template work (step 49): of the 7 |safe / autoescape-off misses only GeoNode GHSA-rwcv and Modoboa
    GHSA-jm3m print Django model fields; calibre-web GHSA-h56g and invenio GHSA-mfv8 are SQLAlchemy models,
    Cabot GHSA-mqwh prints check errors, bird-lg GHSA-xjrp session data, OctoPrint GHSA-xvxq an autoescape
    setting. Stored fields into |safe would need SQLAlchemy model support to reach more than two cases.
52. **Form field values into HTML (codewatch.js.xss)** (2026-11-07). The JavaScript side of step 49's front-end
    misses, read at the vulnerable lines: only two have a source a rule can see. Modoboa GHSA-c467
    (`$span.html("@" + $("#id_name").val())`) and calibre-web GHSA-wrp6 (`$(this).val()`, an upload's file name,
    into `$("#upload-format").html()`). Added to the XSS rule only: sources `$(...).val()` (also one find step
    deep) and `document.getElementById/querySelector(...).value`; sinks `.html()`/`.append()` on a variable named
    with a leading `$` (jQuery's convention); sanitizers htmlEncode/encodeHTML/htmlEntities-named functions and
    `fetch(...)` (the server's reply, not the posted value: pygoat's comparison lab sends a select's value and
    renders the response). calibre-web's edit_books.js was skipped as vendored: its opening comment "Created by
    SpeedProg on 05.04.2015" matched the library banner with the date as a version; a d.m.yyyy date no longer
    counts (no file among the 50 apps' 3302 JS/CSS files changes status). Both cases found, fixed sides quiet;
    double-take GHSA-q9xj, vulnerable-snippets-js and vulnerable-node-seeds unchanged. App probe (the 18 app JS
    files and 8 templates with both a form value and an HTML sink): two findings, both pygoat's package labs
    (a typed package name into an activity log's innerHTML, real). Left out on purpose: AJAX/fetch responses as a
    source (Horizon GHSA-j772, Weblate GHSA-6wxc): loading a server fragment into .html() is the ordinary pattern.
    pgAdmin GHSA-2rrx and Modoboa GHSA-mgmm have no visible source; django-ucamlookup GHSA-pjx4 (select2's
    escapeMarkup turned off) and Fava GHSA-6hcj (d3 tooltip HTML) need library-specific rules. Test:
    test_form_field_values_written_into_html; test_vendored_libraries_are_recognised_by_their_banner.
53. **Topic 7 batches 4-13 of 2026-11-07 reviewed** (2026-11-08). 600 read by the agent, 45 accepted: 29 open
    read here, 16 blind. Added: cve-pairs-javascript 12 (Rocket.Chat GHSA-8fhh redirect query into Location,
    FalkorDB Browser GHSA-2987 and Swetrix GHSA-6q94 upload names into paths, Actual GHSA-27vg a header file id
    into a path, Ghost GHSA-gjrp filter post_id into SQL and GHSA-f7qg a bookmark URL fetched, PsiTransfer
    GHSA-xphh upload names into archive entries, deco.cx GHSA-qwwx a loader prop fetched, React Native CLI
    GHSA-399j req.body.url into open(), hackmd-mcp GHSA-g5cg a header/query config as the API base URL,
    url-to-png GHSA-vvmv query params into the image path, HFS GHSA-5f4x an upload path into execSync);
    cve-pairs-javascript-nonhttp 8 (OpenClaw GHSA-f6pf model-output MEDIA: paths, GHSA-qf48 and GHSA-r5fq tool
    paths read and written, GHSA-c6hr a chat mention into RegExp; mobile-mcp GHSA-3p2m tool output paths;
    mcp-maigret GHSA-2g7v tool arguments into exec; sequa-mcp GHSA-9pw5 and mcp-cli GHSA-p6rm a remote server's
    authorization URL into open(), the OAuth provider method's parameter being the source). Blind, unread:
    8 into cve-pairs-blind-javascript-nonhttp, 1 into -javascript-12, 3 into a new -javascript-13, and a Python
    one (frappe/crm) into a new cve-pairs-blind-python-14. Rejected at review: create-mcp-server-stdio GHSA-3ch2
    (port is z.number()), mcp-remote GHSA-6xpm (an existing sanitizer made stricter), url-to-png GHSA-665w (a
    protocol refine on an existing zod validator), Parse Server GHSA-x4qj (framework code, as the agent's own
    GHSA-792q), OpenClaw GHSA-hggm (same fix commit as GHSA-f6pf), GHSA-w76h (an allowlist extended to
    redirects) and GHSA-xw4p (a name from an installed skill package), Mockoon GHSA-w7f9 (request values reach
    the path only through the operator's route template). Deferred: LimeSurvey GHSA-wj23 and a blind Tainacan
    case are PHP, kept for a PHP suite. The agent began topic 8 before topic 7 was done (two python-thin batches,
    1 accepted of 120 read); left as is. Both reviewed here too: GeoNode GHSA-9fpx added to cve-pairs-python (a layer
    name from an uploaded vector file into ogr2ogr run with shell=True, through a Celery task; CWE-78).

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
- `python3 -I benchmarks/restore_repos.py [FOLDER...]` re-clones the pinned repos listed under Repos (default
  `fresh/` and `blind4/`). Needed on 2026-11-03, after a disk cleaner (BleachBit) emptied `~/.cache` at 16:08;
  that also lost the 06:08 nightly report. Keep `~/.cache/codewatch` and `~/.cache/ms-playwright` on the
  cleaner's whitelist.

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
54. **Nightly 2026-11-08 (commit 9dbec85) and a narrower fetch sanitizer** (2026-11-08). Step 52's rule found
    Modoboa GHSA-c467 and calibre-web GHSA-wrp6 with both fixed sides quiet (python-frontend verdict 2 to 4 of
    31, no false alarm); the other suites are unchanged. Step 51's scorer took mlflow GHSA-wqmh and GHSA-cr8c
    out of cve-pairs-python's detections: both sides of each gave up, and the only credit was findings missing
    from the incomplete fixed scan. Semgrep giving up is common (most front-end pairs, a dozen Python ones), so
    scans of large repos aren't complete; worth its own look. Of the 10 cases from step 50's review measured
    here, Python GHSA-37c2 and GHSA-xf3h are found, 7 of 8 JS ones missed. One app finding was lost: actual's
    app-cors-proxy.js:248, a route that fetches a URL from the request and sends the reply's text on with the
    remote content type (text/html included). Step 52's `fetch(...)` sanitizer hid it; it now covers only a
    fetch of a same-origin path (a string or template literal starting with one `/`), which still covers
    pygoat's comparison lab. actual's proxy is reported again; pygoat's findings are the nightly's exactly;
    c467 and wrp6 unchanged. Test: test_form_field_values_written_into_html (proxy.js). README table updated
    to this night.
55. **Topic 7's last batches, of 2026-11-08, reviewed** (2026-11-08). Six batches, 310 read by the agent (the
    topic's list is now used up: the sixth batch read the last 10), 14 accepted: 6 open read here, 8 blind.
    Added to cve-pairs-javascript: n8n GHSA-c8hm (a request's mimeType query parameter becomes the Content-Type
    of a stored upload, so text/html runs; the fix adds a CSP sandbox, and codewatch has no rule for a
    request-chosen Content-Type), github-readme-stats GHSA-jqwf (a GitHub API error that echoes the username into
    renderError's SVG), code-server GHSA-2gp3 (err.message, which carries the requested path, into the HTML
    error page), browserless GHSA-8p9r (a request file name joined to the workspace directory and read) and
    web-node-server GHSA-3fwq (request.url appended to the template root and read). Blind, unread: 7 into a new
    cve-pairs-blind-javascript-14 (the agent proposed -14, -15 and -16 by batch; one suite is enough) and 1 into
    cve-pairs-blind-javascript-nonhttp. Rejected at review: snyk-broker GHSA-gq75 (the fix makes an existing URL
    allowlist stricter, and the path is proxied to an upstream API, not read from disk).
56. **SecurityEval's misses read again; a request-chosen Content-Type is XSS** (2026-11-08). Of the 70 samples
    missed in verdict mode: about 15 are flagged already, under a sibling weakness the CWE-family scorer doesn't
    relate to the folder's (CWE-434 uploads and CWE-099/641/425 as path traversal, CWE-020 codeql_1 as XSS,
    CWE-116 author_1 as command injection), left as they are rather than widen the scorer; about 35 are design
    flaws or not request input (input(), races, off-by-one, missing auth). Added to codewatch.python.web.xss:
    sinks for the response type taken from request data (Response/HttpResponse/FileResponse/make_response
    mimetype= or content_type=, `.mimetype`/`.content_type` and `headers['Content-Type']`/`r['Content-Type']` on
    a response built in the function, `Headers()`'s add/set): SecurityEval CWE-113 sonar_1/sonar_2, and the
    shape of n8n GHSA-c8hm (step 55). Werkzeug and Django refuse newlines in header values, so it is reported as
    XSS (text/html), not response splitting; the scorer therefore still counts both samples as missed (52.1% to
    53.7% with some security finding). Not covered: an attachment (as_attachment=True: downloaded, never
    rendered; label-studio's export was the one app finding among 161 app files that set a type, now quiet), a
    type looked up in an upper-case table, and send_file(mimetype=...) (send_file is a sanitizer of this rule).
    OWASP, Copilot and InCoder unchanged. CWE-611 sonar_4 is missed only because the sample never imports
    feature_external_ges; the imported form is already matched. Left for later: CWE-943 (a DynamoDB
    FilterExpression built by concatenation): Python has no NoSQL rule yet (pymongo `$where` and operator
    injection from a JSON body, boto3 condition expressions). Test: test_request_chosen_response_content_type_is_xss.
57. **Python NoSQL injection (codewatch.python.web.nosql-injection)** (2026-11-08). Python had no rule for
    CWE-943 (step 56). One rule, three sinks, with Semgrep taint labels to keep operator injection honest:
    a parsed JSON body (request.get_json()/request.json, json.loads of request data, DRF request.data in an
    APIView/ViewSet or @api_view) is the only request data that can be an object, so only it counts in a MongoDB
    collection method's filter or pipeline (find/find_one/update_one/.../aggregate on a receiver named for a
    database or collection: mongo.db.users, db["items"], items_collection); `{"$where": ...}` and DynamoDB
    expression keywords (FilterExpression, KeyConditionExpression, ConditionExpression, UpdateExpression,
    ProjectionExpression, PartiQL Statement) take request text of any kind. Sanitizers: str/int/float/bool,
    ObjectId, UUID, a schema's load()/model_validate()/parse_obj(), isinstance(x, str), and boto3's Key()/Attr()
    builders. Known limit: the summary passes give parameters unlabelled sources, so a JSON value handed to a
    helper that runs the find isn't followed (the $where and DynamoDB sinks are). xpath-injection's
    ElementTree find/findall sink no longer takes a dict query or a receiver named like a database, collection or
    soup (Mongo's find({...}) and BeautifulSoup's find(tag) are no XPath). SecurityEval CWE-943 sonar_1 is now a
    hotspot (a function nothing calls; review 77 to 78 of 121); OWASP, Copilot and InCoder unchanged. False-alarm
    evidence is thin: of the 53 app and own-project files touching find/Mongo/DynamoDB none changed, and only
    two projects use boto3 at all, none Mongo from a web view. No CVE pair for Python NoSQL exists yet; a
    research topic for one (Flask/Django apps on pymongo or DynamoDB) would give ground truth.
    Tests: tests/test_python_nosql.py.
58. **Research: topic 8 paused, topic 9 (Python NoSQL) queued** (2026-11-08). Topic 8 accepted 1 of 240 read; its
    pool is mostly library code. Topic 9 looks for ground truth for step 57's rule: advisories with CWE-943 or
    naming MongoDB/DynamoDB/NoSQL operators, in Python app code, from repositories of any primary language
    (full-stack apps often report JavaScript), stopping after one full pass if it yields fewer than 5.
59. **A request-chosen Content-Type in Node is XSS too** (2026-11-09). Step 56's sinks, for codewatch.js.xss:
    res.setHeader/set/header('Content-Type', ...), res.set({...})/writeHead(status, {...}) with a Content-Type
    key, res.type()/contentType(), and Koa's `ctx.type =`, on res/response/reply/ctx. Drove it: n8n GHSA-c8hm
    (step 55; the query's mimeType as the type of a stored upload), now flagged before the fix (line 41) and
    quiet at it. Not reported: a handler that also sends `Content-Security-Policy: sandbox` (n8n's fix) or calls
    res.attachment(), a type looked up in an upper-case table, and a type from mime.getType/lookup/contentType
    (new sanitizer: the type follows the file served). Probe of 121 app and own-project files that set a type or
    load records: the four new findings in wiki's asset, file, site-asset and avatar handlers were stored records
    loaded through `await WIKI.models.<name>.get.../resolve...(...)`, which the data-layer sanitizer missed; it
    now accepts a `models.<name>` receiver and `resolve...` methods, and they are quiet. actual's CORS proxy gets
    two more lines (it copies the upstream's Content-Type for a URL the request chose), as does the synthetic
    proxy in test_form_field_values_written_into_html. Test: test_request_chosen_response_content_type_is_xss_in_node.
60. **Topic 8's last batches and topic 9 reviewed** (2026-11-09). Six batches (topic 8's five of 2026-11-08,
    topic 9's single pass), 8 accepted by the agent: 6 open read here and accepted, 1 rejected, 1 blind.
    Added to cve-pairs-python: moonraker GHSA-3jqf (the login username into an LDAP filter; the fix escapes it),
    mcp-atlassian GHSA-7r34 (Jira/Confluence URLs from request headers fetched by the header-based clients: SSRF)
    and cve-search GHSA-3fmp (a form field names the MongoDB collection and DataTables column names the
    projection and sort, so a request reads mgmt_users; filed as CWE-20, CWE-943 added so the scorer counts the
    NoSQL rule). Added to cve-pairs-python-nonhttp: CHIRP GHSA-6rmm (a CSV file's tone fields into eval()),
    meta-ads-mcp GHSA-45gf (an MCP tool's image_url fetched with redirects followed) and mcp-for-stata GHSA-4p62
    (an MCP tool's log name into a Stata `log using` command). Blind, unread: 1 into a new
    cve-pairs-blind-python-15. Rejected at review: adx-mcp-server GHSA-vphc (KQL from table_name, but the same
    server's execute_query tool runs any KQL the client sends, so no trust boundary is crossed). Topic 9's pool
    was 123 advisories, 107 in non-Python repositories and nearly all the Python ones library or driver code; it
    stopped after one pass as its rule says. Every research topic is now done or paused.
