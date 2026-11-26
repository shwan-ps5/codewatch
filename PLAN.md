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

## The log

Every change and decision is a numbered step in `docs/plan-log.md` (steps 1-110 to 2026-11-21, and on). "PLAN.md
step N" anywhere (suites.json, AGENTS.md, code, tests, commits) means step N there. Add new steps at the end of
that file, not here, and keep them short: what changed, the case behind it, what it measured, the test. A review
step gives counts, what was kept, rejections that set a new precedent and any problem found; the batch TSVs hold
every other reason. This file holds only what is true now: update the sections below when a step changes them.

## Where things stand (nightly 2026-11-25, commit 65e556c)

Verdict mode counts findings that claim a vulnerability; review mode adds hotspots. CVE pairs: found = flagged
before the fix, still flagged = flagged after it (the false-alarm measure).

| Suite | Verdict | Review |
|---|---|---|
| OWASP Benchmark Python (tuned) | 100% found, 0% false alarms | 100%, 35% |
| SecurityEval (tuned) | 51/121 | 78/121 |
| SecurityEval Copilot / InCoder (held out) | 34% / 31%, 0% / 0% false alarms | 51% / 47%, 6% / 0% |
| Juice Shop (tuned) | 15/35 | 17/35 |
| Vulnerable-Code-Snippets JS (held out) | 11/22 | 13/22 |
| vulnerable-node seeds | 11/12, 0 false alarms | 12/12, 1 |
| cve-pairs-python (107; 110 at the run, step 143) | 67 found, 15 still flagged | 71, 24 |
| cve-pairs-python-frontend (32) | 4, 0 | 16, 8 |
| cve-pairs-python-nonhttp (15) | 4, 2 | 6, 3 |
| cve-pairs-javascript (103) | 22, 9 | 46, 32 |
| cve-pairs-javascript-nonhttp (38) | 1, 0 | 10, 8 |
| cve-pairs-php (341) | 75, 27 | 83, 36 |

Apps: 51 in the nightly (learning sets, deliberately vulnerable apps, ordinary apps, the maintainer's own projects;
listed in `~/.config/codewatch/nightly-apps.txt`, outside the repository). Every finding there has been read;
the nightly reports new and gone ones, and `benchmarks/triage.py` drafts a verdict for each new one.

How work runs: a change is checked in isolation by day (its tests, a probe, `devtools.py cases ID...`) and the
full verification runs nightly at 01:30 (`benchmarks/nightly.sh`, report in
`~/.cache/codewatch/nightly/DATE/summary.txt`). Research agents run hourly (`tools/research-batch.sh`) and send
batches through one pull request from `research`, reviewed by a Claude session (CLAUDE.md). Focus: Python web apps
(Django, Flask, FastAPI) and the JavaScript they ship, then Node, then PHP and other languages.

Where this is heading (the maintainer, 2026-11-22): close every gap in the open items below, then keep codewatch
current against new CVEs and changing standards. Once the gaps are closed that is a weekly cycle, not a daily one:
new advisories (topic 16), changes to the standards, and a verification run. Research topics run until they're
exhausted.

## Open items (2026-11-21; keep current, name the step that closes each)

Detection gaps, by cases reached (from the sort of the 81 Python misses, step 108):
- Front-end XSS, 27 of 31 missed. Shipped JS writing data as HTML: 12 (step 42 I: step 131 added a review-mode
  hotspot for fields of a fetched answer reaching an HTML sink, 2 found; whole HTML answers, callbacks passed by
  name (pyLoad's `success: this.createLinks`) and project wrappers are left). `|safe` /
  `{@html}` on stored fields in templates: 7 (step 42 H, the templates part; Django models are done, step 45,
  SQLAlchemy ones aren't). Template values in script strings, inline handlers and unquoted attributes: 4 (J).
- Python server side, 54 missed: existing checks too weak 15, sinks not modelled 13, sources not modelled 12,
  values through several functions 10, archives 2, stored 2. Known small ones: JSON-RPC dispatcher arguments as a
  source (Counterparty, step 110), Location set through `response.headers` (araa-search, step 110).
- Step 42 D (project checks trusted by name: `*safe*`, `*sanitize*`, `*valid*`) and E (dispatch the summaries
  can't follow: pygeoapi GHSA-f6pr, Lektor GHSA-wv28): not started. archivy (step 124) is a D case at its fix: a
  project helper `is_relative_to()` (resolve().relative_to() in a try, returning a bool) guards mkdir and rmtree,
  and both stay flagged.
- Frameworks with no sources yet: webapp2 (bridgy-fed's `self.request.path_qs`, step 124), Checkmk's own
  `request.get_unicode_input*` (step 123).
- From the gap notes (step 128): Fugue (`cloudpickle.loads` inside a helper `_decode()`) and Horizon (a second
  redirect tainted through `get_user_home(users.get_user_from_request(request))`) are still missed though their
  probe shapes are now caught. A helper handed `request` passes taint to its result, which keeps Horizon's fixed
  side flagged.
- JavaScript: path traversal, SSRF and redirects mostly missed; outside HTTP handlers 1 of 38.
- PHP (steps 70, 73): no summaries across functions and files (most misses); helpers given 'escape' => false,
  lookup results, CakePHP action parameters, by-reference arguments, Twig reading the request, short open tags,
  oci_parse and project db wrappers; no PHP learning set of ordinary apps for false alarms.
- Not filled, by choice: CSRF beyond the existing hotspots; authorization (CWE-862/863/639).

Ground truth:
- Topic 16 (new arrivals) is standing; topic 17 (security fixes with no advisory or CVE) was done on 2026-11-23
  (step 123), every month back to 2021-01 searched. Topics 4 and 8 are paused; the rest are done.
- Gap notes (step 122): a second runner explains the nightly's missed open cases (466 on 2026-11-22: 83 Python,
  118 JavaScript, 265 PHP), about 15 a run, as leads for the rule work above. The first 90 (step 126): 72 probes
  are missed by the rules, so each is a test-sized gap; 16 are found, so the miss lies elsewhere. The next 60
  (step 127): 42 missed, 18 found. Then 120 more (step 130; JavaScript, its non-HTTP cases and PHP): 96 missed,
  24 found. Then 95 more PHP (step 133): 74 missed, 21 found. Then 90 more (step 135; 89 PHP, Checkmk): 62 missed, 28 found. Read them as they come; each note's `probe_scanned` says which.
- 5 cases in `cve-pairs-blind-php-35` have a rejected other id (step 102); keep them unread and re-judge after that
  suite's end-of-round scan (step 103).
- End of the round, not yet run: blind set 4 (redash, InvenTree, pretalx, fief) and the blind CVE suites, each
  scanned once, measurement only. Caveats for the report: `-python-5` and the early JavaScript blind fixes were
  never sized (steps 27, 29); GHSA-hh2q and GHSA-h8pc were partly seen (report with and without them); isard's
  summary line was seen (step 110).

Speed and stability:
- clawmetry (step 110): Semgrep gives up on both sides (about 30 minutes a side, 2026-11-22); since step 142 the
  scorer credits its finding anyway (same give-ups both sides). The slowness itself remains.
- tests/test_detection.py (4,300 lines): CI's Semgrep gives up on some rules there even at 60 s a rule (step 125;
  `check` now says so). A finding reviewed in that file can drop out and fail the self-check as a stale review;
  find the slow rule or split the file.
- mlflow GHSA-wqmh: Semgrep gives up on both sides (over 90 minutes a side on the 2026-11-21 nightly; step 68).
- Unbatched regex alternations in `body_models`, `project_checks`, `jinja_sandboxes` and `drf_serializers` could pass
  Semgrep's ~30,000-character limit on very large projects (step 104).

Housekeeping:
- After 2026-11-30: drop the minimatch/glob override in `tools/package.json` once on typescript-eslint >= 8.73
  (step 98).
- A container for server-side scans of untrusted repositories (step 20): not built.
- Comparison (step 71): CodeQL measured once; the cases only CodeQL finds are still to be read as ordinary misses.

## Next steps

Target (agreed 2026-11-23): Python first until `cve-pairs-python` verdict detection passes 70% (64 of 109, 59%, on
2026-11-23; 66 of 110, 60%, on 2026-11-24; 67 of 110, 61%, on 2026-11-25; 67 of 107, 63%, after step 143 dropped three cases no rule should fix; 108 cases after step 145; 69 of 108, 64%, on 2026-11-26; 109 cases after step 148, so 77 needed), with still-flagged fixes not rising. Measure by misses
and the miss rate, not finds: the suites grew faster than the finds (Python misses 22 to 45 from 2026-11-06 to 2026-11-23), and with topic 17 done they now grow
by about one case a day. JavaScript and PHP rule work waits until then; their gap notes keep coming as leads.

1. The 40 Python misses (Checkmk found since step 136, confirmed by the nightly of 2026-11-25 with no new app findings), each with a gap note: the small server-side sources, sinks and checks first (steps 126,
   128), then values through several functions and project checks (42 D, E). From step 141 the gap runner also
   checks those notes' quotes (check-quotes) and explains the 15 fixes still flagged (still-flagged notes, with a
   safe look-alike probe): use both before writing a rule. Step 144 won Langflow GHSA-v798 (compile() alone no longer a sink; to
   confirm in the nightly) and sorted the other found-probe cases by what each needs (none a small rule; roxy-wi's
   double-quoted `shlex.quote` and pgAdmin's SQL templates are the nearest). Step 146: for still-flagged fixes, path helpers that resolve and
   test containment, then redirect helpers that keep only local paths.
2. Step 42 I: browser JS writing fetched or form data as HTML (the largest front-end group; step 131 started it).
3. Step 42 H, templates: stored fields into `|safe` / autoescape-off templates, SQLAlchemy models included.
4. Each morning: read the nightly, review topic 16's batches and read the gap notes (a still-flagged note's probe
   should be quiet; a check-quotes note marked `wrong` corrects the note it names), merge both pull requests the
   same session, and fast-forward `main` weekly after a clean nightly (CLAUDE.md, "Branches").

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
