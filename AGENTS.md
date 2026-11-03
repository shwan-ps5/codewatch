# codewatch: instructions for research agents

This file is for AI agents (opencode, Ollama-hosted models and the like) asked to do **research** in this repository:
finding CVE fix pairs that codewatch, a security scanner, can be measured against. Everything you need is here.
Don't ask the maintainer about the rules below. Follow them, and when a case is truly unclear, record it as
`unsure` with your question in the reason column. A later review session answers it.

## What you do and don't do

Do: find advisories, read each fix commit, accept or reject it with a reason, and write the results as candidate
files (below). Then commit them.

Don't:
- edit `benchmarks/suites.json`, `PLAN.md`, `CLAUDE.md`, rules (`catalog/`), analyzers (`core/`) or tests. A review
  session on the maintainer's desktop checks your candidates and adds the accepted ones to the suites.
- run scans, benchmarks or the test suite. This machine is too slow for that, and the desktop runs them overnight.
- read anything about a blind case after it's split (see "Blind split").
- name the maintainer's private projects or anything from them. This repository is public.

## Setup

```
git checkout detection-gaps && git pull
git config user.name "Shwan"
git config user.email "344055753+shwan-ps5@users.noreply.github.com"
```

Commit only with that identity, never another name or email. You need `gh` (logged in) and `python3`; nothing else.

## 1. Skip what's already been looked at

Before reading any candidate's diff, check it:

```
python3 -I benchmarks/reviewed.py GHSA-xxxx-xxxx-xxxx [more ids or fix commit SHAs]
```

It prints `new` for unseen ids and exits 1 if any is already known (in a suite, accepted, rejected or unsure).
Skip anything known, including when only its fix commit matches. `python3 -I benchmarks/reviewed.py` with no
arguments lists everything known. Load it once at the start of a batch and filter your candidate list with it.

## 2. What to look for

Priorities, in order:
1. Python web apps (Django, Flask, FastAPI) and the JavaScript/templates those apps ship.
2. Node and other JavaScript frameworks (Express, Next, Nest, Koa, Fastify, Vue/React front ends).
3. PHP, Ruby, Rust, C/C++, C#.

Weaknesses (CWE): 22 path traversal, 78/77 command injection, 79 XSS, 89 SQL injection, 94 code injection,
502 deserialization, 601 open redirect, 611 XXE, 918 SSRF, 1336 template injection, 73 external file path.
For Python (PLAN.md step 24) also: 23 and 36 (path variants), 90 LDAP, 113 header injection, 643 XPath, 943 NoSQL,
1333 ReDoS from request data.

Use only advisories that link a fix commit.

### Topic queue

If the maintainer just says "do the next topic", take the first one below not marked done. When you finish one,
mark it `(done YYYY-MM-DD, file name)` in this list and commit that with your batch. Don't start a topic that isn't
listed. If you have an idea for a new one, write it at the end as `(proposed)` and stop.

Already mined, don't repeat: GitHub-reviewed PyPI advisories since 2021 (PLAN.md steps 22-27) and GitHub-reviewed
npm advisories (step 29). Those pools are nearly used up.

1. **Python web apps not published on PyPI.** Apps like these get advisories that GitHub never reviews, so they
   aren't in the PyPI pool. Source: GitHub's advisory database as a git repository, filtered locally with no API
   calls:
   ```
   git clone --depth 1 https://github.com/github/advisory-database ~/advisory-database
   ```
   The files to look at are `advisories/unreviewed/**/GHSA-*.json` (OSV format). Keep the ones published since
   2021 with a CWE from the list above (`database_specific.cwe_ids`) whose `references` hold exactly one
   `https://github.com/OWNER/REPO/commit/SHA` URL. Write that filter as a small Python script in
   `~/codewatch-research/` (your workspace outside the repository), never in the repository. Then drop anything `reviewed.py` already knows, by id or fix SHA. Group what's left by
   repository and get each one's language with GraphQL, 100 repositories per query, one query at a time with two
   seconds between them. Never send one call per repository in parallel: bursts get the account blocked.
   `gh api graphql -f query='{ r0: repository(owner:"O", name:"N") { nameWithOwner primaryLanguage { name }
   isArchived } r1: ... }'`; a null result means the repository is gone or renamed, so skip it. Keep the Python ones, then confirm Django, Flask or FastAPI
   from `requirements*.txt`, `pyproject.toml` or `setup.py` at the fix commit. Many reports are from huntr.dev; that
   doesn't matter. Judge each by section 3. Proposed suites: `cve-pairs-python` (views and handlers) or
   `cve-pairs-python-frontend` (templates and front-end JS); blind ones go in a new blind suite with the next unused
   number (section 4). Files:
   `benchmarks/cve-candidates-YYYY-MM-DD-python-unreviewed.{tsv,json}`.
2. **Node web apps not published on npm.** Same source and method as topic 1, keeping JavaScript/TypeScript
   repositories with a web server (Express, Koa, Fastify, Nest, Next, Hapi) or a Vue/React front end. Suites:
   `cve-pairs-javascript` or `cve-pairs-javascript-nonhttp`, blind ones in the next unused
   `cve-pairs-blind-javascript-N`. Files:
   `benchmarks/cve-candidates-YYYY-MM-DD-javascript-unreviewed.{tsv,json}`.

A batch is at most about 60 advisories read. Stop there, or when the maintainer gives a time, even mid-topic.

**Carrying on a topic** doesn't depend on anything an earlier session did. Rebuild the topic's candidate list from
its source, drop everything `reviewed.py` already knows (by id or fix SHA), sort what's left by published date,
newest first (then by id), and read from the top. That's always the next batch: there's no position to remember.
Say in the JSON's `method` how many candidates were left after filtering, so the review can see how much of the
topic remains.

## 3. Accept or reject: the rules (PLAN.md steps 22 and 24)

Accept only when **all** of these hold:
- **Exactly one fix commit** is linked, and it fixes this advisory (not a different one).
- **Small**, not counting tests, docs, changelogs, lockfiles, `package.json` and similar manifests:
  - JavaScript and other languages: at most **3 changed source files** and **120 changed lines**.
  - Python: the same, or up to **5 files and 200 lines** if the vulnerable flow is still clear from the diff
    (step 24). Say in the reason when a case uses that wider limit.
  Measure it with this command; don't estimate:
  ```
  python3 -I benchmarks/reviewed.py size OWNER/REPO SHA            # JavaScript and other languages
  python3 -I benchmarks/reviewed.py size OWNER/REPO SHA --python   # Python's wider limit
  ```
  It skips test, doc and manifest files and ignores whitespace-only changes (re-indented code), then says
  `within` or `OVER`. Copy its last line into the reason. `OVER` means reject, and so does more than one parent
  (a merge commit). Run it only for candidates that pass every other rule, so most never need the API call.
- **Application code**: the bug is in the project's own app code, not in a library or framework it ships or is
  (Django's ORM, urllib3, a sanitizer package, a UI component library).
- **A visible flow**: data from an HTTP request (query, body, path, headers, cookies, uploaded file names) reaches
  a dangerous call (file open/delete, shell, SQL string, `eval`, HTML output, redirect, outbound fetch...) in the
  code the fix touches, and the fix changes that flow (escaping, parameterising, validating, using an argument
  list...).

Reject, and say which reason applies:
- library or framework code; fix too large; several fix commits; the fix mixes in unrelated changes
- stored data with no request path in sight: rendered later from the database, or taken from a job, workflow or
  run context, even when a user first sent it through the API (e.g. Skyvern GHSA-57gg)
- an existing validator, denylist or regex made stricter: a gap no scanner rule can see. But a check *added*
  where the code had none (a same-origin test before a redirect, a containment check before open(), escaping
  before output) is the fix scanners look for: that passes this rule
- a settings flag or default changed (e.g. turning raw HTML off in a Markdown renderer)
- missing authentication or authorization (CWE-862/863/639)
- races: DNS rebinding, TOCTOU
- Tornado, aiohttp, Gradio and Streamlit apps (Quart, Starlette, Flask-RESTful and Flask-AppBuilder count as
  Flask/FastAPI); test-only fixes; CLI-only tools
- the advisory's fix commit doesn't match its description

**Not an HTTP request** (repository config read by a bot, desktop/Electron IPC, chat-protocol ids, files on disk):
accept only if it passes every other rule, and set the suite to `cve-pairs-javascript-nonhttp` (or
`cve-pairs-python-nonhttp`). Never put these in the web suites.

Proposed suite for accepted open cases: `cve-pairs-python` (Python views/handlers), `cve-pairs-python-frontend`
(the templates and front-end JS of a Python web app: use it whenever the fix changes only templates or JS files), `cve-pairs-javascript` (Node/JS web apps), or the
`-nonhttp` ones above.

## 4. Blind split

Decide accept/reject first. Then, for each accepted case, run the split **before writing anything about it**:

```
python3 -I benchmarks/reviewed.py --split GHSA-xxxx-xxxx-xxxx
```

- `open`: write the flow in the reason column, as in the examples below.
- `blind`: the reason is exactly `accepted; reason withheld so the case stays blind`. Don't describe its flow,
  files or fix anywhere: not in the reason, the JSON, the commit message or your chat summary. Its suite is
  `cve-pairs-blind-<language>-N`. Use the next unused N; `python3 -I benchmarks/reviewed.py | grep blind` shows the
  ones in use.

Rejected cases are never split. Write their reasons in full.

## 5. Output

Two files per batch, named `benchmarks/cve-candidates-YYYY-MM-DD-<topic>.tsv` and `.json`.

The TSV has one row per advisory you read, rejections included (that's how the next agent knows to skip it).
Tab-separated, two `#` comment lines, then a header:

```
# <what this batch is>, YYYY-MM-DD. One line per advisory read. Research only: not reviewed or scanned yet.
# Accepted cases are split by int(sha256(id), 16) % 3 == 0 (blind); blind reasons are withheld.
repo	id	cwe	decision	suite	reason
archesproject/arches	GHSA-gmpq-xrxj-xh8m	89	accept	cve-pairs-python	Arches (Django): a request GET parameter reaches string-formatted SQL in get_child_edges; the fix parameterizes the query.
airbnb/knowledge-repo	GHSA-xmw7-848p-p95w	79	reject		escapes at storage; the XSS is rendered later from the database
```

`decision` is `accept`, `reject` or `unsure`. `repo` is `owner/name`. Several CWEs are comma-separated.

The JSON holds the suite entries for accepted cases (blind ones too, because the review session needs them), in
the shape `benchmarks/suites.json` uses:

```json
{"batch": "...", "status": "research only: not reviewed or scanned",
 "accepted": [{"id": "GHSA-...", "suite": "cve-pairs-python",
               "entry": {"id": "GHSA-...", "cve": "CVE-...", "repo": "https://github.com/owner/name.git",
                         "fix": "<full 40-char sha>", "cwe": [89], "license": "MIT",
                         "summary": "<the advisory's title>", "scope": ["path/of/the/changed/dir"]},
               "flow": "<open cases only: request source -> sink -> what the fix changed>",
               "fix_size": "<files and lines you measured>"}]}
```

For blind cases, leave out `flow` and `fix_size`. Every case in `accepted` must also have its `accept` row in the
TSV; the push check refuses a batch where they disagree. `scope` is the directory or directories holding the changed
source files.

## 6. Work in few, large steps

Every turn sends the whole conversation to the model again, so a batch's cost grows with the number of turns.
Measured on 2026-11-03: one long session re-read 107M tokens to take in 1.4M characters, while a fresh batch
re-read 4.8M. So write one script in `~/codewatch-research/` that, for the next 5-10 candidates, fetches each
advisory's summary and its fix commit's diff (source files only, each cut to about 300 lines), and prints them
together. Judge them all from that one output instead of making one tool call per candidate. Keep the 2-second
pause between API calls inside the script.

## 7. GitHub API manners

At most two requests at a time, with a second or two between them. Never send requests in parallel. To look up
many repositories, batch them in GraphQL (100 per query; topic 1 shows how). Bursts have tripped rate limits before. If you
get a 403 or a 429, wait a few minutes; don't retry in a loop.

## 8. Commit

```
git add benchmarks/cve-candidates-YYYY-MM-DD-<topic>.*
git commit -m "Research: <topic> CVE candidates (N read, A accepted: O open, B blind)"
```

Commit to `detection-gaps` (never `main`). Push only when the maintainer says so. Your summary to the maintainer
gives the counts and lists open cases by id, plus any `unsure` questions; blind cases appear as a count only.
