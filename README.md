# codewatch

> **Work in Progress** — usable for local scanning, but the data model, CLI, API and UI may change without notice. Expect rough edges.

Self-hosted code-quality server: branch analysis, new-code tracking, quality gates, coverage, duplication, dependency CVEs, security hotspots and accessibility checks, built on open-source analyzers. Django + SQLite, no containers or JVM.

Like sonar-scanner, scans normally run **on the developer's machine** against the local working copy (private repos never leave it) and upload the results. The server can also clone and scan a repository URL itself.

## Server setup

```bash
git clone https://github.com/shwan-ps5/codewatch && cd codewatch
python3 -m venv venv && venv/bin/pip install -e '.[dev,mcp]'
make tools                      # Node analyzers + headless Chromium for axe (needs Node 20+)
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

## What it checks

| Analyzer | Covers |
|---|---|
| ruff, bandit, radon | Python lint, security, complexity, maintainability |
| lizard | complexity for JS/TS, C/C++ and others |
| semgrep CE | bugs, vulnerabilities and security hotspots across languages (config per project, default `p/default`) |
| cppcheck | C/C++ |
| jscpd | duplication |
| pip-audit + OSV | known CVEs in Python dependencies (`requirements*.txt`, `pyproject.toml`), rated by advisory severity |
| html-a11y (html-validate) | static WCAG checks on HTML/Django/Jinja templates: alt text, labels, empty headings, landmarks, ARIA |
| jsx-a11y (ESLint) | accessibility rules for JSX/TSX |
| axe (axe-core + Chromium) | runtime WCAG 2.2 AA on live pages: colour contrast, ARIA, focus, landmarks. Set **Accessibility URLs** per project (e.g. `http://localhost:8000/`); `{branch}` is replaced by the branch name |
| coverage | imports Cobertura XML / LCOV; paths from other machines are matched by suffix |

Issue types: bug, vulnerability, **security hotspot** (security-sensitive code to review: semgrep audit rules, low-confidence or blacklist bandit checks), code smell, accessibility.

**New code**: on a branch, everything changed since its merge-base with the main branch (plus uncommitted/untracked files for local scans); on main, everything since the previous analysis. An issue is new if it is on a changed line, or absent from the reference analysis in a changed file. Issues are fingerprinted by rule + file + source text, so they keep their identity, and any won't-fix / false-positive resolution, when code moves.

The default quality gate fails on new blocker/critical issues, new bugs, new vulnerabilities, new accessibility issues, new-code coverage below 80%, new-code duplication above 3%, and any critical dependency CVE. Edit it per project under **Settings**.

## Claude / MCP

Create a token for Claude on your Account page (a **read** token lets it list and resolve issues; a **scan** token can also start server-side scans), then:

```bash
claude mcp add codewatch -e CODEWATCH_URL=http://127.0.0.1:8100 -e CODEWATCH_TOKEN=cw_... \
  -- /path/to/codewatch/venv/bin/codewatch-mcp
```

Tools: `list_projects`, `quality_gate`, `list_issues` (filter by branch, new code, type, severity, tool, path), `list_security_hotspots`, `get_issue` (with source snippet), `resolve_issue`, `start_server_scan`. Paths are repo-relative, so the agent can fix issues in its local checkout and rescan with `codewatch scan`.

## HTTP API

All endpoints take `Authorization: Bearer <token>`.

| Method | Path | |
|---|---|---|
| GET | `/api/projects/` | projects you can see, with latest analysis per branch |
| GET | `/api/projects/<key>/status/?branch=` | latest analysis: gate, metrics, tools |
| GET | `/api/projects/<key>/issues/?branch=&new=1&type=&severity=&tool=&path=&status=&limit=&offset=` | issues, most severe first |
| GET | `/api/issues/<id>/?context=5` | one issue with source snippet |
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
