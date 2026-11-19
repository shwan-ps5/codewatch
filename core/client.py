"""codewatch: scan a local working copy and upload the results.

The repository never leaves the machine; only issues, metrics and the source of files with issues are sent.
"""
import argparse
import contextlib
import gzip
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .analyzers.base import node_tool
from .catalog import custom_semgrep_rules
from .collect import GitError, LocalRepo, ScanConfig, ScanInput, choose_reference, collect, excluded

CONFIG_FILE = "codewatch-project.json"
COVERAGE_CANDIDATES = ["coverage.xml", "coverage/cobertura-coverage.xml", "coverage/lcov.info", "lcov.info"]
HOOK_MARKER = "# installed by codewatch init"
COVERAGE = "coverage"
ERROR = "error"
STORE_TRUE = "store_true"


class ClientError(Exception):
    pass


def log(message):
    print(message, file=sys.stderr, flush=True)


LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
# Servers this user has said they trust. The repository's codewatch-project.json may name one, but it is part of
# the repository: a branch could point it anywhere and collect the token and the code.
TRUSTED_SERVERS_FILE = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "codewatch" / "servers.txt"


def trusted_servers():
    listed = os.environ.get("CODEWATCH_TRUSTED_URLS", "").split(",")
    with contextlib.suppress(OSError):
        listed += TRUSTED_SERVERS_FILE.read_text().split()
    return {url.strip().rstrip("/") for url in listed if url.strip()}


def trust_server(url):
    if url.rstrip("/") not in trusted_servers():
        TRUSTED_SERVERS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with TRUSTED_SERVERS_FILE.open("a") as out:
            out.write(url.rstrip("/") + "\n")


def request(url, token, data=None, timeout=600):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ClientError(f"codewatch server URL must be http(s): {url}")
    if parts.scheme == "http" and parts.hostname not in LOCAL_HOSTS:
        raise ClientError(f"Not sending the token to {parts.hostname} over plain http; use https")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if data is not None:
        data = gzip.compress(json.dumps(data).encode())
        headers.update({"Content-Type": "application/json", "Content-Encoding": "gzip"})
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as exc:
        try:
            body = json.load(exc)
        except ValueError:
            body = {ERROR: exc.reason}
        return exc.code, body
    except urllib.error.URLError as exc:
        raise ClientError(f"Can't reach {url}: {exc.reason}") from exc


def detect_main_branch(repo):
    head = repo.git("symbolic-ref", "--quiet", "refs/remotes/origin/HEAD", check=False).strip()
    if head:
        return head.removeprefix("refs/remotes/origin/")
    for name in ("main", "master", "trunk", "develop"):
        if repo.git("rev-parse", "--verify", "--quiet", name, check=False).strip():
            return name
    return repo.branch()


def load_config(root):
    path = root / CONFIG_FILE
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except ValueError as exc:
        raise ClientError(f"{path} is not valid JSON: {exc}") from exc


def default_key(root):
    return re.sub(r"[^a-z0-9_-]+", "-", root.name.lower()).strip("-")


# --- scan -------------------------------------------------------------------------------------------------


def first(*values):
    return next((v for v in values if v), "")


@dataclass
class ScanTarget:
    """The working copy being scanned and where its results go."""

    args: argparse.Namespace
    repo: LocalRepo
    conf: dict
    url: str
    token: str
    key: str
    branch: str


def scan_target(args, repo, conf):
    url = first(args.url, os.environ.get("CODEWATCH_URL"))
    named = conf.get("serverUrl")
    if not url and named:
        if named.rstrip("/") not in trusted_servers():
            raise ClientError(f"{CONFIG_FILE} names the server {named}, which you haven't trusted. It is part of the "
                              f"repository, so check it, then add it to {TRUSTED_SERVERS_FILE} (or set CODEWATCH_URL)")
        url = named
    url = (url or "").rstrip("/")
    token = first(args.token, os.environ.get("CODEWATCH_TOKEN"))
    key = first(args.project, os.environ.get("CODEWATCH_PROJECT"), conf.get("projectKey"), default_key(repo.root))
    branch = first(args.branch, repo.branch())
    if branch == "HEAD":
        raise ClientError("Detached HEAD: pass --branch")
    return ScanTarget(args, repo, conf, url, token, key, branch)


def require_server(target):
    """An upload needs a server and a token (writing the payload to a file doesn't)."""
    if not target.args.output and not (target.url and target.token):
        raise ClientError(f"Set CODEWATCH_URL and CODEWATCH_TOKEN (or serverUrl in {CONFIG_FILE}, --url/--token)")


def fetch_config(target):
    cfg, created = server_config(target)
    # Local opt-outs (e.g. a slow tool) add to the server's list rather than replacing it.
    conf = target.conf
    cfg.disabled_analyzers = sorted(set(cfg.disabled_analyzers) | set(conf.get("disabledAnalyzers", [])))
    cfg.exclusions = list(dict.fromkeys([*cfg.exclusions, *conf.get("exclusions", [])]))
    return cfg, created


def server_config(target):
    url, token, key, repo = target.url, target.token, target.key, target.repo
    main = target.args.main_branch or target.conf.get("mainBranch")
    if not url:
        return default_config(main or detect_main_branch(repo)), True
    status, body = request(f"{url}/api/projects/{key}/config/", token)
    if status == 200:
        return ScanConfig.from_dict(body), False
    if status == 404:
        main = main or detect_main_branch(repo)
        log(f"Project {key} doesn't exist yet; it will be created (main branch: {main})")
        return default_config(main), True
    raise ClientError(f"Config request failed ({status}): {body.get('error')}")


def default_config(main_branch):
    """A new project's settings: the server would send the same built-in rules once the project exists."""
    return ScanConfig(main_branch=main_branch, custom_rules=custom_semgrep_rules())


def find_coverage(args, root, conf):
    explicit = args.coverage or conf.get("coverageReport")
    if explicit:
        return (root / explicit).resolve()
    return next((root / c for c in COVERAGE_CANDIDATES if (root / c).exists()), None)


def cmd_scan(args):
    repo = LocalRepo(args.path)
    conf = load_config(repo.root)
    target = scan_target(args, repo, conf)
    url, token, key, branch = target.url, target.token, target.key, target.branch
    require_server(target)
    cfg, created = fetch_config(target)
    head = repo.head()
    ref, ref_analysis = choose_reference(branch, head, cfg, repo)
    log(f"Scanning {repo.root} ({branch} @ {head[:8]}"
        + (f", new code since {ref[:8]})" if ref else ", no new-code reference yet)"))
    coverage = find_coverage(args, repo.root, conf)
    if coverage:
        log(f"Using coverage report {coverage}")
    changed = repo.changed_lines(ref) if ref else None
    payload = collect(cfg, ScanInput(repo.root, repo.files(), branch, changed, coverage, repo.root, local=True), log)
    payload.update(
        branch=branch, commit=head, dirty=repo.dirty(), reference_commit=ref,
        reference_analysis_commit=ref_analysis, main_branch=cfg.main_branch,
        project_name=args.name or conf.get("projectName") or key,
    )
    if args.output:
        Path(args.output).write_text(json.dumps(payload))
        log(f"Wrote {args.output}")
        return 0
    status, body = request(f"{url}/api/projects/{key}/analyses/", token, payload)
    if status != 201:
        raise ClientError(f"Upload failed ({status}): {body.get('error')}")
    report(body, created)
    return 1 if args.fail_on_gate and body.get("gate_passed") is False else 0


def report(body, created):
    m = body.get("metrics", {})
    gate = "passed" if body.get("gate_passed") else "FAILED"
    log(f"{'Created project. ' if created else ''}Quality gate {gate}: "
        f"{int(m.get('new_issues', 0))} new issues, {int(m.get('issues', 0))} total")
    for cond in body.get("gate", []):
        if cond["status"] == ERROR:
            log(f"  {cond['metric']} = {cond['value']:g} ({'>' if cond['op'] == 'gt' else '<'} {cond['threshold']:g})")
    log(body.get("url", ""))


# --- check ------------------------------------------------------------------------------------------------

# Whole-project checks, left out of a check of some files: the dependency audit, coverage and live pages.
PROJECT_WIDE_ANALYZERS = ("pip-audit", "osv", COVERAGE, "axe")
# What stops a commit, as the default gate's conditions on new issues: blockers and criticals, bugs, vulnerabilities.
BLOCKING_SEVERITIES = ("blocker", "critical")
BLOCKING_TYPES = ("bug", "vulnerability")


def files_to_check(repo, named, everything=False):
    """The named files, else (everything) the whole project, else the staged ones, else every file changed since
    the last commit (untracked too)."""
    if everything:
        return repo.files()
    if named:
        return sorted({os.path.relpath(Path(f).resolve(), repo.root) for f in named})
    def listed(*args):
        return [f for f in repo.git(*args).split("\0") if f]
    files = listed("diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR")
    if not files and repo.resolve_commit("HEAD"):
        files = listed("diff", "HEAD", "--name-only", "-z", "--diff-filter=ACMR") + repo.untracked()
    elif not files:
        files = repo.files()
    return sorted(set(files))


def check_config(args, repo, conf):
    """The project's settings from its server when one is configured and reachable, else the defaults; local
    opt-outs added either way, and the whole-project analyzers left out."""
    # Only the settings depend on the branch: a detached HEAD (a rebase in progress) is still checked.
    args.branch = args.branch or ("detached" if repo.branch() == "HEAD" else None)
    target = scan_target(args, repo, conf)
    cfg = default_config(target.conf.get("mainBranch", ""))
    if target.url and target.token:
        try:
            cfg, _created = server_config(target)
        except ClientError as exc:
            log(f"Using the default settings: {exc}")
    cfg.disabled_analyzers = sorted({*cfg.disabled_analyzers, *conf.get("disabledAnalyzers", []), *PROJECT_WIDE_ANALYZERS})
    cfg.exclusions = list(dict.fromkeys([*cfg.exclusions, *conf.get("exclusions", [])]))
    return cfg


def blocks(issue, changed, strict=False):
    """Whether an issue stops the commit: a blocking kind (any kind, strict), on a line this change touched (or
    anywhere, with changed=None)."""
    serious = strict or issue["severity"] in BLOCKING_SEVERITIES or issue["type"] in BLOCKING_TYPES
    if not serious:
        return False
    if changed is None:
        return True
    return bool(issue["line"]) and issue["line"] in changed.get(issue["path"], ())


def checked_files(repo, args, cfg):
    """files_to_check that exist; when none were named, without the project's exclusions."""
    return [f for f in files_to_check(repo, args.files, args.all)
            if (repo.root / f).is_file() and (args.files or not excluded(f, cfg.exclusions))]


REVIEWS_FILE = "codewatch-reviews.json"
REVIEW_STATUSES = ("safe", "false_positive")


def load_reviews(root):
    """{fingerprint: review} from the repository's codewatch-reviews.json: findings someone read and judged safe
    or a false positive, each with the reason, kept in the repository where anyone can read and question it."""
    path = root / REVIEWS_FILE
    if not path.exists():
        return {}
    reviews = json.loads(path.read_text())
    bad = [r for r in reviews if r.get("status") not in REVIEW_STATUSES or not r.get("comment")]
    if bad:
        raise ClientError(f"{REVIEWS_FILE}: every review needs a status ({', '.join(REVIEW_STATUSES)}) and a "
                          f"reason in comment; not {bad[0]}")
    return {r["fingerprint"]: r for r in reviews}


def issue_line(issue):
    return (f"{issue['path']}:{issue['line'] or '-'}: {issue['severity']} {issue['type']} "
            f"{issue['tool']}:{issue['rule']}: {issue['message'].splitlines()[0][:200]}")


def print_issues(issues, blocking, reviewed):
    for i in issues:
        mark = "!" if i in blocking else " "
        print(f"{mark} {issue_line(i)}", flush=True)
    for i in reviewed:
        review = i["review"]
        print(f"= {issue_line(i)}\n    reviewed {review['status']}: {review['comment']}", flush=True)


def failed_tools(payload):
    """{analyzer: what went wrong} for each analyzer that failed, said aloud: their files weren't fully checked."""
    failed = {name: t.get("detail", "") for name, t in payload["tools"].items() if t.get("status") == ERROR}
    for name, detail in failed.items():
        log(f"codewatch check: {name} failed, so these files weren't fully checked: {detail[:300]}")
    return failed


def cmd_check(args):
    """Every analyzer on some files, nothing uploaded and nothing run: exit 1 if a changed line has a bug, a
    vulnerability or a blocker/critical issue, 2 if an analyzer failed (the files weren't fully checked)."""
    repo = LocalRepo(".")
    cfg = check_config(args, repo, load_config(repo.root))
    files = checked_files(repo, args, cfg)
    if not files:
        log("codewatch check: no files to check")
        return 0
    changed = changed_lines(repo, args.all_lines or args.all)
    log(f"Checking {len(files)} file(s): " + ", ".join(files[:5]) + (", ..." if len(files) > 5 else ""))
    payload = collect(cfg, ScanInput(repo.root, files, repo.branch(), changed, None, repo.root, local=True),
                      check_log(args.verbose))
    issues, reviewed = split_reviewed(payload["issues"], load_reviews(repo.root))
    blocking = [i for i in issues if blocks(i, changed, args.strict)]
    print_issues(issues, blocking, reviewed)
    failed = failed_tools(payload)
    where = "anywhere in these files" if changed is None else "on changed lines"
    log(f"{len(issues)} open issue(s) and {len(reviewed)} reviewed in {len(files)} file(s); "
        f"{len(blocking)} blocking {where} (marked !)")
    write_summary(files, issues, reviewed, blocking, failed)
    return check_exit(blocking, failed)


def split_reviewed(found, reviews):
    """(open issues, reviewed ones with their review), each in file and line order."""
    found = sorted(found, key=lambda i: (i["path"], i["line"] or 0))
    return ([i for i in found if i["fingerprint"] not in reviews],
            [{**i, "review": reviews[i["fingerprint"]]} for i in found if i["fingerprint"] in reviews])


def open_counts(issues):
    """"2 bug, 1 code smell" for the open issues, or "none"."""
    kinds = {}
    for i in issues:
        kinds[i["type"]] = kinds.get(i["type"], 0) + 1
    return ", ".join(f"{n} {kind.replace('_', ' ')}" for kind, n in sorted(kinds.items())) or "none"


def reviewed_table(reviewed):
    if not reviewed:
        return []
    return ["", f"### {len(reviewed)} reviewed findings ({REVIEWS_FILE})", "",
            "| Where | Finding | Verdict | Reason |", "|---|---|---|---|"] + [
        f"| `{i['path']}:{i['line'] or '-'}` | {i['tool']}:{i['rule']} | {i['review']['status']} | "
        f"{i['review']['comment'].replace('|', '/')} |" for i in reviewed]


def write_summary(files, issues, reviewed, blocking, failed):
    """A Markdown report where GitHub Actions shows one ($GITHUB_STEP_SUMMARY), for anyone reading the run."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    verdict = "fails" if blocking or failed else "passes"
    lines = [f"## codewatch check {verdict}", "",
             f"{len(files)} files checked by every analyzer. Open issues: {open_counts(issues)}.", ""]
    lines += [f"- **{name} failed**, so the files weren't fully checked: {detail[:300]}" for name, detail in failed.items()]
    lines += [f"- `{issue_line(i)}`" for i in issues] + reviewed_table(reviewed)
    with open(path, "a") as out:
        out.write("\n".join(lines) + "\n")


def changed_lines(repo, all_lines):
    """{path: lines} changed since the last commit; None (every line counts) with --all-lines or no commit yet."""
    if all_lines or not repo.resolve_commit("HEAD"):
        return None
    return repo.changed_lines("HEAD")


def check_log(verbose):
    """Each analyzer as it runs with --verbose, else only what went wrong."""
    if verbose:
        return log
    return lambda message: log(message) if "failed" in message else None


def check_exit(blocking, failed):
    """1 when something blocks, else 2 when an analyzer failed (not fully checked), else 0."""
    if blocking:
        return 1
    return 2 if failed else 0


# --- coverage ---------------------------------------------------------------------------------------------


def project_python(root):
    for candidate in ("venv/bin/python", ".venv/bin/python", "env/bin/python"):
        if (root / candidate).exists():
            return str(root / candidate)
    return sys.executable


def coverage_commands(root, conf):
    """Commands that run the project's tests and leave a coverage report where `scan` looks for one."""
    if conf.get("testCommand"):
        return [["sh", "-c", conf["testCommand"]]]
    if any((root / f).exists() for f in ("pyproject.toml", "setup.py", "setup.cfg", "pytest.ini", "manage.py")):
        py = project_python(root)
        if subprocess.run([py, "-c", "import coverage, pytest"], capture_output=True, check=False).returncode:
            raise ClientError(f"{py} needs coverage and pytest: {py} -m pip install coverage pytest "
                              f"(or set testCommand in {CONFIG_FILE})")
        return [[py, "-m", COVERAGE, "run", "-m", "pytest"], [py, "-m", COVERAGE, "xml", "-o", "coverage.xml"]]
    package = root / "package.json"
    if package.exists() and json.loads(package.read_text()).get("scripts", {}).get("test"):
        c8 = node_tool("c8")
        if c8 is None:
            raise ClientError("c8 missing: run npm ci --prefix tools in the codewatch checkout")
        return [[c8, "--reporter=cobertura", "--reports-dir=coverage", "npm", "test"]]
    raise ClientError(f"Don't know how to run these tests; set testCommand in {CONFIG_FILE}")


def cmd_coverage(args):
    repo = LocalRepo(args.path)
    for command in coverage_commands(repo.root, load_config(repo.root)):
        log("$ " + shlex.join(command))
        code = subprocess.run(command, cwd=repo.root, check=False).returncode
        if code != 0:
            log(f"codewatch: tests failed (exit {code})")
            return code
    return 0


# --- init -------------------------------------------------------------------------------------------------


def hook_script(strict, name="pre-push"):
    exe = shlex.quote(str(Path(sys.argv[0]).resolve()))
    if name == "pre-commit":
        return f"""#!/bin/sh
{HOOK_MARKER}
# Checks the staged files: a bug, vulnerability or blocker/critical issue on a changed line stops the commit
# (git commit --no-verify skips it). Nothing is uploaded or run. Remove this file to disable.
{exe} check
"""
    scan = f"{exe} scan --fail-on-gate" if strict else f"{exe} scan || echo 'codewatch: scan failed (push continues)'"
    return f"""#!/bin/sh
{HOOK_MARKER}
# Runs tests with coverage, then uploads a scan of this branch. Remove this file to disable.
{exe} coverage || exit 1
{scan}
"""


def install_hook(repo, name, strict):
    hooks = Path(repo.git("rev-parse", "--git-path", "hooks").strip())
    hooks = hooks if hooks.is_absolute() else repo.root / hooks
    path = hooks / name
    if path.exists() and HOOK_MARKER not in path.read_text():
        raise ClientError(f"{path} already exists and wasn't written by codewatch; add these lines to it:\n"
                          + hook_script(strict, name))
    hooks.mkdir(parents=True, exist_ok=True)
    path.write_text(hook_script(strict, name))
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    log(f"Installed {path}")


def cmd_init(args):
    repo = LocalRepo(args.path)
    path = repo.root / CONFIG_FILE
    conf = load_config(repo.root)
    conf.setdefault("projectKey", args.project or default_key(repo.root))
    conf.setdefault("projectName", args.name or conf["projectKey"])
    conf.setdefault("mainBranch", detect_main_branch(repo))
    if args.url or os.environ.get("CODEWATCH_URL"):
        conf.setdefault("serverUrl", (args.url or os.environ["CODEWATCH_URL"]).rstrip("/"))
        # This user chose it.
        trust_server(args.url or os.environ["CODEWATCH_URL"])
    path.write_text(json.dumps(conf, indent=2) + "\n")
    log(f"Wrote {path} (commit it; keep the token in CODEWATCH_TOKEN, never in this file)")
    if args.hook != "none":
        install_hook(repo, args.hook, args.strict)
    return 0


# --- entry points -----------------------------------------------------------------------------------------


def add_scan_args(p):
    p.add_argument("path", nargs="?", default=".", help="Working copy (default: current directory)")
    p.add_argument("--url", help="codewatch server (env CODEWATCH_URL, or serverUrl in codewatch-project.json)")
    p.add_argument("--token", help="API token with scan scope (env CODEWATCH_TOKEN)")
    p.add_argument("--project", help="Project key (default: projectKey in codewatch-project.json, else folder name)")
    p.add_argument("--name", help="Display name when the project is created")
    p.add_argument("--branch", help="Branch name (default: current branch; required on a detached HEAD)")
    p.add_argument("--main-branch", help="Main branch for a new project (default: origin's HEAD branch)")
    p.add_argument("--coverage", help="Cobertura XML or LCOV report (default: auto-detected)")
    p.add_argument("--fail-on-gate", action=STORE_TRUE, help="Exit 1 if the quality gate fails")
    p.add_argument("--output", help="Write the payload to this file instead of uploading")


def build_parser():
    parser = argparse.ArgumentParser(prog="codewatch", description=(__doc__ or "codewatch").splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    add_scan_args(sub.add_parser("scan", help="Analyse the working copy and upload the results"))
    check = sub.add_parser("check", help="Check some files locally, uploading nothing (default: the changed ones)")
    check.add_argument("files", nargs="*", help="Files to check (default: staged files, else every changed file)")
    check.add_argument("--all", action=STORE_TRUE, help="Every file in the project (the whole-project check CI runs)")
    check.add_argument("--strict", action=STORE_TRUE,
                       help="Every open issue blocks, of any kind or severity, not only new serious ones")
    check.add_argument("--all-lines", action=STORE_TRUE,
                       help="Block on issues anywhere in the files, not only on changed lines")
    check.add_argument("--verbose", action=STORE_TRUE, help="Show each analyzer as it runs")
    for name in ("--url", "--token", "--project", "--branch"):
        check.add_argument(name, help="As for scan: where the project's settings come from")
    check.set_defaults(main_branch=None)
    cov = sub.add_parser(COVERAGE, help="Run the tests with coverage, writing a report scan picks up")
    cov.add_argument("path", nargs="?", default=".")
    init = sub.add_parser("init", help=f"Write {CONFIG_FILE} and optionally install a git hook")
    init.add_argument("path", nargs="?", default=".")
    init.add_argument("--project")
    init.add_argument("--name")
    init.add_argument("--url")
    init.add_argument("--hook", choices=["pre-push", "pre-commit", "none"], default="none")
    init.add_argument("--strict", action=STORE_TRUE, help="Make the hook block when the quality gate fails")
    bench = sub.add_parser("benchmark", help="Score codewatch against suites with known vulnerabilities")
    bench.add_argument("suites", nargs="*", help="Suite names from benchmarks/suites.json (default: all)")
    return parser


def cmd_benchmark(args):
    from .benchmark import WORKERS
    from .benchmark import run as run_benchmarks

    for name, result in run_benchmarks(args.suites or None, log=log, workers=WORKERS).items():
        log(f"{name}: {json.dumps(result['overall'])}")
    return 0


COMMANDS = {"scan": cmd_scan, "check": cmd_check, COVERAGE: cmd_coverage, "init": cmd_init,
            "benchmark": cmd_benchmark}


def run(args):
    try:
        return COMMANDS[args.command](args)
    except (ClientError, GitError) as exc:
        log(f"codewatch: {exc}")
        return 2


def main(argv=None):
    return run(build_parser().parse_args(argv))


def scan_main(argv=None):
    """`codewatch-scan` is shorthand for `codewatch scan`."""
    return main(["scan", *(sys.argv[1:] if argv is None else argv)])


if __name__ == "__main__":
    sys.exit(main())
