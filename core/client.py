"""codewatch: scan a local working copy and upload the results, like sonar-scanner.

The repository never leaves the machine; only issues, metrics and the source of files with issues are sent.
"""
import argparse
import gzip
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .analyzers.base import node_tool
from .collect import GitError, LocalRepo, ScanConfig, ScanInput, choose_reference, collect

CONFIG_FILE = "codewatch-project.json"
COVERAGE_CANDIDATES = ["coverage.xml", "coverage/cobertura-coverage.xml", "coverage/lcov.info", "lcov.info"]
HOOK_MARKER = "# installed by codewatch init"


class ClientError(Exception):
    pass


def log(message):
    print(message, file=sys.stderr, flush=True)


def request(url, token, data=None, timeout=600):
    if not url.startswith(("http://", "https://")):
        raise ClientError(f"codewatch server URL must be http(s): {url}")
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
            body = {"error": exc.reason}
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
    url = first(args.url, os.environ.get("CODEWATCH_URL"), conf.get("serverUrl")).rstrip("/")
    token = first(args.token, os.environ.get("CODEWATCH_TOKEN"))
    key = first(args.project, os.environ.get("CODEWATCH_PROJECT"), conf.get("projectKey"), default_key(repo.root))
    branch = first(args.branch, repo.branch())
    if branch == "HEAD":
        raise ClientError("Detached HEAD: pass --branch")
    if not args.output and not (url and token):
        raise ClientError(f"Set CODEWATCH_URL and CODEWATCH_TOKEN (or serverUrl in {CONFIG_FILE}, --url/--token)")
    return ScanTarget(args, repo, conf, url, token, key, branch)


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
        return ScanConfig(main_branch=main or detect_main_branch(repo)), True
    status, body = request(f"{url}/api/projects/{key}/config/", token)
    if status == 200:
        return ScanConfig.from_dict(body), False
    if status == 404:
        main = main or detect_main_branch(repo)
        log(f"Project {key} doesn't exist yet; it will be created (main branch: {main})")
        return ScanConfig(main_branch=main), True
    raise ClientError(f"Config request failed ({status}): {body.get('error')}")


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
    cfg, created = fetch_config(target)
    head = repo.head()
    ref, ref_analysis = choose_reference(branch, head, cfg, repo)
    log(f"Scanning {repo.root} ({branch} @ {head[:8]}"
        + (f", new code since {ref[:8]})" if ref else ", no new-code reference yet)"))
    coverage = find_coverage(args, repo.root, conf)
    if coverage:
        log(f"Using coverage report {coverage}")
    changed = repo.changed_lines(ref) if ref else None
    payload = collect(cfg, ScanInput(repo.root, repo.files(), branch, changed, coverage, repo.root), log)
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
        if cond["status"] == "error":
            log(f"  {cond['metric']} = {cond['value']:g} ({'>' if cond['op'] == 'gt' else '<'} {cond['threshold']:g})")
    log(body.get("url", ""))


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
        return [[py, "-m", "coverage", "run", "-m", "pytest"], [py, "-m", "coverage", "xml", "-o", "coverage.xml"]]
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


def hook_script(strict):
    exe = shlex.quote(str(Path(sys.argv[0]).resolve()))
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
                          + hook_script(strict))
    hooks.mkdir(parents=True, exist_ok=True)
    path.write_text(hook_script(strict))
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
    p.add_argument("--fail-on-gate", action="store_true", help="Exit 1 if the quality gate fails")
    p.add_argument("--output", help="Write the payload to this file instead of uploading")


def build_parser():
    parser = argparse.ArgumentParser(prog="codewatch", description=(__doc__ or "codewatch").splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    add_scan_args(sub.add_parser("scan", help="Analyse the working copy and upload the results"))
    cov = sub.add_parser("coverage", help="Run the tests with coverage, writing a report scan picks up")
    cov.add_argument("path", nargs="?", default=".")
    init = sub.add_parser("init", help=f"Write {CONFIG_FILE} and optionally install a git hook")
    init.add_argument("path", nargs="?", default=".")
    init.add_argument("--project")
    init.add_argument("--name")
    init.add_argument("--url")
    init.add_argument("--hook", choices=["pre-push", "pre-commit", "none"], default="none")
    init.add_argument("--strict", action="store_true", help="Make the hook block when the quality gate fails")
    return parser


COMMANDS = {"scan": cmd_scan, "coverage": cmd_coverage, "init": cmd_init}


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
