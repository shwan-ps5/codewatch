"""Running analyzers and turning their output into an upload payload.

Shared by the server (scanning a mirror worktree) and the codewatch-scan client (scanning a local working copy),
so it must not import Django.
"""
import fnmatch
import re
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .analyzers import ANALYZERS
from .analyzers.base import CODE, Context, Result
from .fingerprint import assign_fingerprints

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
MAX_SOURCE_BYTES = 512 * 1024
MAX_TOTAL_SOURCE_BYTES = 50 * 1024 * 1024


@dataclass
class ScanConfig:
    main_branch: str = ""
    exclusions: list[str] = field(default_factory=list)
    disabled_analyzers: list[str] = field(default_factory=list)
    semgrep_config: str = "p/default"
    complexity_threshold: int = 10
    a11y_urls: list[str] = field(default_factory=list)
    # Recent successful main-branch analyses, newest first: [{"commit": ..., "reference_commit": ...}]
    main_analyses: list[dict] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data):
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class GitError(RuntimeError):
    pass


def run_git(*args, cwd=None, check=True, env=None):
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=False, env=env)
    if check and proc.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def parse_diff(diff):
    """Map of path -> set of line numbers added or modified, from `git diff -U0` output."""
    changed, current = {}, None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            target = line[4:]
            current = None if target == "/dev/null" else target.removeprefix("b/")
            if current:
                changed.setdefault(current, set())
        elif current and (m := HUNK_RE.match(line)):
            start, count = int(m[1]), int(m[2]) if m[2] is not None else 1
            changed[current].update(range(start, start + count))
    return changed


class LocalRepo:
    """A developer's working copy, scanned as-is, including uncommitted and untracked (non-ignored) files."""

    def __init__(self, path):
        self.root = Path(run_git("rev-parse", "--show-toplevel", cwd=path).strip())

    def git(self, *args, check=True):
        return run_git(*args, cwd=self.root, check=check)

    def head(self):
        return self.git("rev-parse", "HEAD").strip()

    def branch(self):
        """Current branch, also before the first commit; "HEAD" when detached."""
        return self.git("symbolic-ref", "--short", "-q", "HEAD", check=False).strip() or "HEAD"

    def dirty(self):
        return bool(self.git("status", "--porcelain").strip())

    def files(self):
        listed = self.git("ls-files", "--cached", "--others", "--exclude-standard").splitlines()
        return sorted({f for f in listed if (self.root / f).is_file()})

    def untracked(self):
        return self.git("ls-files", "--others", "--exclude-standard").splitlines()

    def has_commit(self, commit):
        return bool(commit) and subprocess.run(
            ["git", "cat-file", "-e", f"{commit}^{{commit}}"], cwd=self.root, capture_output=True, check=False
        ).returncode == 0

    def is_ancestor(self, a, b):
        return subprocess.run(["git", "merge-base", "--is-ancestor", a, b], cwd=self.root, check=False).returncode == 0

    def merge_base(self, a, b):
        return self.git("merge-base", a, b, check=False).strip() or None

    def resolve_main(self, main_branch):
        """Prefer the remote-tracking ref: a local main is often stale."""
        for ref in (f"origin/{main_branch}", main_branch):
            commit = self.git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", check=False).strip()
            if commit:
                return commit
        return None

    def changed_lines(self, base):
        changed = parse_diff(self.git("diff", "-U0", "--no-renames", "--no-color", base))
        for f in self.untracked():
            try:
                count = len((self.root / f).read_text(errors="replace").splitlines())
            except OSError:
                continue
            changed[f] = set(range(1, count + 1))
        return changed


def choose_reference(branch, head, cfg, repo):
    """(reference_commit, reference_analysis_commit) defining "new code".

    Branches compare with their merge-base on main; main compares with its previous analysis. The reference
    analysis is the newest main analysis at or before the reference commit, whose issues count as already known.
    """
    ref = reference_commit(branch, head, cfg, repo)
    if not ref:
        return None, None
    commits = [a["commit"] for a in cfg.main_analyses]
    return ref, next((c for c in commits if c == ref or is_ancestor(repo, c, ref)), None)


def reference_commit(branch, head, cfg, repo):
    if branch != cfg.main_branch:
        main = repo.resolve_main(cfg.main_branch)
        return repo.merge_base(main, head) if main else None
    if not cfg.main_analyses:
        return None
    if cfg.main_analyses[0]["commit"] == head:
        return cfg.main_analyses[0].get("reference_commit") or None
    return next((a["commit"] for a in cfg.main_analyses if is_ancestor(repo, a["commit"], head)), None)


def is_ancestor(repo, a, b):
    return repo.has_commit(a) and repo.is_ancestor(a, b)


def excluded(path, patterns):
    # fnmatch's "*" already spans "/", so "**/x/**" needs a variant that also matches at the repo root.
    return any(fnmatch.fnmatch(path, p) or (p.startswith("**/") and fnmatch.fnmatch(path, p[3:])) for p in patterns)


def is_url(path):
    return path.startswith(("http://", "https://", "file://"))


def analyzer_skip_reason(analyzer, cfg, ctx):
    if analyzer.name in cfg.disabled_analyzers:
        return {"status": "disabled"}
    if not analyzer.applies(ctx):
        return {"status": "not_applicable"}
    if not analyzer.available():
        return {"status": "missing", "detail": f"{analyzer.executable} not found"}
    return None


def run_analyzers(cfg, ctx, log):
    """Run every applicable analyzer, merging their results; one tool failing doesn't fail the analysis."""
    tracked = set(ctx.files)
    combined, tools = Result(), {}
    for analyzer in ANALYZERS:
        skip = analyzer_skip_reason(analyzer, cfg, ctx)
        if skip:
            tools[analyzer.name] = skip
            continue
        log(f"Running {analyzer.name}")
        started = time.monotonic()
        try:
            result = analyzer.run(ctx)
        except Exception as exc:  # noqa: BLE001 - reported per tool in the UI
            tools[analyzer.name] = {"status": "error", "detail": str(exc)[-2000:]}
            log(f"  {analyzer.name} failed: {exc}")
            continue
        kept = [f for f in result.findings if f.path in tracked or is_url(f.path)]
        combined.findings += kept
        combined.metrics.update(result.metrics)
        combined.covered_lines.update(result.covered_lines)
        combined.coverable_lines.update(result.coverable_lines)
        combined.duplicated_lines.update(result.duplicated_lines)
        tools[analyzer.name] = {"status": "ok", "issues": len(kept), "seconds": round(time.monotonic() - started, 1)}
    return combined, tools


class LineReader:
    def __init__(self, root):
        self.root = root
        self.cache = {}

    def lines(self, path):
        if path not in self.cache:
            try:
                self.cache[path] = (self.root / path).read_text(errors="replace").splitlines()
            except OSError:
                self.cache[path] = []
        return self.cache[path]

    def __call__(self, path, line):
        lines = self.lines(path)
        return lines[line - 1] if line and 0 < line <= len(lines) else ""


def count_code_lines(reader, files):
    return sum(sum(1 for line in reader.lines(f) if line.strip()) for f in files)


def new_code_metrics(new_code, covered, coverable, duplicated):
    new_lines = sum(len(v) for v in new_code.values())
    metrics = {"new_lines": new_lines}
    to_cover = sum(len(lines & coverable.get(p, set())) for p, lines in new_code.items())
    if coverable and to_cover:
        hit = sum(len(lines & covered.get(p, set())) for p, lines in new_code.items())
        metrics["new_lines_to_cover"] = to_cover
        metrics["new_coverage"] = round(100 * hit / to_cover, 1)
    if new_lines and duplicated is not None:
        dup = sum(len(lines & duplicated.get(p, set())) for p, lines in new_code.items())
        metrics["new_duplicated_lines_percent"] = round(100 * dup / new_lines, 2)
    return metrics


def read_sources(root, paths):
    """Contents of files that have issues, so the server can show code without access to the repository."""
    sources, total = {}, 0
    for path in sorted(paths):
        p = root / path
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if size > MAX_SOURCE_BYTES or total + size > MAX_TOTAL_SOURCE_BYTES:
            continue
        sources[path] = p.read_text(errors="replace")
        total += size
    return sources


def make_context(cfg, root, files, branch, coverage_report, coverage_base):
    return Context(
        root=Path(root),
        files=files,
        complexity_threshold=cfg.complexity_threshold,
        semgrep_config=cfg.semgrep_config,
        exclusions=cfg.exclusions,
        a11y_urls=[u.replace("{branch}", branch) for u in cfg.a11y_urls],
        coverage_report=Path(coverage_report) if coverage_report else None,
        coverage_base=Path(coverage_base) if coverage_base else None,
    )


def code_only(changed, tracked):
    return {p: lines for p, lines in changed.items() if p in tracked and Path(p).suffix.lower() in CODE}


def collect(cfg, root, files, branch, changed, coverage_report=None, coverage_base=None, log=print):
    """Analyse `files` under `root`. `changed` maps path -> changed lines since the reference, or None."""
    files = [f for f in files if not excluded(f, cfg.exclusions)]
    ctx = make_context(cfg, root, files, branch, coverage_report, coverage_base)
    combined, tools = run_analyzers(cfg, ctx, log)
    metrics = combined.metrics
    reader = LineReader(ctx.root)
    code_files = [f for f in files if Path(f).suffix.lower() in CODE]
    metrics["files"] = len(code_files)
    metrics["ncloc"] = count_code_lines(reader, code_files)
    fingerprints = assign_fingerprints(combined.findings, reader)
    if changed is not None:
        duplicated = combined.duplicated_lines if "duplicated_lines" in metrics else None
        metrics.update(new_code_metrics(code_only(changed, set(files)), combined.covered_lines,
                                        combined.coverable_lines, duplicated))
    return build_payload(ctx.root, combined, tools, fingerprints, changed)


def build_payload(root, combined, tools, fingerprints, changed):
    issue_paths = {f.path for f in combined.findings if not is_url(f.path)}
    return {
        "tools": tools,
        "metrics": combined.metrics,
        "issues": [{**asdict(f), "fingerprint": fp} for f, fp in zip(combined.findings, fingerprints)],
        "changed_lines": None if changed is None else {
            p: sorted(lines) for p, lines in changed.items() if p in issue_paths
        },
        "sources": read_sources(root, issue_paths),
    }
