import fnmatch
import time
import traceback
from pathlib import Path

from django.db import transaction
from django.utils import timezone

from . import gate
from .analyzers import ANALYZERS
from .analyzers.base import CODE, Context, Result
from .fingerprint import assign_fingerprints
from .git import Mirror
from .models import Analysis, Issue, Metric


def excluded(path, patterns):
    # fnmatch's "*" already spans "/", so "**/x/**" needs a variant that also matches at the repo root.
    return any(fnmatch.fnmatch(path, p) or (p.startswith("**/") and fnmatch.fnmatch(path, p[3:])) for p in patterns)


def find_reference(project, mirror, branch, commit):
    """Commit that defines "new code": merge-base with main for branches, the previous analysis on main."""
    if branch != project.main_branch:
        return project.main_branch, mirror.merge_base(mirror.rev_parse(project.main_branch), commit)
    previous = (
        project.analyses.filter(branch=branch, status=Analysis.SUCCESS).order_by("-started_at").first()
    )
    if previous is None:
        return branch, None
    if previous.commit == commit:
        return branch, previous.reference_commit or None
    if mirror.has_commit(previous.commit) and mirror.is_ancestor(previous.commit, commit):
        return branch, previous.commit
    return branch, None


def reference_analysis(project, mirror, ref_branch, ref_commit):
    candidates = project.analyses.filter(branch=ref_branch, status=Analysis.SUCCESS).order_by("-started_at")
    exact = candidates.filter(commit=ref_commit).first()
    if exact:
        return exact
    for a in candidates:
        if mirror.has_commit(a.commit) and mirror.is_ancestor(a.commit, ref_commit):
            return a
    return None


def count_code_lines(root, files):
    total = 0
    for f in files:
        try:
            total += sum(1 for line in (root / f).read_text(errors="replace").splitlines() if line.strip())
        except OSError:
            pass
    return total


def scan(project, branch, coverage_report=None, coverage_base=None, log=print):
    mirror = Mirror(project)
    log(f"Syncing {project.repo_url}")
    mirror.sync()
    commit = mirror.rev_parse(branch)
    ref_branch, ref_commit = find_reference(project, mirror, branch, commit)
    analysis = Analysis.objects.create(
        project=project, branch=branch, commit=commit, reference_branch=ref_branch, reference_commit=ref_commit or ""
    )
    try:
        with mirror.worktree(commit, f"a{analysis.pk}") as root:
            run_analysis(project, mirror, analysis, root, coverage_report, coverage_base, log)
        analysis.status = Analysis.SUCCESS
    except Exception:  # noqa: BLE001 - recorded on the analysis and shown in the UI
        analysis.status = Analysis.FAILED
        analysis.error = traceback.format_exc()
        log(analysis.error)
    analysis.finished_at = timezone.now()
    analysis.save()
    return analysis


def run_analysis(project, mirror, analysis, root, coverage_report, coverage_base, log):
    files = [f for f in mirror.tracked_files(analysis.commit) if not excluded(f, project.exclusions)]
    ctx = Context(
        root=root,
        files=files,
        complexity_threshold=project.complexity_threshold,
        semgrep_config=project.semgrep_config,
        exclusions=project.exclusions,
        coverage_report=Path(coverage_report) if coverage_report else None,
        coverage_base=Path(coverage_base) if coverage_base else None,
    )
    combined, analysis.tools = run_analyzers(project, ctx, log)
    findings, metrics = combined.findings, combined.metrics

    code_files = [f for f in files if Path(f).suffix.lower() in CODE]
    metrics["files"] = len(code_files)
    metrics["ncloc"] = count_code_lines(root, code_files)

    fingerprints = assign_fingerprints(findings, LineReader(root))
    changed, ref_fps = new_code(project, mirror, analysis, combined, set(files))
    fixed = fixed_issue_count(analysis, fingerprints)
    if fixed is not None:
        metrics["fixed_issues"] = fixed
    save_results(analysis, findings, fingerprints, metrics, changed, ref_fps)
    log(f"{len(findings)} issues, gate {'passed' if analysis.gate_passed else 'FAILED'}")


def new_code(project, mirror, analysis, combined, tracked):
    """Changed lines since the reference commit, plus the reference analysis' fingerprints if one exists.

    Adds new-code metrics to combined.metrics as a side effect.
    """
    if not analysis.reference_commit:
        return {}, None
    changed = mirror.changed_lines(analysis.reference_commit, analysis.commit)
    ref = reference_analysis(project, mirror, analysis.reference_branch, analysis.reference_commit)
    ref_fps = set(ref.issues.values_list("fingerprint", flat=True)) if ref else None
    code = {p: lines for p, lines in changed.items() if p in tracked and Path(p).suffix.lower() in CODE}
    duplicated = combined.duplicated_lines if "duplicated_lines" in combined.metrics else None
    combined.metrics.update(new_code_metrics(code, combined.covered_lines, combined.coverable_lines, duplicated))
    return changed, ref_fps


def save_results(analysis, findings, fingerprints, metrics, changed, ref_fps):
    with transaction.atomic():
        Issue.objects.bulk_create(
            Issue(
                analysis=analysis, fingerprint=fp, tool=f.tool, rule=f.rule[:300], severity=f.severity,
                type=f.type, message=f.message, path=f.path, line=f.line, end_line=f.end_line,
                is_new=is_new(f, fp, changed, ref_fps),
            )
            for f, fp in zip(findings, fingerprints)
        )
        Metric.objects.bulk_create(Metric(analysis=analysis, key=k, value=v) for k, v in metrics.items())
        gate.refresh(analysis)


def analyzer_skip_reason(analyzer, project, ctx):
    if analyzer.name in project.disabled_analyzers:
        return {"status": "disabled"}
    if not analyzer.applies(ctx):
        return {"status": "not_applicable"}
    if not analyzer.available():
        return {"status": "missing", "detail": f"{analyzer.executable} not found"}
    return None


def run_analyzers(project, ctx, log):
    """Run every applicable analyzer, merging their results; one tool failing doesn't fail the analysis."""
    tracked = set(ctx.files)
    combined, tools = Result(), {}
    for analyzer in ANALYZERS:
        skip = analyzer_skip_reason(analyzer, project, ctx)
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
        kept = [f for f in result.findings if f.path in tracked]
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

    def __call__(self, path, line):
        if path not in self.cache:
            try:
                self.cache[path] = (self.root / path).read_text(errors="replace").splitlines()
            except OSError:
                self.cache[path] = []
        lines = self.cache[path]
        return lines[line - 1] if line and 0 < line <= len(lines) else ""


def fixed_issue_count(analysis, fingerprints):
    previous = (
        analysis.project.analyses.filter(branch=analysis.branch, status=Analysis.SUCCESS)
        .exclude(pk=analysis.pk).order_by("-started_at").first()
    )
    if previous is None:
        return None
    return len(set(previous.issues.values_list("fingerprint", flat=True)) - set(fingerprints))


def is_new(finding, fingerprint, changed, ref_fps):
    lines = changed.get(finding.path)
    if lines is None:
        return False
    if finding.line and finding.line in lines:
        return True
    # Issues caused by a change elsewhere in the file (e.g. an import left unused) sit on untouched lines.
    return ref_fps is not None and fingerprint not in ref_fps


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
