import hashlib
import traceback

from django.db import transaction
from django.utils import timezone

from . import catalog, gate
from .collect import ScanConfig, choose_reference, collect
from .git import Mirror
from .models import Analysis, AnalysisSource, Issue, Metric, SourceBlob

ISSUE_FIELDS = ("tool", "rule", "severity", "type", "message", "path", "line", "end_line", "fingerprint")


def ensure_main_branch(project, mirror):
    if not project.main_branch:
        project.main_branch = mirror.default_branch()
        project.save(update_fields=["main_branch"])


def scan(project, branch, coverage_report=None, coverage_base=None, log=print):
    """Server-side scan of a branch from the project's repository URL."""
    mirror = Mirror(project)
    log(f"Syncing {project.repo_url}")
    mirror.sync()
    ensure_main_branch(project, mirror)
    branch = branch or project.main_branch
    commit = mirror.rev_parse(branch)
    cfg = ScanConfig.from_dict(project.scan_config())
    ref, ref_analysis = choose_reference(branch, commit, cfg, mirror)
    analysis = Analysis.objects.create(
        project=project, branch=branch, commit=commit, reference_branch=project.main_branch,
        reference_commit=ref or "",
    )
    try:
        with mirror.worktree(commit, f"a{analysis.pk}") as root:
            changed = mirror.changed_lines(ref, commit) if ref else None
            payload = collect(cfg, root, mirror.tracked_files(commit), branch, changed,
                              coverage_report, coverage_base, log)
        payload.update(reference_analysis_commit=ref_analysis)
        ingest(analysis, payload)
        log(f"{len(payload['issues'])} issues, gate {'passed' if analysis.gate_passed else 'FAILED'}")
    except Exception:  # noqa: BLE001 - recorded on the analysis and shown in the UI
        analysis.status = Analysis.FAILED
        analysis.error = traceback.format_exc()
        analysis.finished_at = timezone.now()
        analysis.save()
        log(analysis.error)
    return analysis


def create_uploaded_analysis(project, payload, user):
    """Analysis record for a codewatch-scan upload; branch/commit/reference come from the client's git."""
    return Analysis.objects.create(
        project=project,
        branch=payload["branch"],
        commit=payload["commit"],
        reference_branch=project.main_branch,
        reference_commit=payload.get("reference_commit") or "",
        dirty=bool(payload.get("dirty")),
        origin="client",
        scanned_by=user,
    )


def ingest(analysis, payload):
    """Store a collect() payload on an analysis: issues with new-code flags, metrics, sources, then the gate."""
    ref_fps = reference_fingerprints(analysis.project, payload.get("reference_analysis_commit"))
    changed = {p: set(lines) for p, lines in (payload.get("changed_lines") or {}).items()}
    issues = dedupe([{k: i.get(k) for k in ISSUE_FIELDS} for i in payload["issues"]])
    metrics = dict(payload["metrics"])
    fixed = fixed_issue_count(analysis, {i["fingerprint"] for i in issues})
    if fixed is not None:
        metrics["fixed_issues"] = fixed

    with transaction.atomic():
        Issue.objects.bulk_create(
            Issue(analysis=analysis, **{**i, "rule": i["rule"][:300], "path": i["path"][:500]},
                  is_new=is_new(i, changed, ref_fps))
            for i in issues
        )
        Metric.objects.bulk_create(Metric(analysis=analysis, key=k, value=v) for k, v in metrics.items())
        store_sources(analysis, payload.get("sources") or {})
        analysis.tools = payload.get("tools", {})
        analysis.status = Analysis.SUCCESS
        analysis.finished_at = timezone.now()
        analysis.save()
        gate.refresh(analysis)
    return analysis


SEVERITY_RANK = {"blocker": 0, "critical": 1, "major": 2, "minor": 3, "info": 4}
SECURITY_TYPES = {"vulnerability", "security_hotspot"}


def same_check(a, b):
    """Two findings on one line are the same problem if the catalogue says the rules are equivalent,
    or both are security findings for a shared CWE."""
    ra, rb = catalog.lookup(a["tool"], a["rule"]), catalog.lookup(b["tool"], b["rule"])
    if not (ra and rb):
        return False
    if rb["id"] in ra.get("same_as", []):
        return True
    return a["type"] in SECURITY_TYPES and b["type"] in SECURITY_TYPES and bool(set(ra["cwe"]) & set(rb["cwe"]))


def dedupe(issues):
    """Keep the most severe of each group of duplicate findings, noting which other tools also reported it."""
    by_line, kept = {}, []
    for issue in sorted(issues, key=lambda i: SEVERITY_RANK.get(i["severity"], 5)):
        issue["also_reported_by"] = []
        if issue["line"] is None:
            kept.append(issue)
            continue
        group = by_line.setdefault((issue["path"], issue["line"]), [])
        twin = next((k for k in group if k["tool"] != issue["tool"] and same_check(k, issue)), None)
        if twin:
            twin["also_reported_by"].append(f"{issue['tool']}:{issue['rule']}")
        else:
            group.append(issue)
            kept.append(issue)
    return kept


def reference_fingerprints(project, commit):
    if not commit:
        return None
    ref = project.analyses.filter(
        branch=project.main_branch, commit=commit, status=Analysis.SUCCESS
    ).order_by("-started_at").first()
    return set(ref.issues.values_list("fingerprint", flat=True)) if ref else None


def store_sources(analysis, sources):
    for path, content in sources.items():
        sha = hashlib.sha256(content.encode()).hexdigest()
        blob, _ = SourceBlob.objects.get_or_create(sha=sha, defaults={"content": content})
        AnalysisSource.objects.create(analysis=analysis, path=path[:500], blob=blob)


def fixed_issue_count(analysis, fingerprints):
    previous = (
        analysis.project.analyses.filter(branch=analysis.branch, status=Analysis.SUCCESS)
        .exclude(pk=analysis.pk).order_by("-started_at").first()
    )
    if previous is None:
        return None
    return len(set(previous.issues.values_list("fingerprint", flat=True)) - fingerprints)


def is_new(issue, changed, ref_fps):
    lines = changed.get(issue["path"])
    if lines is None:
        return False
    if issue["line"] and issue["line"] in lines:
        return True
    # Issues caused by a change elsewhere in the file (e.g. an import left unused) sit on untouched lines.
    return ref_fps is not None and issue["fingerprint"] not in ref_fps
