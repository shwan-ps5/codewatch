from . import ratings
from .models import SEVERITIES, IssueResolution, Metric

TYPE_KEY = {
    "bug": "bugs",
    "vulnerability": "vulnerabilities",
    "security_hotspot": "security_hotspots",
    "code_smell": "code_smells",
    "accessibility": "accessibility_issues",
}
A11Y_TOOLS = ("html-a11y", "jsx-a11y", "axe")


def issue_metrics(analysis):
    """Issue counts and ratings, overall and on new code, ignoring issues marked won't-fix or false positive."""
    resolved = set(
        IssueResolution.objects.filter(project=analysis.project).values_list("fingerprint", flat=True)
    )
    counts = {}
    for scope in ("", "new_"):
        for key in (*TYPE_KEY.values(), "issues", *(f"{s}_issues" for s in SEVERITIES)):
            counts[scope + key] = 0
    rows, reviewed = tally(analysis, resolved, counts)
    base = analysis.metrics_dict
    base["_has_accessibility"] = any(analysis.tools.get(t, {}).get("status") == "ok" for t in A11Y_TOOLS)
    for scope in ("", "new_"):
        counts.update(ratings.compute(rows[scope], reviewed[scope], base, scope))
    return counts


# Percentages over a handful of changed lines swing wildly, so these conditions wait for enough new code.
MIN_NEW_LINES = 20
SMALL_CHANGE_METRICS = {"new_coverage", "new_duplicated_lines_percent"}


def condition_status(cond, value, metrics):
    if value is None:
        return "no_value"
    if cond.metric in SMALL_CHANGE_METRICS and metrics.get("new_lines", 0) < MIN_NEW_LINES:
        return "too_few_lines"
    return "error" if cond.fails(value) else "ok"


def tally(analysis, resolved, counts):
    """Count open issues into `counts`; return open (type, severity) rows and reviewed hotspots per scope."""
    rows = {"": [], "new_": []}
    reviewed = {"": 0, "new_": 0}
    for fp, type_, severity, is_new in analysis.issues.values_list("fingerprint", "type", "severity", "is_new"):
        scopes = ("", "new_") if is_new else ("",)
        for scope in scopes:
            if fp in resolved:
                reviewed[scope] += type_ == "security_hotspot"
                continue
            counts[scope + "issues"] += 1
            counts[scope + TYPE_KEY[type_]] += 1
            counts[f"{scope}{severity}_issues"] += 1
            rows[scope].append((type_, severity))
    return rows, reviewed


def evaluate(analysis, metrics):
    details = []
    for cond in analysis.project.gate_conditions.all():
        value = metrics.get(cond.metric)
        status = condition_status(cond, value, metrics)
        details.append(
            {"metric": cond.metric, "op": cond.op, "threshold": cond.threshold, "value": value, "status": status}
        )
    return all(d["status"] != "error" for d in details), details


def refresh(analysis):
    """Recompute issue counts, ratings and the gate, e.g. after an issue is resolved in the UI."""
    for key, value in issue_metrics(analysis).items():
        Metric.objects.update_or_create(analysis=analysis, key=key, defaults={"value": value})
    analysis.gate_passed, analysis.gate_details = evaluate(analysis, analysis.metrics_dict)
    analysis.save(update_fields=["gate_passed", "gate_details"])
