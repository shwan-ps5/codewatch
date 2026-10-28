from .models import SEVERITIES, IssueResolution, Metric


def issue_metrics(analysis):
    """Issue counts, overall and on new code, ignoring issues marked won't-fix or false positive."""
    resolved = set(
        IssueResolution.objects.filter(project=analysis.project).values_list("fingerprint", flat=True)
    )
    counts = {}
    for scope in ("", "new_"):
        for key in ("issues", "bugs", "vulnerabilities", "code_smells", *(f"{s}_issues" for s in SEVERITIES)):
            counts[scope + key] = 0
    type_key = {"bug": "bugs", "vulnerability": "vulnerabilities", "code_smell": "code_smells"}
    for fp, type_, severity, is_new in analysis.issues.values_list("fingerprint", "type", "severity", "is_new"):
        if fp in resolved:
            continue
        for scope in ("", "new_") if is_new else ("",):
            counts[scope + "issues"] += 1
            counts[scope + type_key[type_]] += 1
            counts[f"{scope}{severity}_issues"] += 1
    return counts


def evaluate(analysis, metrics):
    details = []
    for cond in analysis.project.gate_conditions.all():
        value = metrics.get(cond.metric)
        status = "no_value" if value is None else ("error" if cond.fails(value) else "ok")
        details.append(
            {"metric": cond.metric, "op": cond.op, "threshold": cond.threshold, "value": value, "status": status}
        )
    return all(d["status"] != "error" for d in details), details


def refresh(analysis):
    """Recompute issue counts and the gate, e.g. after an issue is resolved in the UI."""
    for key, value in issue_metrics(analysis).items():
        Metric.objects.update_or_create(analysis=analysis, key=key, defaults={"value": value})
    analysis.gate_passed, analysis.gate_details = evaluate(analysis, analysis.metrics_dict)
    analysis.save(update_fields=["gate_passed", "gate_details"])
