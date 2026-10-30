"""Merge findings that several analyzers (or one analyzer, repeatedly) report for the same problem on one line.

The strongest report is kept (a confirmed vulnerability over a hotspot to review, then the most severe) and
takes the group's highest severity; the others are listed in its also_reported_by as "tool:rule", so a finding
still shows every detector that agreed on it.
"""
from . import catalog

SEVERITY_RANK = {"blocker": 0, "critical": 1, "major": 2, "minor": 3, "info": 4}
TYPE_RANK = {"vulnerability": 0, "bug": 1, "security_hotspot": 2, "accessibility": 3, "code_smell": 4}
SECURITY_TYPES = {"vulnerability", "security_hotspot"}
# Pillar and category CWEs that many unrelated quality rules share; agreeing on one of these says nothing.
BROAD_CWES = {398, 664, 682, 691, 693, 697, 703, 707, 710, 1006, 1041, 1076, 1078, 1164, 1177}


def same_check(a, b):
    """Same tool and rule, rules the catalogue calls equivalent, or rules sharing a specific CWE."""
    if a["tool"] == b["tool"]:
        return a["rule"] == b["rule"]
    ra, rb = catalog.lookup(a["tool"], a["rule"]), catalog.lookup(b["tool"], b["rule"])
    if not (ra and rb):
        return False
    if rb["id"] in (ra.get("same_as") or []) or ra["id"] in (rb.get("same_as") or []):
        return True
    shared = set(ra["cwe"]) & set(rb["cwe"])
    if a["type"] in SECURITY_TYPES and b["type"] in SECURITY_TYPES:
        return bool(shared)
    return a["type"] == b["type"] and bool(shared - BROAD_CWES)


def dedupe(issues):
    """One finding per problem per line; already-merged input (from the scan client) is merged again unchanged."""
    by_line, kept = {}, []
    for issue in sorted(issues, key=lambda i: (TYPE_RANK.get(i["type"], 5), SEVERITY_RANK.get(i["severity"], 5))):
        issue["also_reported_by"] = list(issue.get("also_reported_by") or [])
        if issue.get("line") is None:
            kept.append(issue)
            continue
        group = by_line.setdefault((issue["path"], issue["line"]), [])
        twin = next((k for k in group if same_check(k, issue)), None)
        if twin is None:
            group.append(issue)
            kept.append(issue)
            continue
        if SEVERITY_RANK.get(issue["severity"], 5) < SEVERITY_RANK.get(twin["severity"], 5):
            twin["severity"] = issue["severity"]
        for source in [f"{issue['tool']}:{issue['rule']}", *issue["also_reported_by"]]:
            if source != f"{twin['tool']}:{twin['rule']}" and source not in twin["also_reported_by"]:
                twin["also_reported_by"].append(source)
    return kept
