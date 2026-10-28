"""Project ratings (A-E) and an overall health score.

Reliability, security and accessibility are rated by the worst open issue of that type. Maintainability uses
the SQALE technical-debt ratio: estimated remediation effort for code smells divided by the estimated cost of
writing the code. Security review is the share of security hotspots that have been reviewed (resolved).
"""
GRADES = "ABCDE"
WORST_SEVERITY_RATING = {"blocker": 5, "critical": 4, "major": 3, "minor": 2, "info": 2}
# Remediation estimates in minutes per code smell, by severity.
REMEDIATION_MINUTES = {"blocker": 120, "critical": 60, "major": 20, "minor": 5, "info": 1}
MINUTES_PER_LINE = 30
DEBT_RATIO_LIMITS = [(5, 1), (10, 2), (20, 3), (50, 4)]
REVIEW_LIMITS = [(80, 1), (70, 2), (50, 3), (30, 4)]
SCORE = {1: 100, 2: 80, 3: 60, 4: 40, 5: 20}

RATED_TYPES = {"bug": "reliability", "vulnerability": "security", "accessibility": "accessibility"}


def grade(rating):
    return GRADES[int(rating) - 1] if rating else "\u2013"


def worst(severities):
    return max((WORST_SEVERITY_RATING[s] for s in severities), default=1)


def debt_rating(minutes, lines):
    if not lines:
        return 1
    ratio = 100 * minutes / (lines * MINUTES_PER_LINE)
    return next((r for limit, r in DEBT_RATIO_LIMITS if ratio <= limit), 5)


def review_rating(open_hotspots, reviewed):
    total = open_hotspots + reviewed
    if not total:
        return 1
    pct = 100 * reviewed / total
    return next((r for limit, r in REVIEW_LIMITS if pct >= limit), 5)


def compute(rows, resolved_hotspots, metrics, scope):
    """Ratings for one scope ("" overall, "new_" new code) from (type, severity) rows of open issues."""
    by_type = {}
    for type_, severity in rows:
        by_type.setdefault(type_, []).append(severity)
    smell_minutes = sum(REMEDIATION_MINUTES[s] for s in by_type.get("code_smell", []))
    lines = metrics.get("new_lines" if scope else "ncloc", 0)
    out = {f"{scope}{name}_rating": worst(by_type.get(t, [])) for t, name in RATED_TYPES.items()}
    out[f"{scope}maintainability_rating"] = debt_rating(smell_minutes, lines)
    out[f"{scope}technical_debt_minutes"] = smell_minutes
    if lines:
        out[f"{scope}debt_ratio_percent"] = round(100 * smell_minutes / (lines * MINUTES_PER_LINE), 2)
    out[f"{scope}security_review_rating"] = review_rating(len(by_type.get("security_hotspot", [])),
                                                         resolved_hotspots)
    if not scope:
        ratings = [out[k] for k in ("reliability_rating", "security_rating", "maintainability_rating",
                                    "security_review_rating")]
        if metrics.get("_has_accessibility"):
            ratings.append(out["accessibility_rating"])
        out["health_score"] = round(sum(SCORE[r] for r in ratings) / len(ratings))
    return out


def score_grade(score):
    return next((g for g, limit in zip(GRADES, (90, 75, 60, 40), strict=False) if score >= limit), "E")
