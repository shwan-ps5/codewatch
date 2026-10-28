"""Public pages: the rule catalogue, standards coverage and how ratings are calculated."""
from collections import Counter

from django.contrib import messages
from django.contrib.auth.decorators import login_not_required
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.http import Http404
from django.shortcuts import redirect, render
from django.utils.safestring import mark_safe
from django.views.decorators.http import require_POST, require_safe
from markdown_it import MarkdownIt

from . import catalog, ratings
from .catalog import update

LANGUAGES = [("python", "Python"), ("javascript", "JS / TS"), ("html", "HTML"), ("css", "CSS"),
             ("web", "Live pages"), ("c/c++", "C / C++"), ("iac", "Docker / IaC")]
ORIGINS = [("imported", "Imported"), ("codewatch", "codewatch built-in"), ("custom", "Custom")]
# Raw HTML in tool documentation is not rendered; links and code blocks are.
MARKDOWN = MarkdownIt("commonmark", {"html": False}).enable("table")

FILTERS = {
    "tool": lambda r, v: r["tool"] == v,
    "type": lambda r, v: r["type"] == v,
    "origin": lambda r, v: r.get("origin") == v,
    "language": catalog.speaks,
    "cwe": lambda r, v: v.isdigit() and int(v) in r["cwe"],
    "owasp": lambda r, v: v in r["owasp"],
    "wcag": lambda r, v: v in r["wcag"],
    "duplicates": lambda r, _v: bool(r.get("same_as")),
    "q": lambda r, v: v.lower() in f"{r['id']} {r['title']} {r['summary']}".lower(),
}


def matches(rule, params):
    return all(test(rule, params[key]) for key, test in FILTERS.items() if params.get(key))


@login_not_required
@require_safe
def rules(request):
    all_rules, standards = catalog.load()
    if request.user.is_authenticated:
        update.maybe_launch()
    found = [r for r in all_rules if matches(r, request.GET)]
    page = Paginator(found, 50).get_page(request.GET.get("page"))
    query = request.GET.copy()
    query.pop("page", None)
    return render(request, "core/rules.html", {
        "page": page, "total": len(all_rules), "f": request.GET, "query": query.urlencode(),
        "tools": sorted(Counter(r["tool"] for r in all_rules).items()), "languages": LANGUAGES,
        "origins": [(o, n, sum(1 for r in all_rules if r.get("origin") == o)) for o, n in ORIGINS],
        "types": sorted({r["type"] for r in all_rules}), "standards": standards,
        "meta": catalog.meta(), "changes": catalog.changes(), "status": update.status(),
        "interval_days": update.update_interval().days,
    })


@require_POST
def update_rules(request):
    if not request.user.is_superuser:
        raise PermissionDenied
    if update.running():
        messages.info(request, "An update is already running.")
    else:
        update.launch(upgrade=request.POST.get("upgrade") == "1")
        messages.success(request, "Rule update started. Reload this page in a minute or two.")
    return redirect("rules")


@login_not_required
@require_safe
def rule_detail(request, rule_id):
    rule = catalog.find(rule_id)
    if rule is None:
        raise Http404(rule_id)
    _, standards = catalog.load()
    names, details = standards.get("cwe_names", {}), standards.get("cwe_details", {})
    doc = catalog.docs().get(rule_id)
    return render(request, "core/rule.html", {
        "rule": rule,
        # Safe to mark: MARKDOWN is configured with html=False, so raw HTML in the source is escaped.
        "doc": mark_safe(MARKDOWN.render(doc)) if doc else None,  # nosec B308 B703 # nosemgrep
        "cwes": [{"id": c, "name": names.get(str(c), ""), **(details.get(str(c)) or {})} for c in rule["cwe"]],
        "same_as": [r for r in (catalog.find(i) for i in rule.get("same_as", [])) if r],
    })


@login_not_required
@require_safe
def standards(request):
    all_rules, std = catalog.load()
    if not std:
        raise Http404("Catalogue not imported; run manage.py buildcatalog")
    langs = [code for code, _ in LANGUAGES if code not in ("web", "html", "css")]
    top25, owasp, wcag = catalog.coverage(all_rules, std, langs)
    by_level = Counter((sc["level"], sc["rules"] > 0) for sc in wcag)
    return render(request, "core/standards.html", {
        "std": std, "top25": top25, "owasp": owasp, "wcag": [sc for sc in wcag if sc["level"] in ("A", "AA")],
        "langs": [(c, n) for c, n in LANGUAGES if c in langs],
        "wcag_summary": {lvl: (by_level[(lvl, True)], by_level[(lvl, True)] + by_level[(lvl, False)])
                         for lvl in ("A", "AA")},
        "rule_count": len(all_rules),
    })


@login_not_required
@require_safe
def ratings_help(request):
    return render(request, "core/ratings.html", {
        "remediation": ratings.REMEDIATION_MINUTES, "minutes_per_line": ratings.MINUTES_PER_LINE,
        "debt_limits": ratings.DEBT_RATIO_LIMITS, "review_limits": ratings.REVIEW_LIMITS,
        "score": ratings.SCORE,
    })
