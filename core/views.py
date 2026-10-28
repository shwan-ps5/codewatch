import subprocess
import sys
from collections import Counter

from django import forms
from django.conf import settings
from django.core.paginator import Paginator
from django.forms import modelformset_factory
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from . import gate
from .analyzers import ANALYZERS
from .git import GitError, Mirror
from .models import ISSUE_TYPES, SEVERITIES, Analysis, GateCondition, IssueResolution, Project


def index(request):
    projects = [(p, next(iter(p.latest_analyses()), None)) for p in Project.objects.order_by("key")]
    return render(request, "core/index.html", {"projects": projects})


def project_detail(request, key):
    project = get_object_or_404(Project, key=key)
    latest = project.latest_analyses()
    scanned = {a.branch for a in latest}
    try:
        unscanned = [b for b in Mirror(project).branches() if b not in scanned]
    except GitError:
        unscanned = []
    return render(request, "core/project.html", {
        "project": project,
        "latest": latest,
        "unscanned": unscanned,
        "running": project.analyses.filter(status=Analysis.RUNNING),
        "history": project.analyses.all()[:30],
    })


@require_POST
def start_scan(request, key):
    project = get_object_or_404(Project, key=key)
    branch = request.POST["branch"]
    log_dir = settings.CODEWATCH_CACHE / project.key / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    with open(log_dir / f"{timezone.now():%Y%m%d-%H%M%S}-{branch.replace('/', '_')}.log", "w") as log:
        subprocess.Popen(
            [sys.executable, settings.BASE_DIR / "manage.py", "scan", project.key, "--branch", branch],
            stdout=log, stderr=subprocess.STDOUT, start_new_session=True, cwd=settings.BASE_DIR,
        )
    return redirect("project", key=key)


def analysis_detail(request, key, pk):
    analysis = get_object_or_404(Analysis, pk=pk, project__key=key)
    m = analysis.metrics_dict
    return render(request, "core/analysis.html", {
        "analysis": analysis,
        "project": analysis.project,
        "m": m,
        "severities": [(s, m.get(f"{s}_issues"), m.get(f"new_{s}_issues")) for s in SEVERITIES],
        "types": [(t, m.get(k), m.get(f"new_{k}")) for t, k in
                  [("bug", "bugs"), ("vulnerability", "vulnerabilities"), ("code_smell", "code_smells")]],
        "by_tool": counts_by_tool(analysis),
        "other_metrics": sorted((k, v) for k, v in m.items() if not k.endswith(("issues", "bugs", "vulnerabilities", "code_smells"))),
    })


def counts_by_tool(analysis):
    resolved = set(analysis.project.resolutions.values_list("fingerprint", flat=True))
    overall, new = Counter(), Counter()
    for tool, fp, is_new in analysis.issues.values_list("tool", "fingerprint", "is_new"):
        if fp not in resolved:
            overall[tool] += 1
            new[tool] += is_new
    return [(t, overall[t], new[t]) for t in sorted(overall)]


def issue_list(request, key, pk):
    analysis = get_object_or_404(Analysis, pk=pk, project__key=key)
    resolutions = {r.fingerprint: r for r in analysis.project.resolutions.all()}
    issues = analysis.issues.all()
    f = request.GET
    if f.get("new"):
        issues = issues.filter(is_new=True)
    for field in ("severity", "type", "tool", "rule"):
        if f.get(field):
            issues = issues.filter(**{field: f[field]})
    if f.get("path"):
        issues = issues.filter(path__icontains=f["path"])
    status = f.get("status", "open")
    if status == "open":
        issues = issues.exclude(fingerprint__in=resolutions)
    elif status == "resolved":
        issues = issues.filter(fingerprint__in=resolutions)
    page = Paginator(issues, 100).get_page(f.get("page"))
    for issue in page:
        issue.resolution = resolutions.get(issue.fingerprint)
    query = f.copy()
    query.pop("page", None)
    return render(request, "core/issues.html", {
        "analysis": analysis,
        "project": analysis.project,
        "page": page,
        "f": f,
        "status": status,
        "query": query.urlencode(),
        "severities": SEVERITIES,
        "types": ISSUE_TYPES,
        "tools": sorted(set(analysis.issues.values_list("tool", flat=True))),
        "resolution_choices": IssueResolution.STATUSES,
    })


@require_POST
def resolve_issue(request, key):
    project = get_object_or_404(Project, key=key)
    fp, status = request.POST["fingerprint"], request.POST["status"]
    if status == "reopen":
        IssueResolution.objects.filter(project=project, fingerprint=fp).delete()
    else:
        IssueResolution.objects.update_or_create(
            project=project, fingerprint=fp,
            defaults={"status": status, "comment": request.POST.get("comment", "")},
        )
    for analysis in project.latest_analyses():
        if analysis.status == Analysis.SUCCESS:
            gate.refresh(analysis)
    return redirect(request.POST.get("next") or reverse("project", args=[key]))


def source_view(request, key, pk):
    analysis = get_object_or_404(Analysis, pk=pk, project__key=key)
    path = request.GET.get("path", "")
    try:
        text = Mirror(analysis.project).show(analysis.commit, path)
    except GitError as exc:
        raise Http404(path) from exc
    by_line = {}
    for issue in analysis.issues.filter(path=path):
        by_line.setdefault(issue.line or 0, []).append(issue)
    lines = [(n, line, by_line.get(n, [])) for n, line in enumerate(text.splitlines(), 1)]
    return render(request, "core/source.html", {
        "analysis": analysis, "project": analysis.project, "path": path, "lines": lines,
        "file_issues": by_line.get(0, []),
    })


class ProjectSettingsForm(forms.ModelForm):
    exclusions = forms.CharField(widget=forms.Textarea(attrs={"rows": 6}), required=False,
                                 help_text="One glob per line")
    disabled_analyzers = forms.MultipleChoiceField(
        choices=[(a.name, a.name) for a in ANALYZERS], required=False, widget=forms.CheckboxSelectMultiple
    )

    class Meta:
        model = Project
        fields = ["name", "main_branch", "semgrep_config", "complexity_threshold", "exclusions", "disabled_analyzers"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.initial["exclusions"] = "\n".join(self.instance.exclusions)

    def clean_exclusions(self):
        return [line.strip() for line in self.cleaned_data["exclusions"].splitlines() if line.strip()]


GateFormSet = modelformset_factory(GateCondition, fields=["metric", "op", "threshold"], extra=1, can_delete=True)


def project_settings(request, key):
    project = get_object_or_404(Project, key=key)
    form = ProjectSettingsForm(request.POST or None, instance=project)
    formset = GateFormSet(request.POST or None, queryset=project.gate_conditions.all(), prefix="gate")
    if request.method == "POST" and form.is_valid() and formset.is_valid():
        form.save()
        for cond in formset.save(commit=False):
            cond.project = project
            cond.save()
        for cond in formset.deleted_objects:
            cond.delete()
        for analysis in project.latest_analyses():
            if analysis.status == Analysis.SUCCESS:
                gate.refresh(analysis)
        return redirect("project", key=key)
    return render(request, "core/settings.html", {"project": project, "form": form, "formset": formset})
