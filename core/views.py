from collections import Counter

from django import forms
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import SetPasswordForm, UserCreationForm
from django.contrib.auth.views import PasswordChangeView
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.forms import modelformset_factory
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse, reverse_lazy
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from . import gate
from .analyzers import ANALYZERS
from .catalog import update as catalog_update
from .git import GitError, Mirror, validate_repo_url
from .jobs import launch_scan
from .models import (
    DEFAULT_GATE,
    ISSUE_TYPES,
    SEVERITIES,
    Analysis,
    ApiToken,
    GateCondition,
    IssueResolution,
    Profile,
    Project,
    ProjectMember,
)

User = get_user_model()
PROJECT_PAGE = "project"


def get_project(request, key):
    return get_object_or_404(Project.visible_to(request.user), key=key)


def get_analysis(request, key, pk):
    return get_object_or_404(Analysis, pk=pk, project=get_project(request, key))


def require(allowed):
    if not allowed:
        raise PermissionDenied


def safe_next(request, fallback):
    target = request.POST.get("next", "")
    if url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}):
        return target
    return fallback


def refresh_gates(project):
    for analysis in project.latest_analyses():
        if analysis.status == Analysis.SUCCESS:
            gate.refresh(analysis)


def index(request):
    catalog_update.maybe_launch()
    projects = [(p, next(iter(p.latest_analyses()), None)) for p in Project.visible_to(request.user).order_by("key")]
    return render(request, "core/index.html", {"projects": projects})


class NewProjectForm(forms.ModelForm):
    class Meta:
        model = Project
        fields = ["key", "name", "repo_url", "main_branch"]
        labels = {"repo_url": "Repository URL"}

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        if not user.is_superuser:
            self.fields["repo_url"].help_text = "https://, ssh:// or git@host: URL"

    def clean_repo_url(self):
        try:
            return validate_repo_url(self.cleaned_data["repo_url"], allow_local=self.user.is_superuser)
        except ValueError as exc:
            raise forms.ValidationError(str(exc)) from exc


def create_project(owner, **fields):
    project = Project.objects.create(owner=owner, **fields)
    GateCondition.objects.bulk_create(
        GateCondition(project=project, metric=m, op=op, threshold=t) for m, op, t in DEFAULT_GATE
    )
    return project


def new_project(request):
    form = NewProjectForm(request.POST or None, user=request.user)
    if request.method == "POST" and form.is_valid():
        project = create_project(request.user, **form.cleaned_data)
        launch_scan(project)
        messages.success(request, f"Created {project.key}; the first scan of the main branch has started.")
        return redirect(PROJECT_PAGE, key=project.key)
    return render(request, "core/new_project.html", {"form": form})


def project_detail(request, key):
    project = get_project(request, key)
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
        "can_scan": project.can_scan(request.user),
        "can_admin": project.can_admin(request.user),
        "running": project.analyses.filter(status=Analysis.RUNNING),
        "history": project.analyses.all()[:30],
    })


@require_POST
def start_scan(request, key):
    project = get_project(request, key)
    require(project.can_scan(request.user))
    branch = request.POST.get("branch") or None
    if launch_scan(project, branch) is None:
        messages.info(request, f"{branch} is already being analysed.")
    else:
        messages.success(request, f"Scan of {branch or 'the main branch'} started.")
    return redirect(PROJECT_PAGE, key=key)


TYPE_ROWS = [("bug", "bugs"), ("vulnerability", "vulnerabilities"), ("security_hotspot", "security_hotspots"),
             ("code_smell", "code_smells"), ("accessibility", "accessibility_issues")]


def analysis_detail(request, key, pk):
    analysis = get_analysis(request, key, pk)
    m = analysis.metrics_dict
    return render(request, "core/analysis.html", {
        "analysis": analysis,
        "project": analysis.project,
        "m": m,
        "severities": [(s, m.get(f"{s}_issues"), m.get(f"new_{s}_issues")) for s in SEVERITIES],
        "types": [(t, m.get(k), m.get(f"new_{k}")) for t, k in TYPE_ROWS],
        "by_tool": counts_by_tool(analysis),
        "other_metrics": sorted(
            (k, v) for k, v in m.items()
            if not k.endswith(("issues", "bugs", "vulnerabilities", "code_smells", "hotspots", "rating"))
            and not k.startswith("_")
        ),
    })


def counts_by_tool(analysis):
    resolved = set(analysis.project.resolutions.values_list("fingerprint", flat=True))
    overall, new = Counter(), Counter()
    for tool, fp, is_new in analysis.issues.values_list("tool", "fingerprint", "is_new"):
        if fp not in resolved:
            overall[tool] += 1
            new[tool] += is_new
    return [(t, overall[t], new[t]) for t in sorted(overall)]


def filter_issues(analysis, params):
    """Shared by the issue page and the API: new, type/severity/tool/rule (comma lists), path, status."""
    resolutions = {r.fingerprint: r for r in analysis.project.resolutions.all()}
    issues = analysis.issues.all()
    if params.get("new") in ("1", "true"):
        issues = issues.filter(is_new=True)
    for field in ("type", "severity", "tool", "rule"):
        if params.get(field):
            issues = issues.filter(**{f"{field}__in": params[field].split(",")})
    if params.get("path"):
        issues = issues.filter(path__icontains=params["path"])
    status = params.get("status", "open")
    if status == "open":
        issues = issues.exclude(fingerprint__in=resolutions)
    elif status == "resolved":
        issues = issues.filter(fingerprint__in=resolutions)
    return issues, resolutions, status


def issue_list(request, key, pk):
    analysis = get_analysis(request, key, pk)
    issues, resolutions, status = filter_issues(analysis, request.GET)
    page = Paginator(issues, 100).get_page(request.GET.get("page"))
    for issue in page:
        issue.resolution = resolutions.get(issue.fingerprint)
    query = request.GET.copy()
    query.pop("page", None)
    return render(request, "core/issues.html", {
        "analysis": analysis,
        "project": analysis.project,
        "page": page,
        "f": request.GET,
        "status": status,
        "query": query.urlencode(),
        "severities": SEVERITIES,
        "types": ISSUE_TYPES,
        "tools": sorted(set(analysis.issues.values_list("tool", flat=True))),
        "resolution_choices": IssueResolution.STATUSES,
        "can_resolve": analysis.project.can_scan(request.user),
    })


def set_resolution(project, fingerprint, status, comment=""):
    if status == "reopen":
        IssueResolution.objects.filter(project=project, fingerprint=fingerprint).delete()
    elif status in dict(IssueResolution.STATUSES):
        IssueResolution.objects.update_or_create(
            project=project, fingerprint=fingerprint, defaults={"status": status, "comment": comment}
        )
    else:
        raise ValueError(f"Unknown status {status}")
    refresh_gates(project)


@require_POST
def resolve_issue(request, key):
    project = get_project(request, key)
    require(project.can_scan(request.user))
    try:
        set_resolution(project, request.POST["fingerprint"], request.POST["status"], request.POST.get("comment", ""))
    except ValueError as exc:
        messages.error(request, str(exc))
    return redirect(safe_next(request, reverse(PROJECT_PAGE, args=[key])))


def source_text(analysis, path):
    """Source uploaded with the analysis, else the server-side mirror; None if neither has it."""
    stored = analysis.sources.filter(path=path).select_related("blob").first()
    if stored:
        return stored.blob.content
    if analysis.project.repo_url:
        try:
            return Mirror(analysis.project).show(analysis.commit, path)
        except GitError:
            return None
    return None


def source_view(request, key, pk):
    analysis = get_analysis(request, key, pk)
    path = request.GET.get("path", "")
    text = source_text(analysis, path)
    if text is None:
        raise Http404(path)
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
    a11y_urls = forms.CharField(widget=forms.Textarea(attrs={"rows": 4}), required=False,
                                label="Accessibility URLs",
                                help_text="One live page per line, checked with axe-core on every scan. "
                                          "{branch} is replaced by the branch name.")
    disabled_analyzers = forms.MultipleChoiceField(
        choices=[(a.name, a.name) for a in ANALYZERS], required=False, widget=forms.CheckboxSelectMultiple
    )

    class Meta:
        model = Project
        fields = ["name", "main_branch", "semgrep_config", "complexity_threshold", "cognitive_complexity_threshold",
                  "duplicate_literal_threshold", "exclusions", "a11y_urls", "disabled_analyzers"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.initial["exclusions"] = "\n".join(self.instance.exclusions)
        self.initial["a11y_urls"] = "\n".join(self.instance.a11y_urls)

    @staticmethod
    def lines(value):
        return [line.strip() for line in value.splitlines() if line.strip()]

    def clean_exclusions(self):
        return self.lines(self.cleaned_data["exclusions"])

    def clean_a11y_urls(self):
        urls = self.lines(self.cleaned_data["a11y_urls"])
        bad = [u for u in urls if not u.startswith(("http://", "https://"))]
        if bad:
            raise forms.ValidationError(f"Not an http(s) URL: {', '.join(bad)}")
        return urls


GateFormSet = modelformset_factory(GateCondition, fields=["metric", "op", "threshold"], extra=1, can_delete=True)


class MemberForm(forms.Form):
    username = forms.CharField()
    role = forms.ChoiceField(choices=ProjectMember.ROLES, initial=ProjectMember.CONTRIBUTOR)

    def clean_username(self):
        try:
            return User.objects.get(username=self.cleaned_data["username"], is_active=True)
        except User.DoesNotExist as exc:
            raise forms.ValidationError("No active user with that username") from exc


def project_settings(request, key):
    project = get_project(request, key)
    require(project.can_admin(request.user))
    form = ProjectSettingsForm(request.POST or None, instance=project)
    formset = GateFormSet(request.POST or None, queryset=project.gate_conditions.all(), prefix="gate")
    if request.method == "POST" and form.is_valid() and formset.is_valid():
        form.save()
        for cond in formset.save(commit=False):
            cond.project = project
            cond.save()
        for cond in formset.deleted_objects:
            cond.delete()
        refresh_gates(project)
        messages.success(request, "Settings saved.")
        return redirect(PROJECT_PAGE, key=key)
    return render(request, "core/settings.html", {
        "project": project, "form": form, "formset": formset, "member_form": MemberForm(),
        "members": project.members.select_related("user").order_by("user__username"),
    })


@require_POST
def project_members(request, key):
    project = get_project(request, key)
    require(project.can_admin(request.user))
    if request.POST.get("remove"):
        project.members.filter(pk=request.POST["remove"]).delete()
        return redirect("settings", key=key)
    form = MemberForm(request.POST)
    if not form.is_valid():
        messages.error(request, "; ".join(e for errs in (form.errors or {}).values() for e in errs))
    elif form.cleaned_data["username"].pk == project.owner_id:
        messages.error(request, "That user already owns this project.")
    else:
        user, role = form.cleaned_data["username"], form.cleaned_data["role"]
        ProjectMember.objects.update_or_create(project=project, user=user, defaults={"role": role})
        messages.success(request, f"{user.username} added as {role}.")
    return redirect("settings", key=key)


@require_POST
def delete_project(request, key):
    project = get_project(request, key)
    require(project.can_admin(request.user))
    if request.POST.get("confirm") != project.key:
        messages.error(request, "Type the project key to confirm deletion.")
        return redirect("settings", key=key)
    project.delete()
    messages.success(request, f"Deleted {key}.")
    return redirect("index")


class ChangePasswordView(PasswordChangeView):
    template_name = "core/password_change.html"
    success_url = reverse_lazy("account")

    def form_valid(self, form):
        response = super().form_valid(form)
        Profile.objects.update_or_create(user=self.request.user, defaults={"must_change_password": False})  # nosec B105
        messages.success(self.request, "Password changed.")
        return response


class TokenForm(forms.Form):
    name = forms.CharField(max_length=100, help_text="e.g. 'CI' or 'Claude'")
    scope = forms.ChoiceField(choices=ApiToken.SCOPES, initial=ApiToken.SCAN)


def account(request):
    form = TokenForm(request.POST or None)
    new_token = None
    if request.method == "POST":
        if request.POST.get("revoke"):
            request.user.api_tokens.filter(pk=request.POST["revoke"]).delete()
            messages.success(request, "Token revoked.")
            return redirect("account")
        if form.is_valid():
            _, new_token = ApiToken.issue(request.user, form.cleaned_data["name"], form.cleaned_data["scope"])
            form = TokenForm()
    return render(request, "core/account.html", {
        "form": form, "new_token": new_token, "tokens": request.user.api_tokens.all(),
        "api_base": request.build_absolute_uri("/api/"),
    })


class NewUserForm(UserCreationForm):
    is_superuser = forms.BooleanField(required=False, label="Administrator",
                                      help_text="Sees all projects and manages users")

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ["username", "email"]


def users(request):
    require(request.user.is_superuser)
    form = NewUserForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = form.save(commit=False)
        user.is_superuser = user.is_staff = form.cleaned_data["is_superuser"]
        user.save()
        messages.success(request, f"Created {user.username}.")
        return redirect("users")
    return render(request, "core/users.html", {"form": form, "users": User.objects.order_by("username")})


def user_edit(request, pk):
    require(request.user.is_superuser)
    target = get_object_or_404(User, pk=pk)
    form = SetPasswordForm(target, request.POST or None)
    if request.method == "POST" and "toggle_active" in request.POST:
        if target == request.user:
            messages.error(request, "You can't deactivate yourself.")
        else:
            target.is_active = not target.is_active
            target.save(update_fields=["is_active"])
            messages.success(request, f"{target.username} {'activated' if target.is_active else 'deactivated'}.")
        return redirect("users")
    if request.method == "POST" and form.is_valid():
        form.save()
        Profile.objects.update_or_create(user=target, defaults={"must_change_password": True})  # nosec B105
        messages.success(request, f"Password reset for {target.username}; they must change it on next login.")
        return redirect("users")
    return render(request, "core/user_edit.html", {"target": target, "form": form})
