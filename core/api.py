import gzip
import json
import zlib
from functools import wraps

from django.contrib.auth.decorators import login_not_required
from django.db import IntegrityError
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from . import catalog
from .git import validate_repo_url
from .jobs import launch_scan, save_coverage_upload
from .models import Analysis, ApiToken, Issue, Project
from .runner import create_uploaded_analysis, ingest
from .views import create_project, filter_issues, set_resolution, source_text

MAX_PAYLOAD_BYTES = 500 * 1024 * 1024
MAX_PAGE = 500


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def api(scope=ApiToken.READ, methods=("GET",)):
    """Bearer-token auth. "read" tokens can read and resolve issues; "scan" tokens can also upload and start scans."""
    def decorator(view):
        @csrf_exempt
        @login_not_required
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            if request.method not in methods:
                return JsonResponse({"error": f"{request.method} not allowed"}, status=405)
            header = request.headers.get("Authorization", "")
            scheme, _, raw = header.partition(" ")
            token = ApiToken.authenticate(raw.strip()) if scheme.lower() in ("bearer", "token") else None
            if token is None:
                return JsonResponse({"error": "Missing or invalid API token"}, status=401)
            if scope == ApiToken.SCAN and token.scope != ApiToken.SCAN:
                return JsonResponse({"error": "This token is read-only; a scan token is required"}, status=403)
            ApiToken.objects.filter(pk=token.pk).update(last_used_at=timezone.now())
            request.user = token.user
            try:
                return view(request, *args, **kwargs)
            except ApiError as exc:
                return JsonResponse({"error": str(exc)}, status=exc.status)
        return wrapper
    return decorator


def visible_project(request, key):
    project = Project.visible_to(request.user).filter(key=key).first()
    if project is None:
        raise ApiError(404, f"No project {key} (or no access)")
    return project


def latest_analysis(project, branch, include_running=False):
    qs = project.analyses.filter(branch=branch or project.main_branch)
    if not include_running:
        qs = qs.filter(status=Analysis.SUCCESS)
    analysis = qs.order_by("-started_at").first()
    if analysis is None:
        raise ApiError(404, f"No analysis of {branch or project.main_branch} yet")
    return analysis


def analysis_json(request, a, full=False):
    data = {
        "id": a.pk,
        "branch": a.branch,
        "commit": a.commit,
        "status": a.status,
        "origin": a.origin,
        "dirty": a.dirty,
        "started_at": a.started_at.isoformat(),
        "gate_passed": a.gate_passed,
        "url": request.build_absolute_uri(f"/p/{a.project.key}/a/{a.pk}/"),
    }
    if full:
        data.update(
            reference_commit=a.reference_commit, gate=a.gate_details, metrics=a.metrics_dict, tools=a.tools,
            error=a.error,
        )
    return data


def issue_json(issue, resolution=None):
    return {
        "id": issue.pk,
        "type": issue.type,
        "severity": issue.severity,
        "tool": issue.tool,
        "rule": issue.rule,
        "message": issue.message,
        "path": issue.path,
        "line": issue.line,
        "end_line": issue.end_line,
        "is_new": issue.is_new,
        "fingerprint": issue.fingerprint,
        "resolution": resolution and {"status": resolution.status, "comment": resolution.comment},
    }


def project_json(request, p):
    return {
        "key": p.key,
        "name": p.name,
        "main_branch": p.main_branch,
        "repo_url": p.repo_url,
        "role": p.role_of(request.user),
        "branches": [analysis_json(request, a) for a in p.latest_analyses()],
    }


@api()
def projects(request):
    return JsonResponse({"projects": [project_json(request, p) for p in Project.visible_to(request.user)]})


@api()
def project(request, key):
    return JsonResponse(project_json(request, visible_project(request, key)))


@api(scope=ApiToken.SCAN)
def project_config(request, key):
    p = visible_project(request, key)
    if not p.can_scan(request.user):
        raise ApiError(403, "You can view this project but not scan it")
    return JsonResponse(p.scan_config())


@api()
def status(request, key):
    p = visible_project(request, key)
    return JsonResponse(analysis_json(request, latest_analysis(p, request.GET.get("branch"), True), full=True))


@api()
def analysis(request, pk):
    a = Analysis.objects.filter(pk=pk, project__in=Project.visible_to(request.user)).first()
    if a is None:
        raise ApiError(404, "No such analysis")
    return JsonResponse(analysis_json(request, a, full=True))


@api()
def issues(request, key):
    p = visible_project(request, key)
    a = latest_analysis(p, request.GET.get("branch"))
    qs, resolutions, _ = filter_issues(a, request.GET)
    severity_rank = {"blocker": 0, "critical": 1, "major": 2, "minor": 3, "info": 4}
    limit = min(int(request.GET.get("limit", 100)), MAX_PAGE)
    offset = int(request.GET.get("offset", 0))
    total = qs.count()
    rows = sorted(qs, key=lambda i: (severity_rank[i.severity], i.path, i.line or 0))[offset:offset + limit]
    return JsonResponse({
        "analysis": analysis_json(request, a),
        "total": total,
        "offset": offset,
        "issues": [issue_json(i, resolutions.get(i.fingerprint)) for i in rows],
    })


def snippet(issue, context):
    text = source_text(issue.analysis, issue.path) if issue.line else None
    if text is None:
        return None
    lines = text.splitlines()
    start = max(1, issue.line - context)
    # Some rules span a whole function; the start of the range is what matters.
    end = min(len(lines), min(issue.end_line or issue.line, issue.line + 10) + context)
    return [{"line": n, "text": lines[n - 1]} for n in range(start, end + 1)]


@api()
def issue_detail(request, pk):
    issue = Issue.objects.select_related("analysis__project").filter(
        pk=pk, analysis__project__in=Project.visible_to(request.user)
    ).first()
    if issue is None:
        raise ApiError(404, "No such issue")
    resolution = issue.analysis.project.resolutions.filter(fingerprint=issue.fingerprint).first()
    data = issue_json(issue, resolution)
    data["project"] = issue.analysis.project.key
    data["analysis"] = analysis_json(request, issue.analysis)
    data["snippet"] = snippet(issue, min(int(request.GET.get("context", 5)), 50))
    data["also_reported_by"] = issue.also_reported_by
    entry = catalog.lookup(issue.tool, issue.rule)
    data["rule"] = rule_json(entry, full=False) if entry else None
    return JsonResponse(data)


def rule_json(entry, full=True):
    data = {k: entry.get(k) for k in ("id", "title", "summary", "type", "severity", "languages", "docs", "cwe",
                                      "owasp", "wcag", "same_as", "origin", "references")}
    if full:
        details = catalog.load()[1].get("cwe_details", {})
        data["explanation"] = catalog.docs().get(entry["id"])
        data["cwe_guidance"] = [{"cwe": c, **{k: details[str(c)][k] for k in ("description", "mitigations")}}
                                for c in entry["cwe"] if str(c) in details]
    return data


@api()
def rule(request, rule_id):
    entry = catalog.find(rule_id)
    if entry is None:
        raise ApiError(404, f"No rule {rule_id}")
    return JsonResponse(rule_json(entry))


@api(methods=("POST",))
def resolve(request, pk):
    issue = Issue.objects.select_related("analysis__project").filter(
        pk=pk, analysis__project__in=Project.visible_to(request.user)
    ).first()
    if issue is None:
        raise ApiError(404, "No such issue")
    project = issue.analysis.project
    if not project.can_scan(request.user):
        raise ApiError(403, "Viewers can't resolve issues")
    body = json_body(request)
    try:
        set_resolution(project, issue.fingerprint, body.get("status", ""), body.get("comment", ""))
    except ValueError as exc:
        raise ApiError(400, str(exc)) from exc
    return JsonResponse({"ok": True, "fingerprint": issue.fingerprint, "status": body.get("status")})


def json_body(request):
    raw = request.body
    if request.headers.get("Content-Encoding") == "gzip":
        try:
            raw = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS).decompress(raw, MAX_PAYLOAD_BYTES)
        except (zlib.error, gzip.BadGzipFile) as exc:
            raise ApiError(400, "Invalid gzip body") from exc
    try:
        return json.loads(raw or b"{}")
    except ValueError as exc:
        raise ApiError(400, "Body must be JSON") from exc


def project_for_scan(request, key, create_fields):
    """Existing project the user may scan, or a new one owned by them."""
    project = Project.objects.filter(key=key).first()
    if project is None:
        try:
            return create_project(request.user, key=key, **create_fields)
        except IntegrityError as exc:
            raise ApiError(409, f"Project key {key} is taken") from exc
    if not project.can_scan(request.user):
        raise ApiError(403 if project.role_of(request.user) else 404, f"No project {key} (or no scan access)")
    return project


@api(scope=ApiToken.SCAN, methods=("POST",))
def upload(request, key):
    """Results from codewatch-scan run against a local working copy."""
    payload = json_body(request)
    for field in ("branch", "commit", "issues", "metrics"):
        if field not in payload:
            raise ApiError(400, f"Missing {field}")
    project = project_for_scan(request, key, {
        "name": payload.get("project_name") or key, "repo_url": "", "main_branch": payload.get("main_branch", ""),
    })
    if not project.main_branch and payload.get("main_branch"):
        project.main_branch = payload["main_branch"]
        project.save(update_fields=["main_branch"])
    analysis = create_uploaded_analysis(project, payload, request.user)
    try:
        ingest(analysis, payload)
    except (KeyError, TypeError, ValueError) as exc:
        analysis.status = Analysis.FAILED
        analysis.error = f"Malformed upload: {exc!r}"
        analysis.save()
        raise ApiError(400, analysis.error) from exc
    data = analysis_json(request, analysis, full=True)
    return JsonResponse(data, status=201)


def new_server_project_fields(request, key, body):
    fields = {"name": body.get("name") or key, "main_branch": body.get("main_branch", "")}
    if Project.objects.filter(key=key).exists():
        return fields
    try:
        fields["repo_url"] = validate_repo_url(body.get("repo_url", ""), allow_local=request.user.is_superuser)
    except ValueError as exc:
        raise ApiError(400, str(exc)) from exc
    return fields


@api(scope=ApiToken.SCAN, methods=("POST",))
def server_scan(request, key):
    """Ask the server to clone/fetch the repository URL and scan a branch itself."""
    body = request.POST if request.content_type.startswith("multipart/") else json_body(request)
    project = project_for_scan(request, key, new_server_project_fields(request, key, body))
    if not project.repo_url:
        raise ApiError(400, "This project has no repository URL; upload results with codewatch-scan instead")
    coverage = request.FILES.get("coverage")
    path = save_coverage_upload(project, coverage) if coverage else None
    branch = body.get("branch") or None
    if launch_scan(project, branch, coverage=path) is None:
        raise ApiError(409, f"{branch} is already being analysed")
    return JsonResponse({"project": project.key, "branch": branch or project.main_branch or None,
                         "status": "queued"}, status=202)
