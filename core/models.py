import hashlib
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone

from .catalog import custom_semgrep_rules
from .collect import DEFAULT_EXCLUSIONS, period_days

SEVERITIES = ["blocker", "critical", "major", "minor", "info"]
ISSUE_TYPES = ["bug", "vulnerability", "security_hotspot", "code_smell", "accessibility"]


def default_exclusions():
    return list(DEFAULT_EXCLUSIONS)


class Project(models.Model):
    key = models.SlugField(unique=True)
    name = models.CharField(max_length=200)
    repo_url = models.CharField(
        max_length=500, blank=True, help_text="Only for server-side scans; leave blank when using codewatch-scan"
    )
    main_branch = models.CharField(max_length=200, blank=True, help_text="Detected on first scan if blank")
    exclusions = models.JSONField(default=default_exclusions, blank=True)
    disabled_analyzers = models.JSONField(default=list, blank=True)
    semgrep_config = models.CharField(max_length=200, default="p/default")
    complexity_threshold = models.PositiveIntegerField(default=10, help_text="Cyclomatic complexity per function")
    cognitive_complexity_threshold = models.PositiveIntegerField(
        default=15, help_text="Cognitive complexity per function (Python)"
    )
    duplicate_literal_threshold = models.PositiveIntegerField(
        default=3, help_text="Flag a string literal repeated more than this many times in a file"
    )
    a11y_urls = models.JSONField(
        default=list, blank=True, help_text="Live pages to check with axe-core; {branch} is replaced by the branch name"
    )
    new_code_period = models.CharField(
        max_length=200, blank=True, verbose_name="New code on the main branch",
        help_text="Blank: since the previous analysis. 30d: since the newest analysis at least 30 days old. "
                  "Anything else is a tag, branch or commit, e.g. v1.4.",
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="projects"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.key

    @classmethod
    def visible_to(cls, user):
        if user.is_superuser:
            return cls.objects.all()
        return cls.objects.filter(models.Q(owner=user) | models.Q(members__user=user)).distinct()

    def scan_config(self):
        """Settings the codewatch-scan client needs, mirroring collect.ScanConfig."""
        main = self.main_analyses_for_reference()
        return {
            "main_branch": self.main_branch,
            "exclusions": self.exclusions,
            "disabled_analyzers": self.disabled_analyzers,
            "semgrep_config": self.semgrep_config,
            "complexity_threshold": self.complexity_threshold,
            "cognitive_complexity_threshold": self.cognitive_complexity_threshold,
            "duplicate_literal_threshold": self.duplicate_literal_threshold,
            "custom_rules": custom_semgrep_rules(),
            "a11y_urls": self.a11y_urls,
            "new_code_period": self.new_code_period,
            "main_analyses": [
                {"commit": a.commit, "reference_commit": a.reference_commit, "started_at": a.started_at.isoformat()}
                for a in main
            ],
        }

    def main_analyses_for_reference(self):
        """Recent main analyses, newest first, plus what a days-based new-code period needs further back:
        the newest few older than the cutoff, and the first ever (the fallback for a younger project)."""
        done = self.analyses.filter(branch=self.main_branch, status=Analysis.SUCCESS).order_by("-started_at")
        main = list(done[:50])
        days = period_days(self.new_code_period)
        if days is not None:
            older = [*done.filter(started_at__lte=timezone.now() - timedelta(days=days))[:10], *done.reverse()[:1]]
            main += [a for a in dict.fromkeys(older) if a not in main]
        return main

    def role_of(self, user):
        if user.is_superuser or self.owner_id == user.pk:
            return ProjectMember.OWNER
        member = self.members.filter(user=user).first()
        return member.role if member else None

    def can_scan(self, user):
        return self.role_of(user) in (ProjectMember.OWNER, ProjectMember.CONTRIBUTOR)

    def can_admin(self, user):
        return self.role_of(user) == ProjectMember.OWNER

    def latest_analyses(self):
        """Latest finished analysis per branch, main branch first."""
        latest = {}
        for a in self.analyses.exclude(status=Analysis.RUNNING).order_by("-started_at"):
            latest.setdefault(a.branch, a)
        return sorted(latest.values(), key=lambda a: (a.branch != self.main_branch, a.branch))


class ProjectMember(models.Model):
    OWNER, CONTRIBUTOR, VIEWER = "owner", "contributor", "viewer"
    ROLES = [(VIEWER, "Viewer: see results"), (CONTRIBUTOR, "Contributor: also scan branches and resolve issues")]

    project = models.ForeignKey("Project", on_delete=models.CASCADE, related_name="members")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="memberships")
    role = models.CharField(max_length=12, choices=ROLES, default=CONTRIBUTOR)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "user"], name="uniq_member")]

    def __str__(self):
        return f"{self.user} ({self.role}) on {self.project}"


class Analysis(models.Model):
    RUNNING, SUCCESS, FAILED = "running", "success", "failed"
    STATUSES = [(s, s) for s in (RUNNING, SUCCESS, FAILED)]

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="analyses")
    branch = models.CharField(max_length=200)
    commit = models.CharField(max_length=40)
    reference_branch = models.CharField(max_length=200, blank=True)
    reference_commit = models.CharField(max_length=40, blank=True)
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUSES, default=RUNNING)
    error = models.TextField(blank=True)
    gate_passed = models.BooleanField(null=True)
    gate_details = models.JSONField(default=list, blank=True)
    tools = models.JSONField(default=dict, blank=True)
    dirty = models.BooleanField(default=False, help_text="Scanned from a working copy with uncommitted changes")
    origin = models.CharField(max_length=10, default="server", choices=[("server", "server"), ("client", "client")])
    scanned_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self):
        return f"{self.project.key}@{self.branch} {self.commit[:8]}"

    @property
    def metrics_dict(self):
        return {m.key: m.value for m in self.metrics.all()}


class Issue(models.Model):
    analysis = models.ForeignKey(Analysis, on_delete=models.CASCADE, related_name="issues")
    fingerprint = models.CharField(max_length=40, db_index=True)
    tool = models.CharField(max_length=30)
    rule = models.CharField(max_length=300)
    severity = models.CharField(max_length=10, choices=[(s, s) for s in SEVERITIES])
    type = models.CharField(max_length=20, choices=[(t, t) for t in ISSUE_TYPES])
    message = models.TextField()
    path = models.CharField(max_length=500)
    line = models.PositiveIntegerField(null=True)
    end_line = models.PositiveIntegerField(null=True)
    is_new = models.BooleanField(default=False)
    also_reported_by = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["path", "line"]

    def __str__(self):
        return f"{self.tool}:{self.rule} at {self.path}:{self.line}"


class SourceBlob(models.Model):
    sha = models.CharField(max_length=64, primary_key=True)
    content = models.TextField()

    def __str__(self):
        return self.sha[:12]


class AnalysisSource(models.Model):
    analysis = models.ForeignKey(Analysis, on_delete=models.CASCADE, related_name="sources")
    path = models.CharField(max_length=500)
    blob = models.ForeignKey(SourceBlob, on_delete=models.PROTECT)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["analysis", "path"], name="uniq_source")]

    def __str__(self):
        return f"{self.analysis} {self.path}"


class Metric(models.Model):
    analysis = models.ForeignKey(Analysis, on_delete=models.CASCADE, related_name="metrics")
    key = models.CharField(max_length=60)
    value = models.FloatField()

    class Meta:
        constraints = [models.UniqueConstraint(fields=["analysis", "key"], name="uniq_metric")]

    def __str__(self):
        return f"{self.key}={self.value:g}"


class IssueResolution(models.Model):
    WONT_FIX, FALSE_POSITIVE = "wont_fix", "false_positive"
    STATUSES = [(WONT_FIX, "Won't fix"), (FALSE_POSITIVE, "False positive")]

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="resolutions")
    fingerprint = models.CharField(max_length=40)
    status = models.CharField(max_length=20, choices=STATUSES)
    comment = models.TextField(blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "fingerprint"], name="uniq_resolution")]

    def __str__(self):
        return f"{self.fingerprint[:8]} {self.status}"


class GateCondition(models.Model):
    GT, LT = "gt", "lt"
    OPS = [(GT, "is greater than"), (LT, "is less than")]

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="gate_conditions")
    metric = models.CharField(max_length=60)
    op = models.CharField(max_length=2, choices=OPS)
    threshold = models.FloatField()

    class Meta:
        ordering = ["metric"]

    def __str__(self):
        return f"{self.metric} {self.op} {self.threshold:g}"

    def fails(self, value):
        return value > self.threshold if self.op == self.GT else value < self.threshold


class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profile")
    must_change_password = models.BooleanField(default=False)

    def __str__(self):
        return str(self.user)


def hash_token(raw):
    return hashlib.sha256(raw.encode()).hexdigest()


class ApiToken(models.Model):
    READ, SCAN = "read", "scan"
    SCOPES = [(READ, "Read issues and results, resolve issues"), (SCAN, "Read, resolve, and create projects / start scans")]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="api_tokens")
    name = models.CharField(max_length=100)
    scope = models.CharField(max_length=10, choices=SCOPES, default=SCAN)
    prefix = models.CharField(max_length=12)
    key_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user}: {self.name} ({self.prefix}\u2026)"

    @classmethod
    def issue(cls, user, name, scope):
        """Create a token; the raw value is returned once and only its hash is stored."""
        raw = "cw_" + secrets.token_urlsafe(32)
        token = cls.objects.create(user=user, name=name, scope=scope, prefix=raw[:10], key_hash=hash_token(raw))
        return token, raw

    @classmethod
    def authenticate(cls, raw):
        token = cls.objects.select_related("user").filter(key_hash=hash_token(raw)).first()
        if token is None or not token.user.is_active:
            return None
        return token


DEFAULT_GATE = [
    ("new_blocker_issues", GateCondition.GT, 0),
    ("new_critical_issues", GateCondition.GT, 0),
    ("new_bugs", GateCondition.GT, 0),
    ("new_vulnerabilities", GateCondition.GT, 0),
    ("new_coverage", GateCondition.LT, 80),
    ("new_duplicated_lines_percent", GateCondition.GT, 3),
    ("dependency_critical_vulnerabilities", GateCondition.GT, 0),
    ("new_accessibility_issues", GateCondition.GT, 0),
    ("new_maintainability_rating", GateCondition.GT, 1),
    ("new_security_review_rating", GateCondition.GT, 1),
]
