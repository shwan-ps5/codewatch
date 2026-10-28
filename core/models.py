from django.conf import settings
from django.db import models

SEVERITIES = ["blocker", "critical", "major", "minor", "info"]
ISSUE_TYPES = ["bug", "vulnerability", "code_smell"]


def default_exclusions():
    return list(settings.CODEWATCH_DEFAULT_EXCLUSIONS)


class Project(models.Model):
    key = models.SlugField(unique=True)
    name = models.CharField(max_length=200)
    repo_url = models.CharField(max_length=500, help_text="Local path or git URL")
    main_branch = models.CharField(max_length=200, default="main")
    exclusions = models.JSONField(default=default_exclusions, blank=True)
    disabled_analyzers = models.JSONField(default=list, blank=True)
    semgrep_config = models.CharField(max_length=200, default="p/default")
    complexity_threshold = models.PositiveIntegerField(default=10)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.key

    def latest_analyses(self):
        """Latest finished analysis per branch, main branch first."""
        latest = {}
        for a in self.analyses.exclude(status=Analysis.RUNNING).order_by("-started_at"):
            latest.setdefault(a.branch, a)
        return sorted(latest.values(), key=lambda a: (a.branch != self.main_branch, a.branch))


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
    type = models.CharField(max_length=15, choices=[(t, t) for t in ISSUE_TYPES])
    message = models.TextField()
    path = models.CharField(max_length=500)
    line = models.PositiveIntegerField(null=True)
    end_line = models.PositiveIntegerField(null=True)
    is_new = models.BooleanField(default=False)

    class Meta:
        ordering = ["path", "line"]


class Metric(models.Model):
    analysis = models.ForeignKey(Analysis, on_delete=models.CASCADE, related_name="metrics")
    key = models.CharField(max_length=60)
    value = models.FloatField()

    class Meta:
        constraints = [models.UniqueConstraint(fields=["analysis", "key"], name="uniq_metric")]


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


class GateCondition(models.Model):
    GT, LT = "gt", "lt"
    OPS = [(GT, "is greater than"), (LT, "is less than")]

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="gate_conditions")
    metric = models.CharField(max_length=60)
    op = models.CharField(max_length=2, choices=OPS)
    threshold = models.FloatField()

    class Meta:
        ordering = ["metric"]

    def fails(self, value):
        return value > self.threshold if self.op == self.GT else value < self.threshold


DEFAULT_GATE = [
    ("new_blocker_issues", GateCondition.GT, 0),
    ("new_critical_issues", GateCondition.GT, 0),
    ("new_bugs", GateCondition.GT, 0),
    ("new_vulnerabilities", GateCondition.GT, 0),
    ("new_coverage", GateCondition.LT, 80),
    ("new_duplicated_lines_percent", GateCondition.GT, 3),
    ("dependency_critical_vulnerabilities", GateCondition.GT, 0),
]
