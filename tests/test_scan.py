
from datetime import timedelta

import pytest
from django.core.management import call_command
from django.utils import timezone

from core import gate
from core.models import Analysis, IssueResolution, Metric, Project
from core.views import ProjectSettingsForm

from .conftest import ONLY_RUFF, sh


@pytest.fixture
def project(repo):
    call_command("addproject", "demo", str(repo))
    p = Project.objects.get(key="demo")
    # ruff alone keeps the test fast and offline.
    p.disabled_analyzers = ONLY_RUFF
    p.save()
    return p


@pytest.fixture
def scanned_feature(repo, project):
    """main scanned, then a feature branch that shifts an existing issue down and adds a new bug."""
    call_command("scan", "demo")
    sh(repo, "checkout", "-qb", "feature")
    (repo / "app.py").write_text("# moved down\nimport os\n\n\ndef f():\n    return undefined_name\n")
    sh(repo, "commit", "-qam", "feature")
    call_command("scan", "demo", "--branch", "feature")
    return Analysis.objects.get(branch="main"), Analysis.objects.get(branch="feature")


@pytest.mark.django_db
def test_main_has_no_new_code_on_first_scan(scanned_feature):
    main, _ = scanned_feature
    assert main.status == "success"
    assert main.issues.filter(rule="F401").count() == 1
    assert not main.issues.filter(is_new=True).exists()


@pytest.mark.django_db
def test_branch_new_code_and_gate(scanned_feature):
    main, feature = scanned_feature
    assert feature.reference_commit == main.commit
    new = list(feature.issues.filter(is_new=True).values_list("rule", flat=True))
    assert new == ["F821"], "shifted F401 must keep its identity; only the undefined name is new"
    assert feature.gate_passed is False
    assert {d["metric"] for d in feature.gate_details if d["status"] == "error"} == {"new_bugs", "new_critical_issues"}


@pytest.mark.django_db
def test_resolving_the_new_issue_passes_the_gate(scanned_feature, project):
    _, feature = scanned_feature
    issue = feature.issues.get(rule="F821")
    IssueResolution.objects.create(project=project, fingerprint=issue.fingerprint, status="false_positive")
    gate.refresh(feature)
    assert feature.gate_passed is True


@pytest.mark.django_db
def test_main_rescan_uses_previous_analysis_as_reference(repo, project):
    call_command("scan", "demo")
    first = Analysis.objects.get()
    (repo / "app.py").write_text((repo / "app.py").read_text() + "\nimport sys\n")
    sh(repo, "commit", "-qam", "more")
    call_command("scan", "demo")
    second = Analysis.objects.latest("started_at")
    assert second.reference_commit == first.commit
    assert list(second.issues.filter(is_new=True).values_list("rule", flat=True)) == ["F401"]


def commit_change(repo, line):
    (repo / "app.py").write_text((repo / "app.py").read_text() + line)
    sh(repo, "commit", "-qam", line.strip())


@pytest.mark.django_db
def test_main_new_code_since_a_tag_spans_several_scans(repo, project):
    call_command("scan", "demo")
    commit_change(repo, "\nimport sys\n")
    sh(repo, "tag", "v1")
    tagged = sh(repo, "rev-parse", "HEAD")
    call_command("scan", "demo")
    project.new_code_period = "v1"
    project.save()
    commit_change(repo, "\nimport json\n")
    call_command("scan", "demo")
    commit_change(repo, "\nimport re\n")
    call_command("scan", "demo")
    latest = Analysis.objects.latest("started_at")
    assert latest.reference_commit == tagged
    assert sorted(latest.issues.filter(is_new=True, rule="F401").values_list("message", flat=True)) == [
        "`json` imported but unused", "`re` imported but unused"]


@pytest.mark.django_db
def test_main_new_code_by_days(repo, project):
    call_command("scan", "demo")
    old = Analysis.objects.get()
    Analysis.objects.filter(pk=old.pk).update(started_at=timezone.now() - timedelta(days=40))
    commit_change(repo, "\nimport sys\n")
    call_command("scan", "demo")
    project.new_code_period = "30d"
    project.save()
    commit_change(repo, "\nimport json\n")
    call_command("scan", "demo")
    assert Analysis.objects.latest("started_at").reference_commit == old.commit


@pytest.mark.django_db
def test_settings_form_rejects_an_invalid_new_code_period(project):
    data = {"name": "demo", "main_branch": "main", "semgrep_config": "p/default", "complexity_threshold": 10,
            "cognitive_complexity_threshold": 15, "duplicate_literal_threshold": 3, "exclusions": "", "a11y_urls": ""}
    assert ProjectSettingsForm({**data, "new_code_period": "30d"}, instance=project).is_valid()
    assert "new_code_period" in ProjectSettingsForm({**data, "new_code_period": "-x"}, instance=project).errors


@pytest.mark.django_db
def test_failing_gate_exit_code(repo, project):
    (repo / "app.py").write_text("x = undefined_name\n")
    sh(repo, "commit", "-qam", "bad")
    call_command("scan", "demo")
    sh(repo, "checkout", "-qb", "feature")
    (repo / "app.py").write_text("x = undefined_name\ny = other_undefined\n")
    sh(repo, "commit", "-qam", "worse")
    with pytest.raises(SystemExit):
        call_command("scan", "demo", "--branch", "feature", "--fail-on-gate")


@pytest.mark.django_db
def test_new_code_coverage_from_cobertura(repo, project, tmp_path):
    call_command("scan", "demo")
    sh(repo, "checkout", "-qb", "feature")
    (repo / "app.py").write_text("import os\n\n\ndef f():\n    return 1\n\n\ndef g():\n    a = 1\n    return a\n")
    sh(repo, "commit", "-qam", "g")
    report = tmp_path / "coverage.xml"
    report.write_text(
        f'<coverage><sources><source>{repo}</source></sources><packages><package><classes>'
        '<class filename="app.py"><lines><line number="1" hits="1"/><line number="4" hits="1"/>'
        '<line number="5" hits="1"/><line number="8" hits="1"/><line number="9" hits="0"/>'
        '<line number="10" hits="0"/></lines></class></classes></package></packages></coverage>'
    )
    call_command("scan", "demo", "--branch", "feature", "--coverage", str(report), "--coverage-base", str(repo))
    m = Analysis.objects.get(branch="feature").metrics_dict
    assert m["coverage"] == 66.7
    assert m["new_coverage"] == 33.3
    feature = Analysis.objects.get(branch="feature")
    gate_row = next(d for d in feature.gate_details if d["metric"] == "new_coverage")
    assert gate_row["status"] == "too_few_lines", "3 changed lines is below the 20-line minimum"
    Metric.objects.filter(analysis=feature, key="new_lines").update(value=25)
    gate.refresh(feature)
    gate_row = next(d for d in feature.gate_details if d["metric"] == "new_coverage")
    assert gate_row["status"] == "error"
