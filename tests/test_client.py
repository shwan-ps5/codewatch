"""codewatch scan against a local working copy, uploading through the real API views."""
import gzip
import json
import stat

import pytest
from django.test import Client

from core import client as cli
from core.models import Analysis, ApiToken, Project, ProjectMember

from .conftest import ONLY_RUFF, auth, sh, token_for


@pytest.fixture
def server(monkeypatch):
    """Route the CLI's HTTP calls to the Django test client."""
    django_client = Client()

    def request(url, token, data=None, timeout=600):
        path = url.removeprefix("http://testserver")
        if data is None:
            resp = django_client.get(path, headers=auth(token))
        else:
            body = gzip.compress(json.dumps(data).encode())
            resp = django_client.generic(
                "POST", path, body,  # pyright: ignore[reportArgumentType] - Django sends bytes bodies as-is
                content_type="application/json", headers={**auth(token), "Content-Encoding": "gzip"},
            )
        return resp.status_code, resp.json()

    monkeypatch.setattr(cli, "request", request)
    monkeypatch.setenv("CODEWATCH_URL", "http://testserver")


def scan(repo, token, *extra):
    config = repo / "codewatch-project.json"
    if not config.exists():
        config.write_text(json.dumps({"projectKey": "demo", "disabledAnalyzers": ONLY_RUFF}))
        sh(repo, "add", config.name)
        sh(repo, "commit", "-qm", "config")
    return cli.main(["scan", str(repo), "--token", token, *extra])


@pytest.mark.django_db
def test_local_scan_creates_project_and_tracks_branch(repo, alice, server):
    token = token_for(alice)
    assert scan(repo, token) == 0
    project = Project.objects.get(key="demo")
    assert project.owner == alice and project.main_branch == "main" and project.repo_url == ""

    sh(repo, "checkout", "-qb", "feature")
    (repo / "app.py").write_text("# moved down\nimport os\n\n\ndef f():\n    return undefined_name\n")
    (repo / "extra.py").write_text("import sys\n")  # untracked files are scanned and count as new code
    assert scan(repo, token, "--fail-on-gate") == 1

    feature = Analysis.objects.get(branch="feature")
    assert feature.origin == "client" and feature.dirty and feature.scanned_by == alice
    assert sorted(feature.issues.filter(is_new=True).values_list("rule", flat=True)) == ["F401", "F821"]
    assert set(feature.issues.values_list("path", flat=True)) == {"app.py", "extra.py"}
    assert feature.sources.filter(path="app.py").exists()


@pytest.mark.django_db
def test_contributor_can_upload_viewer_cannot(repo, alice, bob, server):
    assert scan(repo, token_for(alice)) == 0
    project = Project.objects.get(key="demo")
    assert scan(repo, token_for(bob)) == 2, "strangers can't upload to someone else's project"
    ProjectMember.objects.create(project=project, user=bob, role=ProjectMember.VIEWER)
    assert scan(repo, token_for(bob)) == 2
    ProjectMember.objects.filter(user=bob).update(role=ProjectMember.CONTRIBUTOR)
    assert scan(repo, token_for(bob)) == 0
    assert scan(repo, token_for(bob, ApiToken.READ)) == 2, "read tokens can't upload"


@pytest.mark.django_db
def test_api_issue_listing_detail_and_resolve(repo, alice, server):
    token = token_for(alice)
    scan(repo, token)
    c = Client()
    data = c.get("/api/projects/demo/issues/?type=code_smell,bug", headers=auth(token)).json()
    issue = next(i for i in data["issues"] if i["rule"] == "F401")
    assert issue["path"] == "app.py" and issue["line"] == 1

    detail = c.get(f"/api/issues/{issue['id']}/?context=1", headers=auth(token)).json()
    assert detail["snippet"][0] == {"line": 1, "text": "import os"}

    read = token_for(alice, ApiToken.READ)
    resp = c.post(f"/api/issues/{issue['id']}/resolve/", json.dumps({"status": "false_positive", "comment": "ok"}),
                  content_type="application/json", headers=auth(read))
    assert resp.status_code == 200
    open_rules = [i["rule"] for i in c.get("/api/projects/demo/issues/", headers=auth(read)).json()["issues"]]
    assert "F401" not in open_rules
    assert c.get("/api/projects/", headers=auth("cw_wrong")).status_code == 401


def test_init_writes_config_and_hook(repo, monkeypatch):
    monkeypatch.setenv("CODEWATCH_URL", "http://example.test")
    assert cli.main(["init", str(repo), "--hook", "pre-push"]) == 0
    conf = json.loads((repo / "codewatch-project.json").read_text())
    assert conf == {"projectKey": "repo", "projectName": "repo", "mainBranch": "main",
                    "serverUrl": "http://example.test"}
    hook = repo / ".git" / "hooks" / "pre-push"
    assert "coverage || exit 1" in hook.read_text() and hook.stat().st_mode & stat.S_IXUSR
    (hook).write_text("#!/bin/sh\necho mine\n")
    assert cli.main(["init", str(repo), "--hook", "pre-push"]) == 2, "never overwrite someone else's hook"


def test_coverage_uses_test_command(repo):
    (repo / "codewatch-project.json").write_text(json.dumps({"testCommand": "echo '<coverage/>' > coverage.xml"}))
    assert cli.main(["coverage", str(repo)]) == 0
    assert (repo / "coverage.xml").read_text().strip() == "<coverage/>"
    (repo / "codewatch-project.json").write_text(json.dumps({"testCommand": "exit 3"}))
    assert cli.main(["coverage", str(repo)]) == 3
