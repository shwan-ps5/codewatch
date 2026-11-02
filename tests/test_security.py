"""The server's own security: what an upload, a repository or a project's settings can make it do."""
import json
import os
from pathlib import Path

import pytest
from django.core.management import call_command
from django.test import Client

from core.analyzers.base import Context
from core.collect import GitError, LocalRepo, inside, read_sources
from core.git import Mirror
from core.models import Analysis, Project

from .conftest import ONLY_RUFF, auth, sh, token_for

HEAD = "a" * 40


def upload(token, **fields):
    payload = {"branch": "main", "commit": HEAD, "issues": [], "metrics": {}, **fields}
    return Client().post("/api/projects/demo/analyses/", json.dumps(payload), content_type="application/json",
                         headers=auth(token))


@pytest.mark.django_db
def test_uploaded_commits_and_branches_must_be_what_they_claim(alice):
    token = token_for(alice)
    assert upload(token, commit="--output=/tmp/x").status_code == 400
    assert upload(token, reference_commit="--output=/tmp/x").status_code == 400
    assert upload(token, reference_analysis_commit="HEAD~1").status_code == 400
    assert upload(token, branch="--all").status_code == 400
    assert upload(token, branch="a b").status_code == 400
    assert not Analysis.objects.exists()
    bad_issue = {"tool": "t", "rule": "r", "severity": "urgent", "type": "bug", "message": "m", "path": "a.py",
                 "line": 1, "end_line": 1, "fingerprint": "f", "also_reported_by": []}
    assert upload(token, issues=[bad_issue]).status_code == 400
    assert upload(token, branch="feature/x-1.2", reference_commit="b" * 40).status_code == 201


def test_a_revision_is_never_taken_for_a_git_option(repo, tmp_path, settings):
    written = tmp_path / "written"
    hostile = f"--output={written}"
    with pytest.raises(GitError):
        LocalRepo(repo).changed_lines(hostile)
    assert LocalRepo(repo).merge_base(hostile, "HEAD") is None
    assert LocalRepo(repo).resolve_commit(hostile) is None

    settings.CODEWATCH_CACHE = tmp_path / "cache"
    mirror = Mirror(Project(key="demo", repo_url=str(repo)))
    mirror.sync()
    head = sh(repo, "rev-parse", "HEAD")
    for call in (lambda: mirror.show(hostile, "app.py"), lambda: mirror.changed_lines(hostile, head),
                 lambda: mirror.tracked_files(hostile), lambda: mirror.rev_parse(hostile)):
        with pytest.raises(GitError):
            call()
    assert not mirror.has_commit(hostile) and not mirror.is_ancestor(hostile, head)
    assert mirror.show(head, "app.py").startswith("import os")
    assert not written.exists()


@pytest.mark.django_db
def test_a_symlink_never_brings_a_file_from_outside_the_repository(repo, tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text("import os\nSECRET = 'server file'\n")
    (repo / "linked.py").symlink_to(outside)
    (repo / "inner.py").symlink_to("app.py")
    sh(repo, "add", ".")
    sh(repo, "commit", "-qm", "links")
    call_command("addproject", "demo", str(repo))
    Project.objects.filter(key="demo").update(disabled_analyzers=ONLY_RUFF)
    call_command("scan", "demo")
    analysis = Analysis.objects.get()
    assert analysis.status == Analysis.SUCCESS
    assert not analysis.issues.filter(path="linked.py").exists()
    assert not analysis.sources.filter(blob__content__contains="server file").exists()
    assert analysis.issues.filter(path="app.py").exists()

    files = ["app.py", "linked.py", "inner.py"]
    assert [f for f in files if inside(repo, f)] == ["app.py", "inner.py"]
    assert "linked.py" not in read_sources(repo, files)


def test_a_server_scan_never_runs_the_repositorys_python(tmp_path, monkeypatch):
    """basedpyright runs a venv's python to find its packages, and pip-audit builds what it resolves: a repository
    can commit both. Only the developer's own copy (codewatch-scan) is trusted with them."""
    from core.analyzers import dependencies, extra

    (tmp_path / "venv" / "bin").mkdir(parents=True)
    (tmp_path / "venv" / "bin" / "python").write_text("#!/bin/sh\ntouch owned\n")
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / "requirements.txt").write_text("-e .\ndjango==5.1.15\n")
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n")
    configs, audits = [], []

    def pyright(self, args, ctx, ok_codes=(0,)):
        configs.append(json.loads(Path(args[args.index("--project") + 1]).read_text()))
        return "{}"

    def audit(self, args, ctx, ok_codes=(0,)):
        audits.append(args)
        return json.dumps({"dependencies": []})

    monkeypatch.setattr(extra.TypeCheck, "exec", pyright)
    monkeypatch.setattr(dependencies.PipAudit, "exec", audit)
    by_kind = {}
    for local in (False, True):
        audits.clear()
        ctx = Context(root=tmp_path, files=["app.py", "requirements.txt", "pyproject.toml"], local=local)
        extra.TypeCheck().run(ctx)
        dependencies.PipAudit().run(ctx)
        by_kind[local] = list(audits)
    server, own = configs
    assert "venv" not in server and own["venv"] == "venv"
    assert by_kind[False] == [["-r", "requirements.txt", "--no-deps", "--disable-pip", "--format", "json",
                               "--progress-spinner", "off"]]
    assert ["-r", "requirements.txt", "--format", "json", "--progress-spinner", "off"] in by_kind[True]


@pytest.mark.django_db
def test_only_an_administrators_project_clones_with_the_servers_git_credentials(repo, tmp_path, settings,
                                                                                monkeypatch, alice):
    """The server's global git config stands in for its credentials: here it maps a private URL to a repository."""
    from django.contrib.auth.models import User

    from core import git

    config = tmp_path / "server.gitconfig"
    config.write_text(f'[url "{repo}"]\n\tinsteadOf = https://private.example/demo\n')
    monkeypatch.setattr(git, "GIT_ENV", {**git.GIT_ENV, "GIT_CONFIG_GLOBAL": str(config)})
    monkeypatch.setattr(git, "check_public", lambda url: url)  # what's under test is the credentials
    settings.CODEWATCH_CACHE = tmp_path / "cache"
    admin = User.objects.create_superuser("root", password="pw-root-123")  # nosec B106  # pragma: allowlist secret
    url = "https://private.example/demo"
    with pytest.raises(GitError):
        Mirror(Project.objects.create(key="theirs", repo_url=url, owner=alice)).sync()
    mine = Mirror(Project.objects.create(key="mine", repo_url=url, owner=admin))
    mine.sync()
    assert mine.branches() == ["main"]


@pytest.mark.django_db
def test_a_deleted_projects_mirror_never_serves_the_next_project_with_its_key(repo, tmp_path, settings):
    from django.contrib.auth.models import User

    settings.CODEWATCH_CACHE = tmp_path / "cache"
    admin = User.objects.create_superuser("root", password="pw-root-123")  # nosec B106  # pragma: allowlist secret
    first = Project.objects.create(key="demo", repo_url=str(repo), owner=admin)
    Mirror(first).sync()
    client = Client()
    client.force_login(admin)
    client.post("/p/demo/delete/", {"confirm": "demo"})
    assert not Project.objects.exists() and not (tmp_path / "cache" / "demo").exists()

    other = tmp_path / "other"
    other.mkdir()
    for args in (("init", "-q", "-b", "main"), ("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q",
                                               "--allow-empty", "-m", "other")):
        sh(other, *args)
    Mirror(first).sync()  # left behind, as before the fix
    second = Project.objects.create(key="demo", repo_url=str(other), owner=admin)
    Mirror(second).sync()
    assert sh(repo, "rev-parse", "HEAD") != Mirror(second).rev_parse("main") == sh(other, "rev-parse", "HEAD")


@pytest.mark.django_db
def test_only_an_administrators_project_reaches_the_servers_own_network(alice, monkeypatch):
    from core import network
    from core.views import ProjectSettingsForm

    addresses = {"intranet.example": "10.0.0.5", "metadata.example": "169.254.169.254", "site.example": "93.184.215.14"}
    monkeypatch.setattr(network.socket, "getaddrinfo", lambda host, port: [(0, 0, 0, "", (addresses[host], 0))])
    with pytest.raises(ValueError, match="private or local"):
        network.check_public("https://intranet.example/repo.git")
    with pytest.raises(ValueError, match="private or local"):
        network.check_public("git@metadata.example:org/repo.git")
    assert network.check_public("https://site.example/x")

    project = Project.objects.create(key="demo", owner=alice)
    data = {"name": "demo", "main_branch": "main", "complexity_threshold": 10, "cognitive_complexity_threshold": 15,
            "duplicate_literal_threshold": 3, "exclusions": "", "new_code_period": ""}
    def errors(**fields):
        return ProjectSettingsForm({**data, "semgrep_config": "p/default", "a11y_urls": "", **fields},
                                   instance=project).errors
    assert not errors(a11y_urls="https://site.example/{branch}")
    assert "a11y_urls" in errors(a11y_urls="http://metadata.example/latest/")
    assert "semgrep_config" in errors(semgrep_config="http://intranet.example/rules.yml")
    assert "semgrep_config" in errors(semgrep_config="/etc/passwd")
    project.owner = None  # added by an administrator with manage.py addproject
    assert not errors(a11y_urls="http://intranet.example/", semgrep_config="/srv/rules.yml")


def test_the_client_sends_its_token_only_to_a_server_its_user_chose(repo, monkeypatch, trusted_servers_file):
    from core import client

    monkeypatch.delenv("CODEWATCH_URL", raising=False)
    monkeypatch.setenv("CODEWATCH_TOKEN", "cw_secret")
    real_request = client.request
    sent = []
    monkeypatch.setattr(client, "request", lambda url, token, data=None, timeout=600: sent.append(url) or (500, {}))
    (repo / "codewatch-project.json").write_text(json.dumps({"projectKey": "demo",
                                                              "serverUrl": "https://collector.example"}))
    assert client.main(["scan", str(repo)]) == 2
    assert sent == []
    trusted_servers_file.parent.mkdir()
    trusted_servers_file.write_text("https://collector.example\n")
    client.main(["scan", str(repo)])
    assert sent and sent[0].startswith("https://collector.example/")

    with pytest.raises(client.ClientError, match="plain http"):
        real_request("http://codewatch.example/api/", "cw_secret")


def test_init_trusts_the_server_its_user_gave(repo, trusted_servers_file):
    from core import client

    assert client.main(["init", str(repo), "--url", "https://codewatch.example/"]) == 0
    assert trusted_servers_file.read_text() == "https://codewatch.example\n"


@pytest.mark.django_db
def test_repeated_wrong_passwords_lock_the_login_for_a_while(alice):
    from django.core.cache import cache

    cache.clear()
    c = Client()
    assert c.get("/login/").status_code == 200
    for _ in range(10):
        assert c.post("/login/", {"username": "alice", "password": "guess"}).status_code == 200  # nosec B105
    right = {"username": "alice", "password": "pw-alice-123"}  # nosec B105  # pragma: allowlist secret
    assert c.post("/login/", right).status_code == 429
    cache.clear()
    assert c.post("/login/", right).status_code == 302


def test_settings_are_safe_unless_configured_otherwise():
    from django.conf import settings

    assert not settings.DEBUG
    assert settings.ALLOWED_HOSTS[:3] == ["localhost", "127.0.0.1", "[::1]"]
    assert settings.X_FRAME_OPTIONS == "DENY"
    if "CODEWATCH_SECRET_KEY" not in os.environ:
        assert (settings.CODEWATCH_CACHE / "secret_key").stat().st_mode & 0o077 == 0, "only this account reads it"


def test_upgrading_the_tools_installs_only_locked_versions(monkeypatch):
    from core.catalog import update

    steps = []
    monkeypatch.setattr(update, "run_step", lambda args, log, cwd=None: steps.append([str(a) for a in args]) or True)
    assert update.upgrade_tools(lambda message: None)
    pip = [s for s in steps if "pip" in " ".join(s)]
    assert pip and all("--require-hashes" in s and "-U" not in s for s in pip)
    assert ["npm", "ci", "--no-fund", "--no-audit"] in steps
    assert not any("@latest" in a for s in steps for a in s)


@pytest.mark.django_db
def test_scans_are_limited_per_branch_and_across_the_server(alice, monkeypatch, settings, tmp_path):
    from django.core.files.uploadedfile import SimpleUploadedFile

    from core import jobs

    launched = []
    monkeypatch.setattr(jobs.subprocess, "Popen", lambda args, **kw: launched.append(args))
    settings.CODEWATCH_CACHE = tmp_path / "cache"
    project = Project.objects.create(key="demo", repo_url="https://site.example/r.git", main_branch="main",
                                     owner=alice)
    Analysis.objects.create(project=project, branch="main", commit=HEAD)
    assert "already being analysed" in jobs.scan_refusal(project)
    assert jobs.launch_scan(project) is None, "the main branch counts as a branch too"
    assert jobs.scan_refusal(project, "--upload-pack=x") == "That isn't a branch name."
    assert jobs.scan_refusal(project, "feature") is None

    monkeypatch.setattr(jobs, "MAX_RUNNING_SCANS", 1)
    assert "already running 1 scans" in jobs.scan_refusal(project, "feature")
    monkeypatch.setattr(jobs, "MAX_RUNNING_SCANS", 4)

    settings.CODEWATCH_MAX_COVERAGE_UPLOAD = 10
    report = SimpleUploadedFile("coverage.xml", b"<coverage>" + b" " * 20 + b"</coverage>")
    resp = Client().post("/api/projects/demo/scan/", {"branch": "feature", "coverage": report},
                         headers=auth(token_for(alice)))
    assert resp.status_code == 413 and not launched


@pytest.mark.django_db
def test_an_uploaded_analysis_says_its_results_are_self_reported(alice):
    assert upload(token_for(alice)).status_code == 201
    analysis = Analysis.objects.get()
    client = Client()
    client.force_login(alice)
    assert "(self-reported)" in client.get("/p/demo/").content.decode()
    assert "the server didn't run this scan" in client.get(f"/p/demo/a/{analysis.pk}/").content.decode()


def test_a_file_name_never_reaches_a_tool_as_an_option(tmp_path):
    from core.collect import ScanConfig, ScanInput, collect

    name = "--output-file=out.json.py"
    (tmp_path / name).write_text("import os\n")
    cfg = ScanConfig.from_dict({"disabled_analyzers": ONLY_RUFF})
    payload = collect(cfg, ScanInput(tmp_path, [name], "main"), log=lambda message: None)
    assert [(i["rule"], i["path"]) for i in payload["issues"]] == [("F401", name)]
    assert not (tmp_path / "out.json.py").exists()


@pytest.mark.django_db
def test_api_numbers_are_checked_and_issues_sorted_by_the_database(alice):
    token = token_for(alice)
    issues = [{"tool": "t", "rule": f"r{n}", "severity": severity, "type": "bug", "message": "m", "path": path,
               "line": line, "end_line": line, "fingerprint": f"f{n}", "also_reported_by": []}
              for n, (severity, path, line) in enumerate([("minor", "a.py", 1), ("blocker", "b.py", 9),
                                                           ("blocker", "a.py", None), ("info", "a.py", 2)])]
    assert upload(token, issues=issues, main_branch="main").status_code == 201
    c = Client()
    for query in ("limit=x", "offset=-1", "limit=0"):
        assert c.get(f"/api/projects/demo/issues/?{query}", headers=auth(token)).status_code == 400
    page = c.get("/api/projects/demo/issues/?limit=3&offset=0", headers=auth(token)).json()
    assert page["total"] == 4
    assert [(i["severity"], i["path"], i["line"]) for i in page["issues"]] == [
        ("blocker", "a.py", None), ("blocker", "b.py", 9), ("minor", "a.py", 1)]
