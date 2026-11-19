"""Adding a local repository from the new-project page: pick its folder, create it with a scan token, scan it from
the project list."""
import subprocess

import pytest
from django.contrib.auth.models import User
from django.forms.models import model_to_dict
from django.test import Client

from core import views
from core.models import Analysis, ApiToken, Project
from core.runner import progress_recorder


@pytest.fixture
def admin():
    user = User.objects.get(username="admin")
    user.profile.must_change_password = False
    user.profile.save()
    c = Client()
    c.force_login(user)
    return c


@pytest.fixture
def root(tmp_path, settings):
    settings.CODEWATCH_BROWSE_ROOT = tmp_path
    (tmp_path / "Dev" / "My App").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(tmp_path / "Dev" / "My App")], check=True)
    (tmp_path / "Dev" / "notes").mkdir()
    (tmp_path / "Dev" / ".hidden").mkdir()
    return tmp_path


@pytest.fixture
def launched(monkeypatch):
    calls = []
    monkeypatch.setattr(views, "launch_scan", lambda project, branch=None: calls.append((project.key, branch)))
    return calls


@pytest.mark.django_db
def test_the_folder_list_marks_repositories_and_hides_hidden_folders(admin, root):
    browse = admin.get("/projects/new/?folder=Dev").context["browse"]
    assert [(f["name"], f["repository"]) for f in browse["folders"]] == [("My App", True), ("notes", False)]
    assert browse["parent"] == ""


@pytest.mark.django_db
def test_browsing_stays_under_the_browse_root(admin, root):
    for outside in ("..", "../..", "/etc", "Dev/../../"):
        assert admin.get("/projects/new/", {"folder": outside}).context["browse"]["path"] == "", outside


@pytest.mark.django_db
def test_using_a_folder_fills_in_its_path_title_and_a_free_key(admin, root):
    Project.objects.create(key="my-app", name="taken")
    form = admin.get("/projects/new/", {"use": "Dev/My App"}).context["form"]
    assert form.initial == {"repo_url": str(root / "Dev" / "My App"), "name": "My App", "key": "my-app-2"}


@pytest.mark.django_db
def test_a_folder_outside_the_root_or_missing_fills_in_nothing(admin, root):
    for use in ("..", "/etc", "Dev/missing", ""):
        assert admin.get("/projects/new/", {"use": use}).context["picked"] is None, use


@pytest.mark.django_db
def test_only_administrators_browse_folders(alice, root):
    c = Client()
    c.force_login(alice)
    resp = c.get("/projects/new/", {"folder": "Dev", "use": "Dev/My App"})
    assert resp.context["browse"] is None and resp.context["picked"] is None
    assert b"My App" not in resp.content


@pytest.mark.django_db
def test_creating_a_project_shows_a_scan_token_once_on_its_page(admin, root, launched):
    path = str(root / "Dev" / "My App")
    resp = admin.post("/projects/new/", {"key": "my-app", "name": "My App", "repo_url": path, "main_branch": ""})
    assert resp.url == "/p/my-app/" and launched == [("my-app", None)]
    page = admin.get("/p/my-app/")
    raw = page.context["new_token"]
    token = ApiToken.objects.get()
    assert raw.startswith("cw_") and token.scope == ApiToken.SCAN and token.name.startswith("my-app")
    assert f"CODEWATCH_TOKEN={raw} codewatch-scan --project my-app".encode() in page.content
    assert raw.encode() not in admin.get("/p/my-app/").content


@pytest.mark.django_db
def test_the_project_list_scans_a_project_and_comes_back(admin, root, launched):
    admin.post("/projects/new/", {"key": "my-app", "name": "My App", "repo_url": str(root / "Dev" / "My App")})
    Project.objects.create(key="uploaded", name="uploaded", owner=User.objects.get(username="admin"))
    page = admin.get("/")
    assert [(p.key, scannable) for p, _a, scannable, _running in page.context["projects"]] == [
        ("my-app", True), ("uploaded", False)]
    resp = admin.post("/p/my-app/scan/", {"next": "/"})
    assert resp.url == "/" and launched[-1] == ("my-app", None)


@pytest.mark.django_db
def test_a_running_scan_shows_its_steps_on_the_project_page_and_list(admin, root, launched):
    admin.post("/projects/new/", {"key": "my-app", "name": "My App", "repo_url": str(root / "Dev" / "My App")})
    analysis = Analysis.objects.create(project=Project.objects.get(key="my-app"), branch="main", commit="0" * 40)
    step = progress_recorder(analysis, log=lambda line: None)
    for line in ("Running ruff", "  ruff failed: something", "Running semgrep"):
        step(line)
    assert [s["step"] for s in Analysis.objects.get(pk=analysis.pk).progress] == ["Running ruff", "Running semgrep"]
    page = admin.get("/p/my-app/").content.decode()
    assert 'id="scan-progress" data-live' in page and "Running semgrep (for" in page and "Finished: ruff" in page
    listing = admin.get("/").content.decode()
    assert 'id="projects" data-live' in listing and "<strong>Scanning</strong>: semgrep" in listing
    analysis.status = Analysis.SUCCESS
    analysis.save()
    assert "scan-progress" not in admin.get("/p/my-app/").content.decode()


def settings_form(project, **changes):
    """The settings form as its page would post it, with changes."""
    data = {k: v for k, v in model_to_dict(project, fields=views.ProjectSettingsForm.Meta.fields).items()
            if v is not None}
    data.update(exclusions="", a11y_urls="", disabled_analyzers=[], **changes)
    return views.ProjectSettingsForm(data, instance=project)


@pytest.mark.django_db
def test_a_project_scanned_only_by_uploads_can_be_given_a_folder_to_scan(admin, root):
    project = Project.objects.create(key="uploaded", name="uploaded", owner=User.objects.get(username="admin"))
    form = settings_form(project, repo_url=str(root / "Dev" / "My App"))
    assert form.is_valid(), form.errors
    form.save()
    assert Project.objects.get(key="uploaded").repo_url == str(root / "Dev" / "My App")


@pytest.mark.django_db
def test_only_an_administrators_project_can_be_given_a_folder(alice, root):
    project = Project.objects.create(key="hers", name="hers", owner=alice)
    form = settings_form(project, repo_url=str(root / "Dev" / "My App"))
    assert not form.is_valid() and "repo_url" in form.errors
