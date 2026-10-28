"""Accessibility analyzers, and axe-core run over codewatch's own pages."""
import json

import pytest
from django.contrib.auth.models import User
from django.test import Client

from core.analyzers.accessibility import Axe, HtmlA11y, JsxA11y
from core.analyzers.base import Context
from core.models import Project, ProjectMember

from .conftest import token_for
from .test_client import (
    scan,
    server,  # noqa: F401
)


def needs(analyzer):
    return pytest.mark.skipif(not analyzer.available(), reason=f"{analyzer.name} tools not installed")


@needs(HtmlA11y())
def test_html_a11y_on_django_template(tmp_path):
    (tmp_path / "t.html").write_text(
        '{% load static %}<div>\n<img src="{% static "a.png" %}">\n'
        '<h2>{# nothing #}</h2>\n<label>Name</label><input id="x" type="text">\n</div>\n'
    )
    result = HtmlA11y().run(Context(root=tmp_path, files=["t.html"]))
    rules = {(f.rule, f.line) for f in result.findings}
    assert ("wcag/h37", 2) in rules, "img without alt"
    assert ("empty-heading", 3) in rules, "heading whose only content is a template comment"
    assert ("input-missing-label", 4) in rules, "label not associated with the input"
    assert all(f.type == "accessibility" and f.path == "t.html" for f in result.findings)
    assert not any(f.rule == "parser-error" for f in result.findings)


@needs(JsxA11y())
def test_jsx_a11y(tmp_path):
    (tmp_path / "a.tsx").write_text('export const A = () => <img src="x.png" />;\n')
    result = JsxA11y().run(Context(root=tmp_path, files=["a.tsx"]))
    assert [(f.rule, f.line) for f in result.findings] == [("jsx-a11y/alt-text", 1)]


@needs(Axe())
def test_axe_flags_contrast_on_live_page(tmp_path):
    page = tmp_path / "p.html"
    page.write_text('<!doctype html><html lang="en"><head><title>t</title></head><body><main><h1>Hi</h1>'
                    '<p style="color:#bbb;background:#fff">low contrast</p></main></body></html>')
    result = Axe().run(Context(root=tmp_path, files=[], a11y_urls=[page.as_uri()]))
    assert {f.rule for f in result.findings} == {"color-contrast"}
    assert result.findings[0].severity == "major" and result.findings[0].path == page.as_uri()


@needs(Axe())
@pytest.mark.django_db
def test_codewatch_pages_pass_axe(repo, alice, bob, server, tmp_path):  # noqa: F811
    """Render the main pages to files and require zero axe violations in both colour schemes."""
    token = token_for(alice)
    scan(repo, token)
    project = Project.objects.get(key="demo")
    ProjectMember.objects.create(project=project, user=bob)
    analysis = project.analyses.get()
    issue = analysis.issues.first()
    admin = User.objects.get(username="admin")
    admin.profile.must_change_password = False
    admin.profile.save()

    pages = {
        "login": (None, "/login/"),
        "index": (alice, "/"),
        "project": (alice, "/p/demo/"),
        "analysis": (alice, f"/p/demo/a/{analysis.pk}/"),
        "issues": (alice, f"/p/demo/a/{analysis.pk}/issues/"),
        "source": (alice, f"/p/demo/a/{analysis.pk}/source/?path={issue.path}"),
        "settings": (alice, "/p/demo/settings/"),
        "account": (alice, "/account/"),
        "password": (alice, "/account/password/"),
        "new-project": (alice, "/projects/new/"),
        "users": (admin, "/users/"),
        "user-edit": (admin, f"/users/{bob.pk}/"),
    }
    urls = []
    for name, (user, path) in pages.items():
        c = Client()
        if user:
            c.force_login(user)
        resp = c.get(path)
        assert resp.status_code == 200, name
        out = tmp_path / f"{name}.html"
        out.write_bytes(resp.content)
        urls.append(out.as_uri())
    problems = []
    for scheme in ("light", "dark"):
        result = Axe(scheme).run(Context(root=tmp_path, files=[], a11y_urls=urls))
        problems += [f"{scheme} {f.path.rsplit('/', 1)[-1]}: {f.rule} {f.message[:160]}" for f in result.findings]
    assert problems == [], json.dumps(problems, indent=1)
