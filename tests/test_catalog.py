"""Rule catalogue: imported vs custom layers, duplicates, codewatch's own checks, ratings, public pages."""
import ast
import json
from datetime import UTC, datetime, timedelta

import pytest
from django.contrib.auth.models import User
from django.test import Client

from core import catalog, ratings
from core.analyzers.base import Context
from core.analyzers.codewatch_checks import CodewatchChecks, python_literals, python_regexes, to_js_syntax
from core.analyzers.multi_tools import Semgrep
from core.catalog import update
from core.catalog.merge import merge
from core.duplicates import dedupe

IMPORTED = [
    {"id": "ruff/S602", "tool": "ruff", "code": "S602", "title": "Shell true", "languages": ["python"],
     "type": "security_hotspot", "severity": "major", "summary": "", "docs": "", "license": "MIT",
     "references": [], "cwe": [], "wcag": [], "owasp": [], "_same_as": ["bandit/B602"]},
    {"id": "bandit/B602:subprocess_popen_with_shell_equals_true", "tool": "bandit",
     "code": "B602:subprocess_popen_with_shell_equals_true", "title": "Popen shell", "languages": ["python"],
     "type": "vulnerability", "severity": "varies", "summary": "", "docs": "", "license": "Apache",
     "references": [], "cwe": [78], "wcag": [], "owasp": []},
]
STANDARDS = {"cwe_names": {"78": "OS Command Injection"}, "cwe_parents": {},
             "owasp": {"categories": [{"id": "A05:2025", "name": "Injection", "cwes": [78]}]}}


def test_merge_applies_custom_layer_without_touching_imports(tmp_path):
    rule_file = tmp_path / "mine.yml"
    rule_file.write_text("rules:\n  - id: my.rule\n    languages: [python]\n    severity: ERROR\n"
                         "    message: Never do this. Really.\n    pattern: eval(...)\n"
                         "    metadata: {category: security, cwe: ['CWE-95: Eval Injection']}\n")
    mappings = {"cwe": {"ruff/S602": [78]}}
    overrides = {"bandit/B602:subprocess_popen_with_shell_equals_true": {"severity": "critical", "bogus": 1}}
    rules = {r["id"]: r for r in merge(IMPORTED, STANDARDS, mappings, overrides, [(rule_file, "custom")])}

    assert "_same_as" in IMPORTED[0], "the imported data itself is never modified"
    s602 = rules["ruff/S602"]
    assert s602["cwe"] == [78] and s602["owasp"] == ["A05:2025"] and s602["mapped_by"] == ["codewatch"]
    assert s602["same_as"] == ["bandit/B602:subprocess_popen_with_shell_equals_true"]
    b602 = rules["bandit/B602:subprocess_popen_with_shell_equals_true"]
    assert b602["severity"] == "critical" and b602["overridden"] and "bogus" not in b602
    custom = rules["codewatch/my.rule"]
    assert custom["origin"] == "custom" and custom["cwe"] == [95] and custom["severity"] == "critical"
    assert rules["codewatch/duplicate-string-literal"]["origin"] == "codewatch"


def issue(tool, rule, severity="major", type_="vulnerability", line=3):
    return {"tool": tool, "rule": rule, "severity": severity, "type": type_, "message": "m", "path": "a.py",
            "line": line, "end_line": None, "fingerprint": tool + rule}


@pytest.mark.django_db
def test_dedupe_keeps_most_severe_and_records_others():
    kept = dedupe([
        issue("ruff", "S602", "major", "security_hotspot"),
        issue("bandit", "B602:subprocess_popen_with_shell_equals_true", "critical"),
        issue("ruff", "F401", "minor", "code_smell"),
        issue("bandit", "B602:subprocess_popen_with_shell_equals_true", "critical", line=9),
    ])
    assert [(i["tool"], i["line"]) for i in kept] == [("bandit", 3), ("bandit", 9), ("ruff", 3)]
    assert kept[0]["also_reported_by"] == ["ruff:S602"]


def test_python_literals_and_regexes():
    tree = ast.parse('"""Docstring docstring."""\nA = "hello world"\nB = "hello world"\nC = "hello world"\n'
                     'D = "hello world"\nE = {"hello world": 1}\nimport re\nre.compile(r"(?P<x>a+)+$", re.I)\n'
                     'F = "hi"\nG = "hi"\nH = "hi"\nI = "hi"\n')
    assert python_literals(tree, 3) == [("hello world", [2, 3, 4, 5])], "dict keys and short strings ignored"
    [rx] = python_regexes(tree, "a.py")
    assert rx["pattern"] == "(?<x>a+)+$" and rx["flags"] == "i" and rx["line"] == 8
    assert to_js_syntax(r"\A(?P=n)\Z") == r"^\k<n>$"


@pytest.mark.skipif(not CodewatchChecks().available(), reason="tools/ not installed")
def test_codewatch_checks_find_redos_in_python_and_js(tmp_path):
    (tmp_path / "a.py").write_text('import re\nEMAIL = re.compile(r"^([a-z0-9_.+-])+@(([a-z0-9-])+\\.)+([a-z]{2,4})+$")\n'
                                   'OK = re.compile(r"^\\d{3}-\\d{4}$")\n')
    (tmp_path / "b.js").write_text('const r = /^(a+)+$/;\nconst s = ["xyzzy","xyzzy","xyzzy","xyzzy"];\n')
    result = CodewatchChecks().run(Context(root=tmp_path, files=["a.py", "b.js"]))
    found = sorted((f.rule, f.path, f.line, f.severity) for f in result.findings)
    assert found == [("duplicate-string-literal", "b.js", 2, "minor"),
                     ("regex-backtracking", "a.py", 2, "critical"),
                     ("regex-backtracking", "b.js", 1, "critical")]


def test_ratings():
    assert ratings.worst([]) == 1 and ratings.worst(["minor", "critical"]) == 4
    assert ratings.debt_rating(0, 0) == 1 and ratings.debt_rating(60, 10) == 3  # 20% debt
    assert ratings.review_rating(0, 0) == 1 and ratings.review_rating(1, 4) == 1 and ratings.review_rating(3, 1) == 5
    out = ratings.compute([("bug", "major"), ("code_smell", "minor")], 0, {"ncloc": 100}, "")
    assert out["reliability_rating"] == 3 and out["maintainability_rating"] == 1
    assert out["health_score"] == 90 and ratings.score_grade(90) == "A"


def test_update_due(tmp_path, monkeypatch):
    monkeypatch.setattr(update, "STATUS_FILE", tmp_path / "status.json")
    monkeypatch.setattr(update, "imported_dir", lambda: tmp_path)
    monkeypatch.setenv("CODEWATCH_CATALOG_UPDATE_DAYS", "7")
    assert update.due(), "never imported"
    old = (datetime.now(UTC) - timedelta(days=8)).isoformat()
    (tmp_path / "meta.json").write_text(json.dumps({"imported_at": datetime.now(UTC).isoformat()}))
    assert not update.due()
    (tmp_path / "meta.json").write_text(json.dumps({"imported_at": old}))
    assert update.due()
    update.write_status(state="running", started_at=datetime.now(UTC).isoformat())
    assert not update.due(), "already running"
    monkeypatch.setenv("CODEWATCH_CATALOG_UPDATE_DAYS", "0")
    update.write_status(state="done")
    assert not update.due(), "0 disables the schedule"


@pytest.mark.django_db
def test_public_rule_pages_and_update_permissions(monkeypatch):
    launched = []
    monkeypatch.setattr(update, "launch", lambda upgrade=False: launched.append(upgrade))
    monkeypatch.setattr(update, "running", lambda: False)
    c = Client()
    assert c.get("/rules/?q=unused").status_code == 200
    page = c.get("/rules/ruff/F841/")
    assert page.status_code == 200 and b"What's wrong and how to fix it" in page.content
    assert c.get("/rules/codewatch/regex-backtracking/").status_code == 200
    assert c.get("/rules/nope/").status_code == 404
    assert c.get("/standards/").status_code == 200
    user = User.objects.create_user("u", password="p-12345678x")  # nosec B106  # pragma: allowlist secret
    c.force_login(user)
    assert c.post("/rules/update/").status_code == 403
    admin = User.objects.get(username="admin")
    admin.profile.must_change_password = False
    admin.profile.save()
    c.force_login(admin)
    c.post("/rules/update/", {"upgrade": "1"})
    assert launched == [True]


@pytest.mark.django_db
def test_rule_api():
    from core.models import ApiToken

    raw = ApiToken.issue(User.objects.get(username="admin"), "t", ApiToken.READ)[1]
    data = Client().get("/api/rules/bandit/B602:subprocess_popen_with_shell_equals_true/",
                        headers={"Authorization": f"Bearer {raw}"}).json()
    assert data["cwe"] == [78] and "ruff/S602" in data["same_as"] and data["explanation"]
    assert data["cwe_guidance"][0]["mitigations"]
    catalog.reload()


def test_table_semantics():
    from core.analyzers.codewatch_checks import table_problems

    assert table_problems('<table role="presentation"><tr><th>A</th><td>1</td></tr></table>') == [
        (1, "layout-table-with-headers")]
    assert table_problems("<table><tr><td>1</td></tr></table>") == [(1, "data-table-without-headers")]
    assert table_problems('<table><tr><th scope="col">x</th></tr><tr><td>1</td></tr></table>') == []
    assert table_problems('<table role="none"><tr><td>layout</td></tr></table>') == []
    assert table_problems("<table><caption>c</caption><tr><td>1</td></tr></table>") == [
        (1, "data-table-without-headers")]


def test_security_findings_are_verdicts_only_with_data_flow():
    from core.analyzers.multi_tools import semgrep_type

    assert semgrep_type("python.flask.security.injection.x", {"category": "security", "subcategory": ["vuln"]}) == "vulnerability"
    assert semgrep_type("python.lang.security.audit.x", {"category": "security", "subcategory": ["vuln"]}) == "security_hotspot"
    assert semgrep_type("python.lang.security.x", {"category": "security", "subcategory": ["audit"]}) == "security_hotspot"
    assert semgrep_type("python.lang.correctness.x", {"category": "correctness"}) == "bug"


def test_builtin_rules_load_and_a_broken_custom_file_is_skipped(tmp_path, monkeypatch, capsys):
    import yaml

    (tmp_path / "rules").mkdir()
    (tmp_path / "rules" / "broken.yml").write_text("rules: [ {id: x, pattern: a: b ")
    monkeypatch.setattr(catalog, "CUSTOM_DIR", tmp_path)
    rules = yaml.safe_load(catalog.custom_semgrep_rules())["rules"]
    ids = {r["id"] for r in rules}
    assert "codewatch.python.web.sql-injection" in ids and "codewatch.js.nosql-injection" in ids
    assert "skipping rule file" in capsys.readouterr().err
    assert not any("&" in str(r) for r in rules), "anchors are expanded before semgrep sees them"


def test_method_restriction_rule_covers_any_views_module(tmp_path):
    semgrep = Semgrep()
    if not semgrep.available():
        pytest.skip("semgrep not installed")
    (tmp_path / "catalog_views.py").write_text(
        "from django.shortcuts import render\n"
        "from django.views.decorators.http import require_safe\n\n\n"
        "@login_not_required\n"
        "def open_view(request):\n"
        "    Room.objects.create(name=request.GET['n'])\n"
        "    return render(request, 'a.html')\n\n\n"
        "@require_safe\n"
        "@login_not_required\n"
        "def safe_view(request):\n"
        "    Room.objects.create(name='x')\n"
        "    return render(request, 'a.html')\n\n\n"
        "def read_only(request):\n"
        "    return render(request, 'a.html', {'rooms': Room.objects.all()})\n\n\n"
        "def form_view(request):\n"
        "    if request.method == 'POST':\n"
        "        Room.objects.get(pk=1).delete()\n"
        "    return render(request, 'a.html')\n\n\n"
        "def submit(request):\n"
        "    name = request.POST.get('name')\n"
        "    return render(request, 'a.html', {'n': name})\n"
    )
    ctx = Context(root=tmp_path, files=["catalog_views.py"], semgrep_config="",
                  custom_rules=catalog.custom_semgrep_rules())
    hits = [f.line for f in semgrep.run(ctx).findings if f.rule.endswith("view-without-method-restriction")]
    assert hits == [5, 28], "only views that change state without a method restriction"
