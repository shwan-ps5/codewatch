from pathlib import Path

from core.analyzers.accessibility import blank_template_syntax
from core.analyzers.base import Finding
from core.analyzers.coverage import parse_cobertura, parse_lcov, resolve
from core.analyzers.dependencies import declaration_line, manifests
from core.collect import excluded, new_code_metrics, parse_diff
from core.fingerprint import assign_fingerprints
from core.runner import is_new


def finding(line, rule="F401", path="a.py"):
    return Finding("ruff", rule, "minor", "code_smell", "msg", path, line)


def test_fingerprint_survives_line_shift():
    before = ["import os", "x = 1"]
    after = ["# header", "", "import os", "x = 1"]
    fp1 = assign_fingerprints([finding(1)], lambda p, n: before[n - 1])
    fp2 = assign_fingerprints([finding(3)], lambda p, n: after[n - 1])
    assert fp1 == fp2


def test_fingerprint_distinguishes_identical_lines_by_occurrence():
    lines = ["pass", "pass"]
    fps = assign_fingerprints([finding(1), finding(2)], lambda p, n: lines[n - 1])
    assert fps[0] != fps[1]


def test_fingerprint_changes_with_rule_or_text():
    read = lambda p, n: "import os"
    assert assign_fingerprints([finding(1)], read) != assign_fingerprints([finding(1, rule="F811")], read)
    assert assign_fingerprints([finding(1)], read) != assign_fingerprints([finding(1)], lambda p, n: "import sys")


def test_excluded_matches_root_and_nested():
    pats = ["**/node_modules/**", "**/*.min.js"]
    assert excluded("node_modules/x/y.js", pats)
    assert excluded("web/node_modules/y.js", pats)
    assert excluded("app.min.js", pats)
    assert not excluded("src/app.js", pats)


def test_is_new_on_changed_line_or_unseen_in_changed_file():
    i = {"path": "a.py", "line": 5, "fingerprint": "fp"}
    assert is_new(i, {"a.py": {5}}, None)
    assert not is_new(i, {"a.py": {6}}, None)
    assert is_new(i, {"a.py": {6}}, {"other"})
    assert not is_new(i, {"a.py": {6}}, {"fp"})
    assert not is_new(i, {"b.py": {5}}, set())


def test_parse_diff():
    diff = "+++ b/a.py\n@@ -1,0 +2,2 @@\n+x\n+y\n+++ /dev/null\n@@ -3 +0,0 @@\n+++ b/c.py\n@@ -4 +4 @@\n"
    assert parse_diff(diff) == {"a.py": {2, 3}, "c.py": {4}}


def test_blank_template_syntax_keeps_positions():
    src = '{% load x %}<img alt="{{ caption }}">\n{% if a %}<p>{# note #}</p>{% endif %}'
    out = blank_template_syntax(src)
    assert len(out) == len(src) and out.count("\n") == 1
    assert "{%" not in out and 'alt="xxxcaptionxxx"' in out


def test_new_code_metrics():
    m = new_code_metrics(
        {"a.py": {1, 2, 3, 4}},
        covered={"a.py": {1}},
        coverable={"a.py": {1, 2}},
        duplicated={"a.py": {4}},
    )
    assert m == {"new_lines": 4, "new_lines_to_cover": 2, "new_coverage": 50.0, "new_duplicated_lines_percent": 25.0}
    assert "new_duplicated_lines_percent" not in new_code_metrics({"a.py": {1}}, {}, {}, None)


def test_parse_cobertura(tmp_path):
    report = tmp_path / "coverage.xml"
    report.write_text(
        '<coverage><sources><source>/repo/src</source></sources><packages><package><classes>'
        '<class filename="pkg/m.py"><lines><line number="1" hits="1"/><line number="2" hits="0"/></lines></class>'
        "</classes></package></packages></coverage>"
    )
    [(candidates, hits)] = list(parse_cobertura(report))
    assert hits == {1: 1, 2: 0}
    assert resolve(candidates[0], Path("/repo")) == "src/pkg/m.py"


def test_parse_lcov(tmp_path):
    report = tmp_path / "lcov.info"
    report.write_text("SF:src/a.js\nDA:1,3\nDA:2,0\nend_of_record\n")
    assert list(parse_lcov(report)) == [(["src/a.js"], {1: 3, 2: 0})]


def test_declaration_line_normalizes_names():
    pyproject = 'dependencies = [\n    "Django>=5.1",\n    "python_dotenv>=1.0",\n]\n'
    assert declaration_line(pyproject, "django") == 2
    assert declaration_line(pyproject, "python-dotenv") == 3
    assert declaration_line(pyproject, "twisted") is None


def test_manifests_requires_dependencies(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.ruff]\nline-length = 100\n')
    (tmp_path / "requirements-dev.txt").write_text("pytest\n")
    assert manifests(["pyproject.toml", "requirements-dev.txt"], tmp_path) == ["requirements-dev.txt"]


def test_bound_text_is_not_empty():
    out = blank_template_syntax('<h2 x-text="team"></h2><p v-html="x">\n</p><h3></h3>')
    assert out == '<h2 x-text="team">x</h2><p v-html="x">x\n</p><h3></h3>'


def test_rule_family_prefixes():
    from core.analyzers.base import by_prefix
    from core.analyzers.python_tools import RUFF_RULES

    default = ("minor", "code_smell")
    assert by_prefix("S602", RUFF_RULES, default) == ("major", "security_hotspot")
    assert by_prefix("SIM108", RUFF_RULES, default) == default, "S must not swallow SIM"
    assert by_prefix("BLE001", RUFF_RULES, default) == ("minor", "bug"), "B must not swallow BLE"
    assert by_prefix("E902", RUFF_RULES, default) == ("blocker", "bug")


def test_framework_required_arguments():
    from core.analyzers.python_tools import framework_required

    assert framework_required("ARG001", "Unused function argument: `request`", "app/views.py")
    assert framework_required("ARG001", "Unused function argument: `x`", "tests/test_views.py")
    assert not framework_required("ARG001", "Unused function argument: `x`", "app/views.py")
    assert not framework_required("F401", "`os` imported but unused", "tests/test_views.py")


def test_test_file_detection():
    from core.analyzers.base import is_test_file

    for path in ("tests/test_a.py", "app/tests/x.py", "test_a.py", "a_test.py", "src/a.spec.ts", "b.test.jsx"):
        assert is_test_file(path), path
    for path in ("app/testing.py", "contest.py", "src/latest.js"):
        assert not is_test_file(path), path


def test_match_patterns_are_anchored():
    from core.analyzers.codewatch_checks import anchored

    assert anchored("a+b", "match") == "^(?:a+b)"
    assert anchored("a+b", "fullmatch") == "^(?:a+b)$"
    assert anchored("a+b", "search") == "a+b"


def test_known_type_checker_false_positives():
    from core.analyzers.extra import known_false_positive

    assert known_false_positive('Argument of type "Literal[3]" cannot be assigned to parameter "default" of type '
                                '"type[NOT_PROVIDED]" in function "__init__"')
    assert known_false_positive('"__getitem__" method not defined on type "CharField"')
    assert not known_false_positive('"splitlines" is not a known attribute of "None"')


def test_new_projects_get_default_exclusions():
    from core.collect import DEFAULT_EXCLUSIONS, ScanConfig

    assert ScanConfig().exclusions == DEFAULT_EXCLUSIONS
    assert ScanConfig().exclusions is not DEFAULT_EXCLUSIONS


def test_distinct_template_values_stay_distinct():
    out = blank_template_syntax("<h2>{{ std.top25.name }}</h2><h2>{{ std.owasp.name }}</h2>")
    assert out.count("<h2>") == 2 and "top25" in out and "owasp" in out


def test_client_refuses_non_http_server_urls():
    import pytest

    from core.client import ClientError, request

    with pytest.raises(ClientError):
        request("file:///etc/passwd", "t")


def test_hashes_are_not_secrets():
    import re

    from core.analyzers.extra import NOT_SECRET_LINES

    pattern = re.compile(NOT_SECRET_LINES)
    for line in ('"commit": "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"', "sha256 = 'ab12'", '"integrity": "sha512-x"'):
        assert pattern.search(line), line
    for line in ('"password": "hunter2hunter2"', "API_KEY = 'abc'", "token: xyz"):
        assert not pattern.search(line), line
