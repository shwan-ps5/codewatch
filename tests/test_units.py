from pathlib import Path

from core.analyzers.base import Finding
from core.analyzers.coverage import parse_cobertura, parse_lcov, resolve
from core.analyzers.dependencies import declaration_line, manifests
from core.fingerprint import assign_fingerprints
from core.runner import excluded, is_new, new_code_metrics


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
    f = finding(5)
    assert is_new(f, "fp", {"a.py": {5}}, None)
    assert not is_new(f, "fp", {"a.py": {6}}, None)
    assert is_new(f, "fp", {"a.py": {6}}, {"other"})
    assert not is_new(f, "fp", {"a.py": {6}}, {"fp"})
    assert not is_new(f, "fp", {"b.py": {5}}, set())


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
