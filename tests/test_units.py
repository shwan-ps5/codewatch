import re
from datetime import UTC, datetime
from pathlib import Path

from core.analyzers.accessibility import blank_template_syntax
from core.analyzers.base import Context, Finding, Result
from core.analyzers.coverage import Coverage, add_unreported, parse_cobertura, parse_lcov, resolve, statement_lines
from core.analyzers.dependencies import declaration_line, manifests
from core.analyzers.multi_tools import added_names, mentioning
from core.analyzers.summaries import (
    NAME_BATCH,
    added,
    argument_sanitizers,
    assigned_calls,
    js_functions,
    keyword_summarised,
    parse_passes,
    pass_rules,
    python_signatures,
    returner_rules,
    split_keyword,
    summary_rules,
    via_sinks,
)
from core.collect import (
    ScanConfig,
    choose_reference,
    excluded,
    in_library_folder,
    library_folders,
    minified,
    new_code_metrics,
    parse_diff,
    parse_period,
    vendored,
)
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


def test_default_exclusions_skip_installed_packages():
    from core.collect import DEFAULT_EXCLUSIONS

    assert excluded("venv/lib/python3.12/site-packages/django/db/models/query.py", DEFAULT_EXCLUSIONS)
    assert not excluded("game_sessions/views.py", DEFAULT_EXCLUSIONS)


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


def test_coverage_ignores_test_files(tmp_path):
    (tmp_path / "tests").mkdir()
    for name in ("app.py", "tests/test_app.py", "tests/conftest.py"):
        (tmp_path / name).write_text("x = 1\ny = 2\n")
    report = tmp_path / "coverage.xml"
    report.write_text(
        "<coverage><packages><package><classes>"
        '<class filename="app.py"><lines><line number="1" hits="1"/><line number="2" hits="0"/></lines></class>'
        '<class filename="tests/test_app.py"><lines><line number="1" hits="1"/><line number="2" hits="1"/></lines></class>'
        "</classes></package></packages></coverage>"
    )
    ctx = Context(root=tmp_path, files=["app.py", "tests/test_app.py", "tests/conftest.py"], coverage_report=report)
    result = Coverage().run(ctx)
    assert set(result.coverable_lines) == {"app.py"}, "reported or not, test files never count"
    assert result.metrics["coverage"] == 50.0


def test_statement_lines_match_coverage_py():
    source = (
        '"""Module docstring."""\n'
        "import os\n\n\n"
        "@decorator\n"
        "@other\n"
        "def f():\n"
        '    """Docstring."""\n'
        "    try:\n"
        "        return os.sep\n"
        "    except OSError:\n"
        "        return None\n"
    )
    assert statement_lines(source) == {2, 5, 6, 7, 9, 10, 11, 12}


def test_python_files_missing_from_the_report_count_as_uncovered(tmp_path):
    (tmp_path / "unused.py").write_text("import os\nx = 1\n")
    result = Result()
    result.coverable_lines["app.py"] = {1}
    add_unreported(result, tmp_path, ["app.py", "unused.py", "missing.py"])
    assert result.coverable_lines == {"app.py": {1}, "unused.py": {1, 2}}
    assert result.covered_lines["unused.py"] == set()


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

    for path in ("tests/test_a.py", "app/tests/x.py", "test_a.py", "a_test.py", "src/a.spec.ts", "b.test.jsx",
                 "e2e/src/utils.ts", "e2e/src/specs/server/api/oauth.e2e-spec.ts", "src/app-spec.js"):
        assert is_test_file(path), path
    for path in ("app/testing.py", "contest.py", "src/latest.js", "src/respect.ts", "src/inspect/x.ts"):
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


class LinearRepo:
    """Commits c0..cN on one line of history; tags map names to commits."""

    def __init__(self, n, tags=None):
        self.commits = [f"c{i}" for i in range(n)]
        self.tags = tags or {}

    def has_commit(self, commit):
        return commit in self.commits

    def is_ancestor(self, a, b):
        return self.commits.index(a) <= self.commits.index(b)

    def resolve_commit(self, ref):
        return self.tags.get(ref) or (ref if ref in self.commits else None)


NOW = datetime(2026, 10, 29, tzinfo=UTC)


def main_cfg(period, analysed):
    """Main analyses of the given (commit, day-of-October) pairs, newest first as the server sends them."""
    return ScanConfig(main_branch="main", new_code_period=period, main_analyses=[
        {"commit": c, "reference_commit": "", "started_at": datetime(2026, 10, day, tzinfo=UTC).isoformat()}
        for c, day in sorted(analysed, key=lambda x: -x[1])
    ])


def test_parse_period():
    assert parse_period("") == ("previous", None)
    assert parse_period(" 30d ") == ("days", 30)
    assert parse_period("v1.4") == ("ref", "v1.4")
    assert parse_period("--output=/tmp/x") == ("previous", None)


def test_blank_period_compares_with_previous_analysis():
    cfg = main_cfg("", [("c1", 1), ("c5", 20), ("c8", 28)])
    assert choose_reference("main", "c9", cfg, LinearRepo(10), NOW) == ("c8", "c8")


def test_days_period_uses_newest_analysis_older_than_cutoff():
    # Many small commits since c5 can't each reset the window.
    cfg = main_cfg("7d", [("c1", 1), ("c5", 20), ("c7", 25), ("c8", 28)])
    assert choose_reference("main", "c9", cfg, LinearRepo(10), NOW) == ("c5", "c5")


def test_days_period_on_a_young_project_uses_the_first_analysis():
    cfg = main_cfg("30d", [("c5", 20), ("c8", 28)])
    assert choose_reference("main", "c9", cfg, LinearRepo(10), NOW) == ("c5", "c5")


def test_ref_period_uses_the_tag_and_the_analysis_before_it():
    cfg = main_cfg("v1", [("c1", 1), ("c5", 20), ("c8", 28)])
    assert choose_reference("main", "c9", cfg, LinearRepo(10, {"v1": "c3"}), NOW) == ("c3", "c1")


def test_unusable_ref_period_falls_back_to_previous_analysis():
    cfg = main_cfg("v9", [("c1", 1), ("c8", 28)])
    assert choose_reference("main", "c9", cfg, LinearRepo(10), NOW) == ("c8", "c8")
    ahead = LinearRepo(10, {"v9": "c9"})
    assert choose_reference("main", "c6", main_cfg("v9", [("c1", 1), ("c5", 20)]), ahead, NOW) == ("c5", "c5")


def test_a_tool_timeout_kills_its_children(tmp_path):
    import subprocess
    import sys
    import time

    import pytest

    from core.analyzers.base import run_killing_group

    if not sys.platform.startswith("linux"):
        pytest.skip("checks /proc")

    pid_file = tmp_path / "child.pid"
    script = f"sleep 60 & echo $! > {pid_file}; wait"
    with pytest.raises(subprocess.TimeoutExpired):
        run_killing_group(["sh", "-c", script], cwd=tmp_path, timeout=1)
    child = int(pid_file.read_text())
    time.sleep(0.2)
    assert not Path(f"/proc/{child}").exists() or "Z" in Path(f"/proc/{child}/stat").read_text().split()[2]


def test_summarised_calls_share_one_sink_per_call_shape():
    # A sink per summarised function, or per parameter name passed by keyword, made Semgrep match thousands of
    # patterns in a large project and time out.
    found = {(f"helper_{i}", 0, f"value_{i % 50}", False, "app.py") for i in range(NAME_BATCH + 1)}
    sinks = via_sinks(found, js=False)
    positional = [s for s in sinks if "pattern" in s["patterns"][0]]
    keyword = [s for s in sinks if "pattern-either" in s["patterns"][0]]
    assert {s["patterns"][0]["pattern"] for s in positional} == {"$VIA_FUNC($ARG, ...)", "$MODULE.$VIA_FUNC($ARG, ...)"}
    assert len(positional) == 4  # each shape's names split into two regexes
    assert len(keyword) == 2  # one callee kind, function names in two regexes, all 50 keywords in one
    regexes = [s["patterns"][1]["metavariable-regex"]["regex"] for s in positional]
    for func, *_ in found:
        assert sum(bool(re.match(r, func)) for r in regexes) == 2
    assert not any(re.match(r, "helper_") for r in regexes)


def test_keyword_via_sinks_keep_only_summarised_pairs():
    found = {("save", 0, "path", False, "a.py")}
    message = "Path from request {keyword save path} [via save()]"
    assert split_keyword(message) == ("Path from request [via save()]", "save", "path")
    assert keyword_summarised("save", "path", found)
    assert not keyword_summarised("save", "mode", found)
    assert keyword_summarised("save", "$VIA_KW", found)  # passed by position
    assert keyword_summarised("$VIA_FUNC", "$VIA_KW", found)  # a sink of the rule itself
    assert split_keyword("Plain message") == ("Plain message", "", "")


def test_deeper_passes_rescan_only_files_naming_new_functions():
    before = {"r": {("helper", 0, "x", False, "a.py")}}
    after = {"r": {("helper", 0, "x", False, "a.py"), ("wrapper", 0, "y", False, "b.py")}, "s": {("other", "c.py")}}
    assert added_names(before, after) == {"wrapper", "other"}


def test_mentioning_matches_whole_names(tmp_path):
    (tmp_path / "calls.py").write_text("wrapper(x)\n")
    (tmp_path / "prefix.py").write_text("wrapper_two(x)\n")
    ctx = Context(root=tmp_path, files=[])
    assert mentioning(ctx, ["calls.py", "prefix.py"], {"wrapper"}) == ["calls.py"]


def test_minified_bundles_are_recognised_by_content(tmp_path):
    """litellm commits Next.js chunks (one 100 KB line each): ReDoS and Semgrep spent minutes per chunk. CTFd commits
    Vite's per-page chunks, a few KB on one line."""
    (tmp_path / "chunk-6a03.js").write_text("(self.webpackChunk=[]).push([[1],{1:function(e){" + "a," * 20_000 + "}}])")
    (tmp_path / "page-BsvbO10u.js").write_text("import{a as e}from'./main.js';" + "e(1);" * 600 + "\n")
    (tmp_path / "app.js").write_text("const a = 1\n" * 5_000)
    (tmp_path / "small.js").write_text("const a = 1;\n" * 300)
    (tmp_path / "tiny.js").write_text("export const routes = ['/a', '/b'];" * 20)
    (tmp_path / "data.py").write_text("x" * 50_000)
    assert [p.name for p in sorted(tmp_path.iterdir()) if minified(p)] == ["chunk-6a03.js", "page-BsvbO10u.js"]



def test_vendored_libraries_are_recognised_by_their_banner(tmp_path):
    """Grappelli ships jQuery and jQuery UI in its static folder: codewatch's ReDoS check spent a minute a side on them."""
    (tmp_path / "jquery.js").write_text("/*!\n * jQuery JavaScript Library v1.11.3\n */\n(function(){})()\n")
    (tmp_path / "bootstrap.css").write_text("/*!\n * Bootstrap v4.3.1 (https://getbootstrap.com/)\n */\nbody{}\n")
    (tmp_path / "materialize.js").write_text("/*!\n * Materialize v0.97.5 (http://materializecss.com)\n */\n")
    (tmp_path / "app.js").write_text("/*\n * Licensed to the Apache Software Foundation (ASF) 2.0\n */\nlet a = 1\n")
    (tmp_path / "util.js").write_text("// helpers for v1.2 of the API\nexport const x = 1\n")
    (tmp_path / "setup.py").write_text("/*! Thing v1.0 */")
    assert sorted(p.name for p in tmp_path.iterdir() if vendored(p)) == ["bootstrap.css", "jquery.js", "materialize.js"]



def test_licensed_folders_inside_asset_folders_are_libraries():
    """Grappelli's TinyMCE has no banner but ships license.txt; monorepo packages have licences outside asset folders."""
    files = ["grappelli/static/grappelli/tinymce/jscripts/tiny_mce/license.txt",
             "grappelli/static/grappelli/tinymce/jscripts/tiny_mce/plugins/paste/editor_plugin.js",
             "grappelli/static/grappelli/js/grappelli.js",
             "packages/utils/LICENSE.md", "packages/utils/index.js",
             "static/LICENSE", "static/app.js"]
    folders = library_folders(files)
    assert folders == {"grappelli/static/grappelli/tinymce/jscripts/tiny_mce/"}
    assert [f for f in files if in_library_folder(f, folders)] == [files[1]]


def test_semgrep_timeouts_are_reported_not_lost(monkeypatch, tmp_path):
    import json

    from core import collect
    from core.analyzers.multi_tools import Semgrep

    semgrep = Semgrep()
    errors = [{"type": "Timeout", "path": "app/big.py", "rule_id": "x"}, {"type": "Syntax", "path": "app/ok.py"}]
    monkeypatch.setattr(semgrep, "exec", lambda *a, **k: json.dumps({"results": [], "errors": errors}))
    semgrep.scan(Context(root=tmp_path, files=[]), [], ["app/big.py"])
    assert semgrep.timeouts == {"app/big.py"}

    class Noted:
        name = "noted"

        def run(self, ctx):
            return Result(notes=["Gave up on app/big.py."])

    monkeypatch.setattr(collect, "ANALYZERS", [Noted()])
    monkeypatch.setattr(collect, "analyzer_skip_reason", lambda *a: None)
    _, tools = collect.run_analyzers(None, Context(root=tmp_path, files=[]), lambda m: None)
    assert tools["noted"]["detail"] == "Gave up on app/big.py."


def test_pass_rules_only_ask_about_functions_whose_result_is_assigned():
    source = ("x = build(a)\ny = await self.fetch(b)\nz = cls.make (c)\nlog(d)\nif a == check(e):\n    pass\n"
              "return resolve(f)\n")
    assert assigned_calls([source]) >= {"build", "fetch", "make", "resolve"}
    assert "log" not in assigned_calls([source])
    rule = {"id": "r", "mode": "taint", "languages": ["python"], "message": "m", "severity": "ERROR",
            "pattern-sources": [{"pattern": "request.args"}], "pattern-sinks": [{"pattern": "os.system(...)"}]}
    assert pass_rules([rule], set()) == []
    [variant] = pass_rules([rule], {"build"})
    [sink] = variant["pattern-sinks"]
    assert {"metavariable-regex": {"metavariable": "$FUNC", "regex": "^(build)$"}} in sink["patterns"]
    # Rules share one variant, whose results answer for each of them, with only the sanitizers they all have.
    same = {**rule, "id": "s", "pattern-sinks": [{"pattern": "eval(...)"}], "pattern-sanitizers": [{"pattern": "f(...)"}]}
    other = {**rule, "id": "o", "pattern-sanitizers": [{"pattern": "int(...)"}, {"pattern": "f(...)"}]}
    variants = pass_rules([same, other], {"build"})
    assert [(v["message"], v["pattern-sanitizers"]) for v in variants] == [
        ("$FUNC|$OWNER|$PARAM|s,o", [{"pattern": "f(...)"}])]
    # Different propagators still make different variants.
    spread = {**rule, "id": "p", "pattern-propagators": [{"pattern": "$A.extend($B)", "from": "$B", "to": "$A"}]}
    assert [v["message"] for v in pass_rules([rule, spread], {"build"})] == ["$FUNC|$OWNER|$PARAM|r",
                                                                              "$FUNC|$OWNER|$PARAM|p"]
    # A nested def returning its outer function's parameter says nothing of which of its own it passes.
    assert parse_passes([("r.passes", "a.py", 1, "build|build|x|r,s"), ("o.passes", "a.py", 2, "$FUNC|$OWNER|$PARAM|o"),
                         ("o.passes", "a.py", 3, "inner|outer|y|o")]) == {
        "r": {("build", "x", "a.py")}, "s": {("build", "x", "a.py")}, "o": {("inner", "*", "a.py")}}


def test_only_arguments_no_def_of_the_name_hands_back_are_cleaned():
    source = ("def one(a, b, *, c=None):\n    return a\n\n"
              "class K:\n    def one(self, a, b):\n        return a\n\n"
              "    @staticmethod\n    def two(x, y):\n        return x\n\n"
              "def three(a, *args):\n    return a\n\n"
              "def four(p, **kwargs):\n    return p\n")
    signatures = python_signatures([source])
    assert signatures["one"] == [(("a", "b"), ("c",), 0), (("a", "b"), (), 0)]
    assert signatures["two"] == [(("x", "y"), (), 0)]
    sanitizers = argument_sanitizers(signatures, {"one": {"a"}, "two": {"x"}, "three": {"a"}, "four": {"p"}})
    regexes = {(s["patterns"][0]["pattern-either"][0]["pattern"],
                tuple(str(m.get("metavariable-regex", m.get("metavariable-comparison"))) for m in s["patterns"][1:-1]))
               for s in sanitizers}
    # Second positions: one's b (both defs), two's y; not three's (*args) or four's (none). Keywords: b and y, not
    # c (one def lacks it) or anything for four (**kwargs). An argument with a call in it is never cleaned: it may
    # hold a sink.
    plain = str({"metavariable": "$PT_ARG", "regex": "^[^()]+$"})
    assert regexes == {
        ("$PT_FUNC($PT_0, $PT_ARG, ...)", (str({"metavariable": "$PT_FUNC", "regex": "^(one|two)$"}), plain)),
        ("$PT_FUNC(..., $PT_KW=$PT_ARG, ...)", (
            str({"metavariable": "$PT_FUNC", "regex": "^(one|two)$"}), str({"metavariable": "$PT_KW", "regex": "^(b|y)$"}),
            str({"comparison": (
            '(re.match("^(one)$", str($PT_FUNC)) and re.match("^(b)$", str($PT_KW))) or '
            '(re.match("^(two)$", str($PT_FUNC)) and re.match("^(y)$", str($PT_KW)))')}), plain))}
    # A function that hands nothing back is left to the result sanitizer, except in pass_rules.
    assert argument_sanitizers(signatures, {}) == []
    assert len(argument_sanitizers(signatures, {}, mixed_only=False)) == 3
    # A function that can return an enclosing one's parameter keeps every argument.
    assert argument_sanitizers(signatures, {"one": {"*"}, "two": {"*"}, "three": {"*"}, "four": {"*"}}) == []


def test_deeper_passes_use_only_what_the_last_pass_added():
    rule = {"id": "r", "mode": "taint", "languages": ["python"], "message": "m", "severity": "ERROR",
            "pattern-sources": [{"pattern": "request.args"}], "pattern-sinks": [{"pattern": "eval(...)"}]}
    other = {**rule, "id": "o"}
    assert added({"r": {"a"}}, {"r": {"a", "b"}, "o": {"c"}}) == {"r": {"b"}, "o": {"c"}}
    assert added({"r": {"a"}}, {"r": {"a"}}) == {}
    full, = summary_rules([rule, other], {"r": {("f", 0, "x", False, "a.py")}})
    deeper, = summary_rules([rule, other], {"r": {("f", 0, "x", False, "a.py")}}, base=False)
    assert {"pattern": "eval(...)"} in full["pattern-sinks"]
    assert {"pattern": "eval(...)"} not in deeper["pattern-sinks"] and deeper["pattern-sinks"]
    deeper, = returner_rules([rule, other], {"r": {("get_name", "a.py")}}, base=False)
    assert deeper["id"].startswith("r") and {"pattern": "request.args"} not in deeper["pattern-sources"]
    assert len(returner_rules([rule, other], {"r": {("get_name", "a.py")}})) == 2


def test_only_javascript_functions_the_pass_rule_can_see_into_can_be_clean():
    text = (
        "function plain(a) { return a; }\n"
        "export async function exported(a) { return a; }\n"
        "const arrow = (a: string): string => a;\n"
        "const block = async (a) => {\n  return a;\n};\n"
        "const handlers = { onUpload: (a) => a, onSave: function (a) { return a; } };\n"
        "class Files {\n"
        "  async method(a: File): Promise<File> {\n    return a;\n  }\n"
        "  field = (a) => a;\n"
        "  constructor(a) {\n    super(a);\n  }\n"
        "}\n"
        "let reassigned = (a) => a;\nreassigned = (a) => a.x;\n"
        "const typed: Handler = (a) => a;\n"
        "if (ready) {\n  run();\n}\n")
    assert js_functions([text]) == {"plain", "exported", "arrow", "block", "method"}
