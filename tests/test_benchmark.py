import json
import subprocess

import pytest

from core import benchmark

PARENTS = {"79": [74], "80": [79]}


@pytest.fixture
def cwes(monkeypatch):
    rules = {"xss": {"cwe": [79]}, "sqli": {"cwe": [89]}}
    monkeypatch.setattr(benchmark.catalog, "lookup", lambda tool, rule: rules.get(rule))


def issue(path, rule, kind="vulnerability", line=1):
    return {"path": path, "rule": rule, "tool": "codewatch", "type": kind, "line": line}


def test_related_follows_the_cwe_hierarchy_both_ways():
    assert benchmark.related(79, 79, PARENTS)
    assert benchmark.related(80, 74, PARENTS) and benchmark.related(74, 80, PARENTS)
    assert not benchmark.related(79, 89, PARENTS)


def test_rates_handle_empty_classes():
    assert benchmark.rates({"tp": 3, "fn": 1, "fp": 1, "tn": 3}) == {
        "tp": 3, "fn": 1, "fp": 1, "tn": 3, "tpr": 0.75, "fpr": 0.25, "score": 0.5}
    assert benchmark.rates({"tp": 0, "fn": 0, "fp": 0, "tn": 0})["score"] == 0.0


def test_owasp_cases_skip_comments(tmp_path):
    (tmp_path / "expected.csv").write_text("# test name, category, real, cwe\nT001, xss, true, 79\nT002, xss, false, 79\n")
    cases = benchmark.owasp_cases(tmp_path, {"expected": "expected.csv"})
    assert cases == [{"test": "T001", "category": "xss", "real": True, "cwe": 79},
                     {"test": "T002", "category": "xss", "real": False, "cwe": 79}]


def test_owasp_scoring_counts_each_outcome(cwes):
    cases = [{"test": t, "category": "xss", "real": real, "cwe": 79}
             for t, real in [("hit", True), ("miss", True), ("alarm", False), ("quiet", False)]]
    issues = [issue("tc/hit.py", "xss"), issue("tc/alarm.py", "xss"), issue("tc/quiet.py", "sqli"),
              issue("tc/miss.py", "xss", kind="security_hotspot")]
    by_file = benchmark.issues_by_file(issues, benchmark.MODES["verdict"])
    result = benchmark.score_owasp_mode(cases, {"test_dir": "tc"}, by_file, PARENTS)
    assert {k: result["categories"]["xss"][k] for k in ("tp", "fn", "fp", "tn")} == {"tp": 1, "fn": 1, "fp": 1, "tn": 1}
    assert [m["test"] for m in result["mistakes"]] == ["miss", "alarm"]
    review = benchmark.score_owasp_mode(cases, {"test_dir": "tc"},
                                        benchmark.issues_by_file(issues, benchmark.MODES["review"]), PARENTS)
    assert review["categories"]["xss"]["tp"] == 2


def git_repo(path, files):
    for name, text in files.items():
        (path / name).parent.mkdir(parents=True, exist_ok=True)
        (path / name).write_text(text)
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "add", "."], cwd=path, check=True)


def test_marked_lines_ignore_code_fixes(tmp_path):
    git_repo(tmp_path, {
        "routes/login.ts": "a\nquery(x) // vuln-code-snippet vuln-line loginAdmin loginJim\n",
        "codefixes/login_1.ts": "query(x) // vuln-code-snippet vuln-line loginAdmin\n",
    })
    assert benchmark.marked_lines(tmp_path) == {"loginAdmin": [("routes/login.ts", 2)],
                                                "loginJim": [("routes/login.ts", 2)]}


def test_snippet_scoring_accepts_nearby_findings():
    marks = {"near": [("a.ts", 10)], "far": [("a.ts", 50)]}
    by_file = {"a.ts": [issue("a.ts", "xss", line=10 + benchmark.NEARBY_LINES)]}
    result = benchmark.score_snippets_mode(marks, {"near": "XSS", "far": "XSS"}, by_file)
    assert result["overall"] == {"found": 1, "total": 2, "recall": 0.5}
    assert result["categories"] == {"XSS": {"found": 1, "total": 2}}


def test_run_scores_and_writes_results(tmp_path, monkeypatch, cwes):
    suite = {"name": "demo", "kind": "owasp-benchmark", "commit": "abc1234567890", "license": "MIT",
             "about": "Demo suite.", "expected": "expected.csv", "test_dir": "tc"}
    (tmp_path / "suites.json").write_text(json.dumps({"suites": [suite, {**suite, "name": "other"}]}))
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "expected.csv").write_text("T1, xss, true, 79\nT2, xss, false, 79\n")
    monkeypatch.setattr(benchmark, "ROOT", tmp_path)
    monkeypatch.setattr(benchmark, "CACHE", tmp_path / "cache")
    (tmp_path / "cache").mkdir()
    monkeypatch.setattr(benchmark, "fetch", lambda s: checkout)
    monkeypatch.setattr(benchmark, "scan", lambda root, log, paths=(): [issue("tc/T1.py", "xss")])
    monkeypatch.setattr(benchmark.catalog, "load", lambda: ({}, {"cwe_parents": PARENTS}))

    out = benchmark.run(["demo"], log=lambda *a: None)

    assert list(out) == ["demo"]
    assert out["demo"]["overall"]["verdict"] == {"tpr": 1.0, "fpr": 0.0, "score": 1.0}
    report = (tmp_path / "results" / "demo.md").read_text()
    assert "**Detection 100%, false alarms 0%, score +100%**" in report and "## Review mode" in report
    assert json.loads((tmp_path / "results" / "demo.json").read_text())["commit"] == suite["commit"]


def test_render_snippets_lists_missed_challenges():
    result = benchmark.score_snippets_mode({"c1": [("a.ts", 1)]}, {"c1": "XSS"}, {})
    text = "\n".join(benchmark.render_snippets("review", result))
    assert "0 of 1 vulnerable challenges flagged" in text and "| c1 | XSS | missed |" in text


FIX_DIFF = """diff --git a/app/views.py b/app/views.py
--- a/app/views.py
+++ b/app/views.py
@@ -10,2 +10,3 @@ def show():
-    q = "SELECT * FROM t WHERE id = " + request.args["id"]
-    db.execute(q)
+    q = "SELECT * FROM t WHERE id = %s"
+    db.execute(q, (request.args["id"],))
+    log(q)
@@ -40,0 +42 @@ def other():
+    check()
diff --git a/tests/test_views.py b/tests/test_views.py
--- a/tests/test_views.py
+++ b/tests/test_views.py
@@ -1 +1 @@
-old
+new
diff --git a/web/new.ts b/web/new.ts
--- /dev/null
+++ b/web/new.ts
@@ -0,0 +1,2 @@
+a
+b
"""


def test_fix_spots_cover_changed_source_lines_and_skip_tests():
    spots = benchmark.fix_spots(FIX_DIFF, (".py",))
    assert spots == {"before": {"app/views.py": [(10, 11), (40, 41)]}, "after": {"app/views.py": [(10, 12), (42, 42)]}}
    assert benchmark.fix_spots(FIX_DIFF, (".ts",))["after"] == {"web/new.ts": [(1, 2)]}


def pair_issue(rule, line, code, kind="vulnerability"):
    return {**issue("app/views.py", rule, kind=kind, line=line), "code": code}


SPOTS = {"before": {"app/views.py": [(10, 11)]}, "after": {"app/views.py": [(10, 12)]}}
CASE = {"id": "GHSA-1", "repo": "r", "cwe": [89]}


def test_pair_detected_when_the_fix_silences_the_finding(cwes):
    sides = {"before": [pair_issue("sqli", 11, "db.execute(q)"), pair_issue("xss", 11, "db.execute(q)")],
             "after": [pair_issue("sqli", 80, "unrelated()")]}
    r = benchmark.score_pair(CASE, SPOTS, sides, benchmark.MODES["verdict"], PARENTS)
    assert r["detected"] and not r["still_flagged"] and r["by"] == ["codewatch:sqli@11"]


def test_pair_still_flagged_when_the_finding_survives_the_fix(cwes):
    far = pair_issue("sqli", 70, "cursor.execute(sql)")
    sides = {"before": [far], "after": [{**far, "line": 71}, pair_issue("sqli", 30, "x()", kind="security_hotspot")]}
    verdict = benchmark.score_pair(CASE, SPOTS, sides, benchmark.MODES["verdict"], PARENTS)
    assert not verdict["detected"] and verdict["still_flagged"] is False
    near = {"before": [pair_issue("sqli", 10, "q = a + b")], "after": [pair_issue("sqli", 10, "q = a + b")]}
    r = benchmark.score_pair(CASE, SPOTS, near, benchmark.MODES["verdict"], PARENTS)
    assert r["detected"] and r["still_by"] == ["codewatch:sqli@10"]


def test_pair_mode_counts_detection_and_fixed_code_alarms(cwes):
    scanned = {"GHSA-1": (SPOTS, {"before": [pair_issue("sqli", 10, "a")], "after": [pair_issue("sqli", 12, "b")]}),
               "GHSA-2": (SPOTS, {"before": [], "after": []})}
    result = benchmark.score_pairs_mode([CASE, {**CASE, "id": "GHSA-2"}], scanned, benchmark.MODES["verdict"], PARENTS)
    assert {k: result["overall"][k] for k in ("tp", "fn", "fp", "tn")} == {"tp": 1, "fn": 1, "fp": 1, "tn": 1}
    text = "\n".join(benchmark.render_pairs("verdict", result))
    assert "| GHSA-2 | 89 | missed | quiet |" in text


def test_run_skips_blind_suites_unless_named(tmp_path, monkeypatch):
    suites = [{"name": "open", "kind": "x"}, {"name": "blind", "kind": "x", "blind": True}]
    (tmp_path / "suites.json").write_text(json.dumps({"suites": suites}))
    monkeypatch.setattr(benchmark, "ROOT", tmp_path)
    ran = []
    monkeypatch.setattr(benchmark, "run_suite", lambda suite, log: ran.append(suite["name"]) or {})
    monkeypatch.setattr(benchmark, "write", lambda suite, result: None)
    monkeypatch.setattr(benchmark, "MODES", {})
    benchmark.run(log=lambda *a: None)
    benchmark.run(["blind"], log=lambda *a: None)
    assert ran == ["open", "blind"]


def test_a_python_web_apps_templates_and_scripts_count_as_its_source():
    diff = ("diff --git a/app/templates/item.html b/app/templates/item.html\n"
            "--- a/app/templates/item.html\n+++ b/app/templates/item.html\n"
            "@@ -3 +3 @@\n-<p>{{ item.caption|safe }}</p>\n+<p>{{ item.caption }}</p>\n"
            "diff --git a/app/static/js/list.js b/app/static/js/list.js\n"
            "--- a/app/static/js/list.js\n+++ b/app/static/js/list.js\n"
            "@@ -7 +7 @@\n-el.innerHTML = v;\n+el.textContent = v;\n")
    web = benchmark.SOURCE_EXTENSIONS["python-web"]
    assert benchmark.fix_spots(diff, web)["after"] == {"app/templates/item.html": [(3, 3)], "app/static/js/list.js": [(7, 7)]}
    assert benchmark.fix_spots(diff, benchmark.SOURCE_EXTENSIONS["python"])["after"] == {}


TEMPLATE_DIFF = (
    "diff --git a/app/templates/error.html b/app/templates/error.html\n"
    "--- a/app/templates/error.html\n+++ b/app/templates/error.html\n"
    "@@ -1 +1 @@\n-<p>{{ error_message|safe }}</p>\n+<p>{{ error_message }}</p>\n"
    "diff --git a/tests/templates/fixture.html b/tests/templates/fixture.html\n"
    "--- a/tests/templates/fixture.html\n+++ b/tests/templates/fixture.html\n"
    "@@ -1 +1 @@\n-a\n+b\n")


def test_changed_templates_are_named_as_views_name_them():
    assert benchmark.changed_templates(TEMPLATE_DIFF) == {"error.html"}


def test_render_spans_find_the_calls_that_name_a_template():
    text = ("def a():\n    return render_template('error.html',\n        error_message=q)\n\n\n"
            "def b(request):\n    return render(request, 'error.html', {'x': 1})\n\n\n"
            "def c():\n    return render_template('other.html', error_message=q)\n\n\n"
            "def d():\n    return flask.render_template(template_name_or_list='error.html', x=1)\n")
    assert benchmark.render_spans(text, {"error.html"}) == [(2, 3), (7, 7), (15, 15)]
    assert benchmark.render_spans("x = 'error.html'\n", {"error.html"}) == []


# A Whoogle-like pair (GHSA-mxvc-fwgx-j778): the fix drops |safe from error.html and changes no Python file. The view
# also renders another template unescaped and echoes a parameter directly: XSS findings in the rendering file that
# the fix has nothing to do with.
ROUTES = (
    "from flask import Flask, render_template, request\n\napp = Flask(__name__)\n\n\n"
    "@app.route('/search')\n"
    "def search():\n"
    "    q = request.args.get('q', '')\n"
    "    return render_template('error.html', error_message='Unable to resolve query: ' + q)\n\n\n"
    "@app.route('/note')\n"
    "def note():\n"
    "    return render_template('other.html', note=request.args['n'])\n\n\n"
    "@app.route('/echo')\n"
    "def echo():\n"
    "    return request.args['x']\n")
TEMPLATE_RULE = "codewatch.python.web.template.xss"


@pytest.fixture(scope="module")
def template_pair(tmp_path_factory):
    from core.analyzers.multi_tools import Semgrep

    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    base = tmp_path_factory.mktemp("template_pair")
    repo = base / "repo"
    (repo / "app" / "templates").mkdir(parents=True)

    def sh(*args):
        return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()

    sh("init", "-q")
    sh("config", "user.email", "t@example.com")
    sh("config", "user.name", "t")
    (repo / "app" / "routes.py").write_text(ROUTES)
    (repo / "app" / "templates" / "error.html").write_text("<p>{{ error_message|safe }}</p>\n")
    (repo / "app" / "templates" / "other.html").write_text("<p>{{ note|safe }}</p>\n")
    sh("add", ".")
    sh("commit", "-q", "-m", "vulnerable")
    (repo / "app" / "templates" / "error.html").write_text("<p>{{ error_message }}</p>\n")
    sh("commit", "-q", "-am", "fix: escape the error message")
    case = {"id": "GHSA-test", "repo": f"file://{repo}", "fix": sh("rev-parse", "HEAD"), "cwe": [79]}
    suite = {"name": "fake-frontend", "language": "python-web"}
    patch = pytest.MonkeyPatch()
    patch.setattr(benchmark, "CACHE", base / "cache")
    try:
        spots, sides = benchmark.scan_pair(suite, case, lambda *a: None)
    finally:
        patch.undo()
    parents = benchmark.catalog.load()[1].get("cwe_parents", {})
    return spots, sides, benchmark.score_pair(case, spots, sides, benchmark.MODES["verdict"], parents)


def test_a_template_only_fix_is_found_at_the_rendering_call_and_quiet_after(template_pair):
    spots, sides, result = template_pair
    assert spots["renders"] == {"before": {"app/routes.py": [(9, 9)]}, "after": {"app/routes.py": [(9, 9)]}}
    assert result["detected"] and result["by"] == [f"codewatch:{TEMPLATE_RULE}@9"]
    assert not result["still_flagged"] and sides["after"] == []


def test_the_template_rule_is_scored_with_the_xss_rules_cwes():
    """codewatch.python.web.template.xss is built at scan time from the XSS rule and has no catalogue entry."""
    assert benchmark.catalog.lookup("codewatch", TEMPLATE_RULE) is None
    assert benchmark.issue_cwes(issue("app/routes.py", TEMPLATE_RULE)) == {79}


def test_an_unrelated_finding_in_the_rendering_file_is_not_counted(template_pair):
    """routes.py also renders other.html unescaped (line 14) and echoes a parameter (line 19): neither concerns the
    changed template, so neither is scored, on either side of the fix. (error.html's own |safe hotspot is in the changed
    file, so it stays, as for any fix.)"""
    _, sides, result = template_pair
    in_routes = {(i["line"], i["rule"]) for side in ("before", "after") for i in sides[side] if i["path"] == "app/routes.py"}
    assert in_routes == {(9, TEMPLATE_RULE)}
    assert result["still_by"] == []


def test_importers_of_a_changed_module_are_scored(tmp_path, cwes):
    """A fix inside a helper module removes the finding at its caller (Dagster GHSA-q93c): files importing a changed
    module are scanned, and their findings count when the fix makes them go away, never as still flagged."""
    git_repo(tmp_path, {
        "pkg/web/server.py": "from core.storage.logs import Manager\n",
        "pkg/core/core/storage/logs.py": "class Manager: ...\n",
        "pkg/web/other.py": "import json\n",
        "pkg/web/tests/test_server.py": "from core.storage.logs import Manager\n",
    })
    assert benchmark.importers(tmp_path, ["pkg"], {"pkg/core/core/storage/logs.py"}) == {"pkg/web/server.py"}
    caller = {**issue("pkg/web/server.py", "sqli", line=5), "code": "FileResponse(location)"}
    gone = benchmark.score_pair(CASE, SPOTS, {"before": [caller], "after": []}, benchmark.MODES["verdict"], PARENTS)
    assert gone["detected"] and not gone["still_flagged"]
    kept = benchmark.score_pair(CASE, SPOTS, {"before": [caller], "after": [caller]}, benchmark.MODES["verdict"], PARENTS)
    assert not kept["detected"] and not kept["still_flagged"]


def test_a_scope_folder_named_like_a_pattern_is_checked_out(tmp_path, monkeypatch):
    # Postiz GHSA-2p7p's scope is a Next.js route folder, `[[...path]]`, which git refuses as a sparse-checkout
    # pattern unless told to skip its checks; the refusal stopped a whole night's suites (PLAN.md step 39).
    def git(*args, cwd):
        subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)

    repo = tmp_path / "repo"
    route = repo / "app" / "[[...path]]"
    route.mkdir(parents=True)
    git("init", "-q", cwd=repo)
    for n in (1, 2):
        (route / "route.ts").write_text(f"export const n = {n};\n")
        git("add", ".", cwd=repo)
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", str(n), cwd=repo)
    fix = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()
    monkeypatch.setattr(benchmark, "CACHE", tmp_path / "cache")

    target, parent = benchmark.fetch_pair({"name": "s"}, {"id": "c", "repo": repo.as_uri(), "fix": fix,
                                                           "scope": ["app/[[...path]]"]})

    assert parent and (target / ".git").is_dir()


def test_a_case_that_fails_to_scan_is_left_out_not_fatal(tmp_path, monkeypatch, cwes):
    cases = [{"id": "ok", "repo": "r", "fix": "f", "cwe": [89]}, {"id": "bad", "repo": "r", "fix": "f", "cwe": [89]}]
    suite = {"name": "pairs", "kind": "cve-pairs", "about": "Demo.", "cases": cases}
    (tmp_path / "suites.json").write_text(json.dumps({"suites": [suite]}))
    monkeypatch.setattr(benchmark, "ROOT", tmp_path)
    monkeypatch.setattr(benchmark, "CACHE", tmp_path / "cache")
    (tmp_path / "cache").mkdir()
    monkeypatch.setattr(benchmark.catalog, "load", lambda: ({}, {"cwe_parents": PARENTS}))

    def scan_pair(suite, case, log):
        if case["id"] == "bad":
            raise subprocess.CalledProcessError(128, ["git"], stderr="fatal: specify directories")
        return {"before": {}, "after": {}}, {"before": [], "after": []}

    monkeypatch.setattr(benchmark, "scan_pair", scan_pair)
    logged = []

    out = benchmark.run(["pairs"], log=logged.append)

    assert [c["id"] for c in out["pairs"]["verdict"]["cases"]] == ["ok"]
    assert any("bad: scan failed" in line and "specify directories" in line for line in logged)
