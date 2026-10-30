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
