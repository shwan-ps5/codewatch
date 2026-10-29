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
    monkeypatch.setattr(benchmark, "scan", lambda root, log: [issue("tc/T1.py", "xss")])
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
