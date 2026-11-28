"""benchmarks/smoke.py (the CVE pairs CI re-scores) and benchmarks/rule_trust.py (per-rule evidence)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))

import rule_trust
import smoke

ROOT = Path(__file__).resolve().parents[1]


def row(case_id, detected=True, still=()):
    return ("cve-pairs-python", {"verdict": {"id": case_id, "detected": detected, "still_flagged": bool(still),
                                             "still_by": list(still)}})


def test_smoke_reports_each_lost_detection_new_flag_and_missing_scan():
    results = [row("A"), row("B", detected=False), row("C", still=["codewatch:x@3"])]
    assert smoke.problems(["A", "B", "C", "D"], results) == [
        "B: no longer found", "C: flagged after its fix by codewatch:x@3",
        "D: not scored (scan failed or id unknown)"]


def test_smoke_cases_are_open_cve_pairs_never_blind():
    suites = json.loads((ROOT / "benchmarks" / "suites.json").read_text())["suites"]
    open_ids = {c["id"] for s in suites if not s.get("blind") for c in s.get("cases", [])}
    blind_ids = {c["id"] for s in suites if s.get("blind") for c in s.get("cases", [])}
    cases = json.loads(smoke.SMOKE.read_text())["cases"]
    assert set(cases) <= open_ids
    assert not set(cases) & blind_ids


def test_rule_keys_group_python_template_and_js_rules():
    assert rule_trust.rule_key("codewatch:codewatch.python.web.path-traversal@12") == ("python", "path-traversal")
    assert rule_trust.rule_key("codewatch:codewatch.python.sql-value-formatting@3") == ("python", "sql-value-formatting")
    assert rule_trust.rule_key("codewatch:codewatch.js.xss@5") == ("javascript", "xss")
    assert rule_trust.rule_key("semgrep:python.flask.security.x@1") is None


def test_rule_trust_counts_cases_once_per_rule_and_only_clean_apps(tmp_path, monkeypatch):
    (tmp_path / "results").mkdir()
    cases = [{"by": ["codewatch:codewatch.python.web.xss@1", "codewatch:codewatch.python.web.xss@9"],
              "still_by": ["codewatch:codewatch.python.web.xss@2"]},
             {"by": [], "still_by": []}]
    (tmp_path / "results" / "cve-pairs-python.json").write_text(json.dumps({"verdict": {"cases": cases}}))
    (tmp_path / "apps.txt").write_text("cleanapp a.py 3 xss\ncleanapp b.py 4 xss\nvulnapp c.py 1 xss\n")
    monkeypatch.setattr(rule_trust, "HERE", tmp_path)
    (tmp_path / "clean-apps.json").write_text(json.dumps({"apps": {"cleanapp": "python"}}))
    assert "| python | `xss` | 1 | 1 | 2 (1) |" in rule_trust.table(tmp_path)
