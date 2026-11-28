"""tools/export_misses.py: the gap-notes runner's list of missed open cases."""

import importlib.util
import json
import shutil
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("export_misses",
                                              Path(__file__).parent.parent / "tools" / "export_misses.py")
assert SPEC is not None and SPEC.loader is not None
export_misses = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(export_misses)


def case(case_id):
    return {"id": case_id, "repo": f"https://github.com/o/{case_id}.git", "fix": "ab" * 20, "cwe": [79, 22],
            "scope": ["app"]}


def test_only_open_misses_without_a_note_are_listed(tmp_path):
    benchmarks, nightly = tmp_path / "benchmarks", tmp_path / "2026-11-22"
    (nightly / "results").mkdir(parents=True)
    benchmarks.mkdir()
    (benchmarks / "suites.json").write_text(json.dumps({"suites": [
        {"name": "cve-pairs-php", "language": "php", "kind": "cve-pairs", "cases": [case("P1")]},
        {"name": "cve-pairs-python", "language": "python", "kind": "cve-pairs",
         "cases": [case("A"), case("B"), case("C")]},
        {"name": "cve-pairs-blind-python-3", "language": "python", "kind": "cve-pairs", "blind": True,
         "cases": [case("X")]},
        {"name": "securityeval", "language": "python", "kind": "snippets", "cases": [case("S")]},
    ]}))
    results = {"cve-pairs-python": {"A": False, "B": True, "C": False}, "cve-pairs-php": {"P1": False},
               "cve-pairs-blind-python-3": {"X": False}, "securityeval": {"S": False}}
    for suite, found in results.items():
        cases = [{"id": i, "detected": d} for i, d in found.items()]
        (nightly / "results" / f"{suite}.json").write_text(json.dumps({"verdict": {"cases": cases}}))
    (benchmarks / "gap-notes-2026-11-22-1.json").write_text(json.dumps({"notes": [{"id": "C"}]}))

    rows = export_misses.rows(nightly, benchmarks)
    assert [(r[0], r[1], r[3]) for r in rows if r[0] == "missed"] == [("missed", "cve-pairs-python", "A"),
                                                                      ("missed", "cve-pairs-php", "P1")]
    assert rows[0][4:] == ("https://github.com/o/A.git", "ab" * 20, "79,22", "app", "")
    assert export_misses.latest_nightly(tmp_path) == nightly


def write_suites(benchmarks, nightly, results):
    """results: {suite: {id: (detected, still_by)}}; each suite's language is its name's last word."""
    (nightly / "results").mkdir(parents=True)
    benchmarks.mkdir()
    (benchmarks / "suites.json").write_text(json.dumps({"suites": [
        {"name": s, "language": s.rsplit("-", 1)[1], "kind": "cve-pairs", "cases": [case(i) for i in r]}
        for s, r in results.items()]}))
    for suite, found in results.items():
        cases = [{"id": i, "detected": d, "still_flagged": bool(by), "still_by": by} for i, (d, by) in found.items()]
        (nightly / "results" / f"{suite}.json").write_text(json.dumps({"verdict": {"cases": cases}}))


def test_python_fixes_still_flagged_are_listed_with_what_flags_them(tmp_path):
    benchmarks, nightly = tmp_path / "benchmarks", tmp_path / "2026-11-25"
    write_suites(benchmarks, nightly, {
        "cve-pairs-python": {"F": (True, ["codewatch:codewatch.python.web.xss@12"]), "G": (True, ["x@3"]),
                             "H": (True, [])},
        "cve-pairs-php": {"Q": (True, ["codewatch:codewatch.php.xss@9"])},
    })
    (benchmarks / "gap-notes-2026-11-25-1.json").write_text(json.dumps({"notes": [{"id": "G", "task": "still-flagged"}]}))

    rows = export_misses.rows(nightly, benchmarks)
    assert [(r[0], r[3], r[8]) for r in rows] == [("still-flagged", "F", "codewatch:codewatch.python.web.xss@12")]


def test_python_notes_of_cases_still_missed_get_their_quotes_checked(tmp_path):
    benchmarks, nightly = tmp_path / "benchmarks", tmp_path / "2026-11-25"
    write_suites(benchmarks, nightly, {
        "cve-pairs-python": {"M": (False, []), "N": (False, []), "K": (False, []), "D": (True, [])},
        "cve-pairs-php": {"R": (False, [])},
    })
    (benchmarks / "gap-notes-2026-11-20-3.json").write_text(json.dumps({"notes": [
        {"id": "M"}, {"id": "N"}, {"id": "D"}, {"id": "R"}]}))
    (benchmarks / "gap-notes-2026-11-25-1.json").write_text(json.dumps({"notes": [{"id": "N", "task": "check-quotes"}]}))

    rows = export_misses.rows(nightly, benchmarks)
    assert [(r[0], r[3], r[8]) for r in rows] == [("missed", "K", ""), ("check-quotes", "M", "gap-notes-2026-11-20-3.json")]


def test_fixes_only_review_mode_still_flags_are_listed_with_the_review_hotspots(tmp_path):
    """PLAN.md step 159: 11 Python fixes were still flagged in review mode only (hotspots), with no note."""
    benchmarks, nightly = tmp_path / "benchmarks", tmp_path / "2026-11-28"
    write_suites(benchmarks, nightly, {"cve-pairs-python": {"V": (True, ["x@1"]), "W": (True, []), "Z": (True, [])}})
    path = nightly / "results" / "cve-pairs-python.json"
    data = json.loads(path.read_text())
    data["review"] = {"cases": [
        {"id": "V", "detected": True, "still_flagged": True, "still_by": ["x@1", "y@2"]},
        {"id": "W", "detected": True, "still_flagged": True, "still_by": ["bandit:B608:hardcoded_sql_expressions@5"]},
        {"id": "Z", "detected": True, "still_flagged": False, "still_by": []}]}
    path.write_text(json.dumps(data))

    rows = export_misses.rows(nightly, benchmarks)
    assert [(r[0], r[3], r[8]) for r in rows] == [
        ("still-flagged", "V", "x@1"), ("still-flagged", "W", "review: bandit:B608:hardcoded_sql_expressions@5")]


def test_notes_a_week_old_on_cases_still_missed_are_rechecked(tmp_path):
    """PLAN.md step 159: once a missed case's quotes are checked, its newest note is rechecked against the rules
    after RECHECK_DAYS; a newer recheck or check-quotes note starts the wait again. Files sort by their number."""
    benchmarks, nightly = tmp_path / "benchmarks", tmp_path / "2026-11-30"
    write_suites(benchmarks, nightly, {"cve-pairs-python": {"A": (False, []), "B": (False, []), "C": (False, []),
                                                            "D": (True, [])},
                                       "cve-pairs-php": {"P": (False, [])}})
    (benchmarks / "gap-notes-2026-11-20-9.json").write_text(json.dumps({"notes": [
        {"id": "A"}, {"id": "B"}, {"id": "C"}, {"id": "D"}, {"id": "P"}]}))
    (benchmarks / "gap-notes-2026-11-21-10.json").write_text(json.dumps({"notes": [
        {"id": i, "task": "check-quotes"} for i in "ABCD"]}))
    (benchmarks / "gap-notes-2026-11-21-2.json").write_text(json.dumps({"notes": [{"id": "A", "task": "check-quotes"}]}))
    (benchmarks / "gap-notes-2026-11-26-1.json").write_text(json.dumps({"notes": [{"id": "B", "task": "recheck"}]}))

    rows = export_misses.rows(nightly, benchmarks)
    assert [(r[0], r[3], r[8]) for r in rows] == [("recheck", "A", "gap-notes-2026-11-21-10.json"),
                                                  ("recheck", "C", "gap-notes-2026-11-21-10.json")]
    six_days = tmp_path / "2026-11-27"
    shutil.copytree(nightly, six_days)
    assert export_misses.rows(six_days, benchmarks) == []
