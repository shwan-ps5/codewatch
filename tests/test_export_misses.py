"""tools/export_misses.py: the gap-notes runner's list of missed open cases."""

import importlib.util
import json
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
    assert [(r[0], r[2]) for r in rows] == [("cve-pairs-python", "A"), ("cve-pairs-php", "P1")]
    assert rows[0][3:] == ("https://github.com/o/A.git", "ab" * 20, "79,22", "app")
    assert export_misses.latest_nightly(tmp_path) == nightly
