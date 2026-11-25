"""The gap-notes runner's work list from the last nightly run (AGENTS.md section 9).

    python3 -I tools/export_misses.py --out FILE [--nightly DIR] [--benchmarks DIR]

Writes one tab-separated row per piece of work: task, suite, language, id, repo, fix, cwe, scope, detail. Tasks:
- missed: an open case verdict mode didn't find, with no gap note yet (every language);
- still-flagged: a Python case verdict mode still flags at its fix, with no still-flagged note yet; detail is what
  flags it there (rule@line, as the nightly reports it);
- check-quotes: a Python case still missed whose gap note hasn't had its quotes checked; detail is the note's file.
Python first (missed, still-flagged, check-quotes), then JavaScript, then PHP, then the rest. Only cve-pairs suites
that aren't blind are read, whatever result files the nightly directory holds. Prints how many rows it wrote.
Standard library only.
"""

import argparse
import json
import sys
from pathlib import Path

ORDER = ("python", "javascript", "php")
MISSED, STILL_FLAGGED, CHECK_QUOTES = "missed", "still-flagged", "check-quotes"
TASKS = (MISSED, STILL_FLAGGED, CHECK_QUOTES)
COLUMNS = ("task", "suite", "language", "id", "repo", "fix", "cwe", "scope", "detail")


def latest_nightly(root):
    """The newest nightly directory that has results, or None."""
    runs = sorted(p for p in root.glob("????-??-??") if (p / "results").is_dir())
    return runs[-1] if runs else None


def open_suites(benchmarks):
    """{name: suite} of the cve-pairs suites that aren't blind."""
    suites = json.loads((benchmarks / "suites.json").read_text())["suites"]
    return {s["name"]: s for s in suites
            if s.get("kind") == "cve-pairs" and not s.get("blind") and "blind" not in s["name"]}


def noted(benchmarks):
    """{(task, id): file name} of the work already done; a note without a task is a missed-case note."""
    done = {}
    for path in sorted(benchmarks.glob("gap-notes-*.json")):
        try:
            notes = json.loads(path.read_text()).get("notes", [])
        except ValueError:
            continue
        for note in notes:
            if isinstance(note, dict):
                done.setdefault((note.get("task") or MISSED, note.get("id")), path.name)
    return done


def verdicts(results, suite):
    """The suite's verdict-mode cases from its result file, or []."""
    path = results / f"{suite}.json"
    if not path.is_file():
        return []
    return json.loads(path.read_text()).get("verdict", {}).get("cases", [])


def work(case, language, done):
    """[(task, detail)] for one case of the nightly."""
    case_id, found = case["id"], case.get("detected")
    todo = []
    if not found and (MISSED, case_id) not in done:
        todo.append((MISSED, ""))
    if language == "python":
        if case.get("still_flagged") and (STILL_FLAGGED, case_id) not in done:
            todo.append((STILL_FLAGGED, ",".join(case.get("still_by", []))))
        if not found and (MISSED, case_id) in done and (CHECK_QUOTES, case_id) not in done:
            todo.append((CHECK_QUOTES, done[(MISSED, case_id)]))
    return todo


def rows(nightly, benchmarks):
    suites = open_suites(benchmarks)
    done = noted(benchmarks)
    found = []
    for name, suite in suites.items():
        language = suite.get("language", "")
        entries = {c["id"]: c for c in suite.get("cases", []) if isinstance(c, dict)}
        for case in verdicts(nightly / "results", name):
            entry = entries.get(case.get("id"))
            if not entry:
                continue
            for task, detail in work(case, language, done):
                found.append((task, name, language, case["id"], entry.get("repo", ""), entry.get("fix", ""),
                              ",".join(map(str, entry.get("cwe", []))), ",".join(entry.get("scope", [])), detail))

    def rank(row):
        language = row[2]
        return (ORDER.index(language) if language in ORDER else len(ORDER), TASKS.index(row[0]), row[1])

    return sorted(found, key=rank)


def main(argv=None):
    parser = argparse.ArgumentParser(description="The gap-notes runner's work list from the last nightly run.")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--nightly", type=Path, help="a nightly run's directory (default: the latest)")
    parser.add_argument("--benchmarks", type=Path, default=Path(__file__).resolve().parent.parent / "benchmarks")
    args = parser.parse_args(argv)
    nightly = args.nightly or latest_nightly(Path.home() / ".cache/codewatch/nightly")
    found = rows(nightly, args.benchmarks) if nightly else []
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join("\t".join(r) for r in [COLUMNS, *found]) + "\n")
    print(len(found))
    return 0


if __name__ == "__main__":
    sys.exit(main())
