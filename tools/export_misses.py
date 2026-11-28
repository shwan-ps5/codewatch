"""The gap-notes runner's work list from the last nightly run (AGENTS.md section 9).

    python3 -I tools/export_misses.py --out FILE [--nightly DIR] [--benchmarks DIR]

Writes one tab-separated row per piece of work: task, suite, language, id, repo, fix, cwe, scope, detail. Tasks:
- missed: an open case verdict mode didn't find, with no gap note yet (every language);
- still-flagged: a Python case verdict mode still flags at its fix, with no still-flagged note yet; detail is what
  flags it there (rule@line, as the nightly reports it). A case only review mode still flags (a hotspot) is listed
  too, its detail starting "review: ";
- check-quotes: a Python case still missed whose gap note hasn't had its quotes checked; detail is the note's file;
- recheck: a Python case still missed, its quotes checked, whose newest note is RECHECK_DAYS old or more: the rules
  have moved since, so its explanation may not hold. detail is the newest note's file.
Python first (missed, still-flagged, check-quotes), then JavaScript, then PHP, then the rest. Only cve-pairs suites
that aren't blind are read, whatever result files the nightly directory holds. Prints how many rows it wrote.
Standard library only.
"""

import argparse
import datetime
import json
import re
import sys
from pathlib import Path

ORDER = ("python", "javascript", "php")
MISSED, STILL_FLAGGED, CHECK_QUOTES, RECHECK = "missed", "still-flagged", "check-quotes", "recheck"
TASKS = (MISSED, STILL_FLAGGED, CHECK_QUOTES, RECHECK)
RECHECK_DAYS = 7
REVIEW = "review: "
NOTE_DATE = re.compile(r"^gap-notes-(\d{4}-\d{2}-\d{2})-")
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


def note_files(benchmarks):
    """[(file name, note)] of every gap note, oldest file first."""
    found = []
    for path in sorted(benchmarks.glob("gap-notes-*.json"), key=lambda p: note_key(p.name)):
        try:
            notes = json.loads(path.read_text()).get("notes", [])
        except ValueError:
            continue
        found += [(path.name, note) for note in notes if isinstance(note, dict)]
    return found


def note_key(name):
    """Sorts gap-notes-DATE-N.json by date, then N as a number (-10 after -9)."""
    date, _, rest = name.removeprefix("gap-notes-").removesuffix(".json").rpartition("-")
    return (date, int(rest) if rest.isdigit() else 0, rest)


def noted(benchmarks):
    """{(task, id): file name} of the work already done; a note without a task is a missed-case note."""
    done = {}
    for name, note in note_files(benchmarks):
        done.setdefault((note.get("task") or MISSED, note.get("id")), name)
    return done


def newest_notes(benchmarks):
    """{id: file name} of each case's newest note explaining a miss (missed, check-quotes or recheck)."""
    newest = {}
    for name, note in note_files(benchmarks):
        if (note.get("task") or MISSED) in (MISSED, CHECK_QUOTES, RECHECK):
            newest[note.get("id")] = name
    return newest


def days_between(name, day):
    """Days from a gap-notes file's date to day (YYYY-MM-DD); None when either isn't a date."""
    match = NOTE_DATE.match(name)
    try:
        return (datetime.date.fromisoformat(day) - datetime.date.fromisoformat(match.group(1))).days if match else None
    except ValueError:
        return None


def verdicts(results, suite, mode="verdict"):
    """The suite's cases in mode (verdict or review) from its result file, or []."""
    path = results / f"{suite}.json"
    if not path.is_file():
        return []
    return json.loads(path.read_text()).get(mode, {}).get("cases", [])


def still_flagged(case, review):
    """The detail of a still-flagged row for a case (verdict mode first, then review mode's hotspots), or None."""
    if case.get("still_flagged"):
        return ",".join(case.get("still_by", []))
    if review and review.get("still_flagged"):
        return REVIEW + ",".join(review.get("still_by", []))
    return None


def missed_note_work(case_id, done, newest):
    """[(task, detail)] for a Python case still missed that has a note: its quotes checked, then a recheck once the
    newest note is RECHECK_DAYS old."""
    if (CHECK_QUOTES, case_id) not in done:
        return [(CHECK_QUOTES, done[(MISSED, case_id)])]
    if newest and (newest[1] or 0) >= RECHECK_DAYS:
        return [(RECHECK, newest[0])]
    return []


def work(case, language, done, review=None, newest=None):
    """[(task, detail)] for one case of the nightly. review: the case in review mode, or None. newest: (file name
    of its newest note explaining the miss, days since), or None."""
    case_id, found = case["id"], case.get("detected")
    todo = [] if found or (MISSED, case_id) in done else [(MISSED, "")]
    if language != "python":
        return todo
    detail = None if (STILL_FLAGGED, case_id) in done else still_flagged(case, review)
    if detail is not None:
        todo.append((STILL_FLAGGED, detail))
    if not found and (MISSED, case_id) in done:
        todo += missed_note_work(case_id, done, newest)
    return todo


def suite_rows(nightly, name, suite, notes):
    """The rows of one suite's cases. notes: (done, newest) as noted() and newest_notes() give them."""
    done, newest = notes
    language = suite.get("language", "")
    entries = {c["id"]: c for c in suite.get("cases", []) if isinstance(c, dict)}
    review = {c.get("id"): c for c in verdicts(nightly / "results", name, "review")}
    found = []
    for case in verdicts(nightly / "results", name):
        entry = entries.get(case.get("id"))
        if not entry:
            continue
        note = newest.get(case["id"])
        for task, detail in work(case, language, done, review.get(case["id"]),
                                 note and (note, days_between(note, nightly.name))):
            found.append((task, name, language, case["id"], entry.get("repo", ""), entry.get("fix", ""),
                          ",".join(map(str, entry.get("cwe", []))), ",".join(entry.get("scope", [])), detail))
    return found


def rows(nightly, benchmarks):
    notes = (noted(benchmarks), newest_notes(benchmarks))
    found = [row for name, suite in open_suites(benchmarks).items() for row in suite_rows(nightly, name, suite, notes)]

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
