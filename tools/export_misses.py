"""The open CVE-pair cases the last nightly run missed, for the gap-notes runner (AGENTS.md section 9).

    python3 -I tools/export_misses.py --out FILE [--nightly DIR] [--benchmarks DIR]

Writes one tab-separated row per missed case (verdict mode): suite, language, id, repo, fix, cwe, scope. Python
suites first, then JavaScript, then PHP, then the rest. Only cve-pairs suites that aren't blind are read, whatever
result files the nightly directory holds, and cases that already have a gap note in benchmarks/gap-notes-*.json are
left out. Prints how many rows it wrote. Standard library only.
"""

import argparse
import json
import sys
from pathlib import Path

ORDER = ("python", "javascript", "php")
COLUMNS = ("suite", "language", "id", "repo", "fix", "cwe", "scope")


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
    """Ids that already have a gap note."""
    ids = set()
    for path in benchmarks.glob("gap-notes-*.json"):
        try:
            ids |= {n.get("id") for n in json.loads(path.read_text()).get("notes", [])}
        except ValueError:
            continue
    return ids


def missed(results, suite):
    """Ids of the suite's cases that verdict mode didn't find, from its result file."""
    path = results / f"{suite}.json"
    if not path.is_file():
        return []
    cases = json.loads(path.read_text()).get("verdict", {}).get("cases", [])
    return [c["id"] for c in cases if not c.get("detected")]


def rows(nightly, benchmarks):
    suites = open_suites(benchmarks)
    done = noted(benchmarks)

    def rank(name):
        language = suites[name].get("language", "")
        return (ORDER.index(language) if language in ORDER else len(ORDER), name)

    found = []
    for name in sorted(suites, key=rank):
        entries = {c["id"]: c for c in suites[name].get("cases", []) if isinstance(c, dict)}
        for case_id in missed(nightly / "results", name):
            entry = entries.get(case_id)
            if entry and case_id not in done:
                found.append((name, suites[name].get("language", ""), case_id, entry.get("repo", ""),
                              entry.get("fix", ""), ",".join(map(str, entry.get("cwe", []))),
                              ",".join(entry.get("scope", []))))
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(description="The open CVE-pair cases the last nightly run missed.")
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
