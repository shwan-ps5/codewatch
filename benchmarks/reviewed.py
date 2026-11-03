"""Which advisories and fix commits have already been looked at, so nobody reads them twice.

Reads every benchmarks/cve-candidates-*.tsv (one row per advisory read, accepted or rejected) and every
cve-pairs suite in benchmarks/suites.json, blind ones included. Standard library only, so it runs anywhere:

    python3 -I benchmarks/reviewed.py                    every known advisory: id, status, where recorded
    python3 -I benchmarks/reviewed.py GHSA-... SHA ...   just these (advisory ids or fix commits, 7+ hex chars);
                                                         exits 1 when any of them is already known
    python3 -I benchmarks/reviewed.py --split GHSA-...   blind or open under PLAN.md step 22's rule

A status is "suite:<name>" (in that suite), "rejected", "accepted" (accepted but not in a suite yet) or "unsure".
Blind cases show only their suite name: their reasons are never written down.
"""

import csv
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def is_blind(advisory_id):
    return int(hashlib.sha256(advisory_id.encode()).hexdigest(), 16) % 3 == 0


def known(root=HERE):
    """{advisory id: (status, where recorded)} and {fix commit: advisory id}."""
    seen, fixes = {}, {}
    for tsv in sorted(root.glob("cve-candidates-*.tsv")):
        rows = csv.reader((line for line in tsv.open() if line.strip() and not line.startswith("#")), delimiter="\t")
        for row in rows:
            if len(row) < 4 or row[1] == "id":
                continue
            decision = {"accept": "accepted", "reject": "rejected"}.get(row[3], row[3] or "unsure")
            seen[row[1]] = (decision, tsv.name)
    for suite in json.loads((root / "suites.json").read_text())["suites"]:
        for case in suite.get("cases", []):
            if isinstance(case, dict) and case.get("id"):
                seen[case["id"]] = (f"suite:{suite['name']}", "suites.json")
                if case.get("fix"):
                    fixes[case["fix"]] = case["id"]
    return seen, fixes


def lookup(key, seen, fixes):
    if key in seen:
        return key, *seen[key]
    if len(key) >= 7 and all(c in "0123456789abcdef" for c in key.lower()):
        for fix, advisory in fixes.items():
            if fix.startswith(key.lower()):
                return f"{key} ({advisory})", *seen[advisory]
    return None


def main(argv, root=HERE):
    if argv[:1] == ["--split"]:
        for advisory in argv[1:]:
            print(advisory, "blind" if is_blind(advisory) else "open")
        return 0
    seen, fixes = known(root)
    if not argv:
        for advisory, (status, where) in sorted(seen.items()):
            print(advisory, status, where, sep="\t")
        return 0
    found = 0
    for key in argv:
        hit = lookup(key, seen, fixes)
        print(*(hit or (key, "new")), sep="\t")
        found += bool(hit)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
