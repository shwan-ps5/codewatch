"""Re-score the CVE fix pairs in benchmarks/smoke.json and fail if any regressed: each must still be found in
verdict mode and quiet after its fix. CI runs this on every push and pull request, so a change that loses a
detection fails on GitHub instead of in the next nightly run on the maintainer's machine.

    venv/bin/python benchmarks/smoke.py [--workers N]

The pairs are fetched shallowly (two commits, blobs on demand, only the case's scope) into the benchmark cache.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import benchmark

SMOKE = Path(__file__).with_name("smoke.json")
VERDICT = "verdict"


def problems(expected, results):
    """One line per expected case that wasn't found, was still flagged after its fix, or didn't scan."""
    rows = {r["id"]: r for _, modes in results for r in [modes[VERDICT]]}
    out = []
    for case_id in expected:
        row = rows.get(case_id)
        if row is None:
            out.append(f"{case_id}: not scored (scan failed or id unknown)")
        elif not row["detected"]:
            out.append(f"{case_id}: no longer found")
        elif row["still_flagged"]:
            out.append(f"{case_id}: flagged after its fix by {', '.join(row['still_by'])}")
    return out


def score(ids, workers):
    return benchmark.score_cases(ids, log=lambda m: print(m) if "fail" in m else None, workers=workers)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=benchmark.WORKERS)
    args = parser.parse_args()
    expected = json.loads(SMOKE.read_text())["cases"]
    found = problems(expected, score(expected, args.workers))
    if found:
        # Under load Semgrep gives up on slow rules and a finding can drop out (GHSA-8whx, 2026-11-28, with three
        # benchmark runs at once): re-score those cases one at a time before calling them regressions.
        again = [line.split(":")[0] for line in found]
        print(f"re-scoring {len(again)} case(s) one at a time: {', '.join(again)}")
        found = problems(again, score(again, 1))
    for line in found:
        print(line)
    print(f"{len(expected) - len(found)} of {len(expected)} smoke cases as expected")
    sys.exit(1 if found else 0)


if __name__ == "__main__":
    main()
