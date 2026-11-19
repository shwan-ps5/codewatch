"""CodeQL on the CVE pairs, scored as codewatch is: a measurement of where codewatch stands (PLAN.md, Open items,
Comparison), never a source of rule changes. Blind suites are refused.

    venv/bin/python benchmarks/codeql_compare.py [--workers N] [--only ID...] SUITE...

Needs the CodeQL bundle (CLI and query packs) at ~/.cache/codewatch/codeql, or $CODEWATCH_CODEQL naming the codeql
binary. CodeQL's terms allow it on Open Source Codebases only (an OSI-approved licence), so a case is scanned only
when its licence is one: GitHub's SPDX id from suites.json, or, for NOASSERTION, the repository's own licence files
read here. Anything else is skipped and listed.

Each side of a fix gets a CodeQL database (Python, plus JavaScript when the checkout has any; JavaScript alone for
JavaScript suites) and the language's security-extended suite. "verdict" counts the queries GitHub runs by default
(the code-scanning suite), "review" all of security-extended. Findings are kept and scored by core.benchmark's own
fix-spot filter and score_pair, with each finding's CWEs from its query's tags. Results go to
~/.cache/codewatch/codeql-compare/<suite>.json (not benchmarks/results, which stays codewatch's).
"""
import argparse
import json
import multiprocessing
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.stdout.reconfigure(line_buffering=True)

from core import benchmark, catalog

CODEWATCH_CACHE = Path.home() / ".cache" / "codewatch"
CODEQL = Path(os.environ.get("CODEWATCH_CODEQL", CODEWATCH_CACHE / "codeql" / "codeql"))
OUT = CODEWATCH_CACHE / "codeql-compare"
SUITES = {lang: {"review": f"codeql/{lang}-queries:codeql-suites/{lang}-security-extended.qls",
                 "verdict": f"codeql/{lang}-queries:codeql-suites/{lang}-code-scanning.qls"}
          for lang in ("python", "javascript")}
JS_FILES = re.compile(r"\.(js|jsx|mjs|cjs|ts|tsx|vue|html|htm)$")
# GitHub's SPDX ids that are OSI-approved, as suites.json records them.
OSI_SPDX = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "GPL-2.0", "GPL-3.0", "LGPL-2.1",
            "LGPL-3.0", "AGPL-3.0", "MPL-2.0", "PostgreSQL", "EPL-2.0", "Unlicense", "Zlib", "BSL-1.0"}
OSI_TEXT = re.compile(r"Permission is hereby granted, free of charge|Apache License,?\s+Version 2\.0|Redistribution "
                      r"and use in source and binary forms|GNU (AFFERO |LESSER )?GENERAL PUBLIC LICENSE|Mozilla "
                      r"Public License|Permission to use, copy, modify,? and(/or)? distribute|PostgreSQL License|"
                      r"free and unencumbered software|Eclipse Public License", re.IGNORECASE)
NOT_OSI_TEXT = re.compile(r"Commons Clause|Business Source License|Elastic License|Server Side Public License|"
                          r"PolyForm|Sustainable Use License|fair[- ]code|commercial licen[cs]e|Enterprise Edition|"
                          r"source[- ]available", re.IGNORECASE)
LICENCE_NAME = re.compile(r"^(LICEN[CS]E|COPYING)(\.\w+)?$|^LICEN[CS]E[-_.]", re.IGNORECASE)


def licence_files(root, paths):
    """The licence files at the checkout's root and in every folder above the fix's changed files."""
    folders = {Path(".")} | {parent for p in paths for parent in Path(p).parents}
    return [f for folder in folders if (root / folder).is_dir()
            for f in (root / folder).iterdir() if f.is_file() and LICENCE_NAME.match(f.name)]


def open_source(case, root, paths):
    """(True, why) when the case's code is under an OSI-approved licence, else (False, why)."""
    files = licence_files(root, paths)
    texts = [f.read_text(errors="replace") for f in files]
    if any(NOT_OSI_TEXT.search(t) for t in texts):
        return False, "a licence file names a non-OSI licence or commercial terms"
    if case.get("license") in OSI_SPDX:
        return True, case["license"]
    if texts and all(OSI_TEXT.search(t) for t in texts):
        return True, "licence files read: " + ", ".join(sorted(f.name for f in files))
    return False, f"licence {case.get('license')}, no OSI licence text found"


def codeql(*args):
    run = subprocess.run([str(CODEQL), *args], check=False, capture_output=True, text=True)
    if run.returncode:
        raise RuntimeError(f"codeql {args[0]} {args[1]} failed: {run.stderr.strip()[-2000:]}")
    return run.stdout


def query_ids(suite):
    """Rule ids of the queries in a query suite."""
    ids = set()
    for path in json.loads(codeql("resolve", "queries", "--format=json", suite)):
        text = Path(path).read_text(errors="replace")
        if match := re.search(r"@id\s+(\S+)", text):
            ids.add(match.group(1))
    return ids


def sarif_issues(sarif, default_ids):
    """Each result as a benchmark issue: verdict ("vulnerability") for a query GitHub runs by default, review
    ("security_hotspot") for the rest of security-extended; CWEs from the query's tags."""
    issues = []
    for run in json.loads(sarif.read_text())["runs"]:
        rules = {r["id"]: r for r in run["tool"]["driver"].get("rules", [])}
        for ext in run["tool"].get("extensions", []):
            rules.update({r["id"]: r for r in ext.get("rules", [])})
        for result in run.get("results", []):
            loc = result["locations"][0]["physicalLocation"]
            rule = rules.get(result["ruleId"], {})
            tags = rule.get("properties", {}).get("tags", [])
            cwes = sorted({int(m.group(1)) for t in tags if (m := re.match(r"external/cwe/cwe-0*([1-9]\d*|0)$", t))})
            issues.append({"tool": "codeql", "rule": result["ruleId"], "path": unquote(loc["artifactLocation"]["uri"]),
                           "line": loc.get("region", {}).get("startLine"), "cwes": cwes,
                           "type": "vulnerability" if result["ruleId"] in default_ids else "security_hotspot"})
    return issues


def codeql_scan(language, default_ids):
    """A stand-in for benchmark.scan_and_gave_up: the same signature, CodeQL's findings."""
    def scan(root, log, paths=(), focus=None, tools=None):  # noqa: ARG001 - scan_and_gave_up's signature
        files = [f for f in benchmark.git("ls-files", "-z", "--", *paths, cwd=root).split("\0") if f]
        # A Python suite's case can be front-end code only (a scope with no Python): CodeQL refuses a language
        # with no files.
        langs = ([*(["python"] if any(f.endswith(".py") for f in files) else []),
                  *(["javascript"] if any(JS_FILES.search(f) for f in files) else [])]
                 if language.startswith("python") else ["javascript"])
        threads, ram = os.environ.get("CODEQL_THREADS", "3"), os.environ.get("CODEQL_RAM", "6000")
        work = Path(tempfile.mkdtemp(prefix="codeql-", dir=OUT))
        try:
            start = time.monotonic()
            while True:
                try:
                    codeql("database", "create", str(work / "db"), "--db-cluster", f"--language={','.join(langs)}",
                           f"--source-root={root}", "--overwrite", f"--threads={threads}", f"--ram={ram}")
                    break
                except RuntimeError as error:
                    # Files with the extension but nothing CodeQL extracts (an HTML page with no script, a
                    # vendored bundle it skips): that language is dropped and the rest scanned.
                    empty = [lang for lang, name in (("python", "Python"), ("javascript", "JavaScript"))
                             if lang in langs and f"not any written in {name}" in str(error)]
                    if not empty or len(langs) == len(empty):
                        raise
                    langs = [lang for lang in langs if lang not in empty]
            issues = []
            for lang in langs:
                sarif = work / f"{lang}.sarif"
                codeql("database", "analyze", str(work / "db" / lang), SUITES[lang]["review"],
                       "--format=sarif-latest", f"--output={sarif}", f"--threads={threads}", f"--ram={ram}")
                issues += sarif_issues(sarif, default_ids[lang])
            if tools is not None:
                tools["codeql"] = time.monotonic() - start
            return issues, False
        finally:
            shutil.rmtree(work, ignore_errors=True)
    return scan


def related_cwes(issue, original=benchmark.issue_cwes):
    return set(issue["cwes"]) if issue.get("tool") == "codeql" else original(issue)


def scan_case(suite, case, default_ids):
    """(case id, pair or None, why skipped or None, log lines), in a worker process."""
    lines = []
    benchmark.scan_and_gave_up = codeql_scan(suite["language"], default_ids)
    try:
        root, parent = benchmark.fetch_pair(suite, case)
        benchmark.git("checkout", "-q", "--force", case["fix"], cwd=root)
        changed = benchmark.git("diff", "--name-only", "--no-renames", parent, case["fix"], cwd=root).splitlines()
        ok, why = open_source(case, root, changed)
        if not ok:
            return case["id"], None, why, lines
        return case["id"], benchmark.scan_pair(suite, case, lines.append), None, lines
    except Exception as error:  # noqa: BLE001 - one case failing is reported, the rest go on
        return case["id"], None, f"failed: {error}", lines


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("suites", nargs="+")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--only", nargs="*", default=[])
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    every = {s["name"]: s for s in json.loads((benchmark.ROOT / "suites.json").read_text())["suites"]}
    suites = [every[name] for name in args.suites]
    if any(s.get("blind") for s in suites):
        sys.exit("blind suites are never scanned for comparison")
    default_ids = {lang: query_ids(SUITES[lang]["verdict"]) for lang in SUITES}
    parents = catalog.load()[1].get("cwe_parents", {})
    benchmark.issue_cwes = related_cwes
    for suite in suites:
        cases = [c for c in suite["cases"] if not args.only or c["id"].startswith(tuple(args.only))]
        print(f"== {suite['name']}: {len(cases)} cases", flush=True)
        scanned, skipped = {}, {}
        if args.only and (OUT / f"{suite['name']}.json").exists():
            # Re-running some cases: the suite's other results are kept.
            scanned = json.loads((OUT / f"{suite['name']}.issues.json").read_text())
            skipped = json.loads((OUT / f"{suite['name']}.json").read_text())["skipped"]
            cases_run = {c["id"] for c in cases}
            scanned = {k: v for k, v in scanned.items() if k not in cases_run}
            skipped = {k: v for k, v in skipped.items() if k not in cases_run}
        with ProcessPoolExecutor(args.workers, mp_context=multiprocessing.get_context("spawn")) as pool:
            futures = [pool.submit(scan_case, suite, case, default_ids) for case in cases]
            for future in as_completed(futures):
                case_id, pair, why, lines = future.result()
                for line in lines:
                    if line.startswith("timing\t"):
                        print("  " + line.removeprefix("timing\t"), flush=True)
                if pair is None:
                    skipped[case_id] = why
                    print(f"  {case_id}: skipped, {why}", flush=True)
                else:
                    scanned[case_id] = pair
        done = [c for c in suite["cases"] if c["id"] in scanned]
        result = {mode: benchmark.score_pairs_mode(done, scanned, types, parents)
                  for mode, types in benchmark.MODES.items()}
        result["skipped"] = skipped
        result["codeql"] = codeql("version", "--format=terse").strip()
        (OUT / f"{suite['name']}.json").write_text(json.dumps(result, indent=1) + "\n")
        (OUT / f"{suite['name']}.issues.json").write_text(json.dumps(scanned))
        for mode in benchmark.MODES:
            o = result[mode]["overall"]
            print(f"{suite['name']} {mode}: found {sum(r['detected'] for r in result[mode]['cases'])}/{len(done)}, "
                  f"still flagged {sum(r['still_flagged'] for r in result[mode]['cases'])} ({o})", flush=True)
        print(f"{suite['name']}: {len(skipped)} skipped", flush=True)


if __name__ == "__main__":
    main()
