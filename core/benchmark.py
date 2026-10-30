"""Benchmarks: scan third-party code with published ground truth and score what codewatch catches.

Suites are listed in benchmarks/suites.json, fetched at a pinned commit into the cache directory, scanned
(never executed) and scored. Results go to benchmarks/results/<suite>.json and .md.
"""
import csv
import json
import os
import re
import subprocess
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

import yaml

from . import catalog
from .collect import ScanConfig, ScanInput, collect

ROOT = Path(__file__).resolve().parents[1] / "benchmarks"
CACHE = Path(os.environ.get("CODEWATCH_CACHE", Path.home() / ".cache" / "codewatch")) / "benchmarks"
SECURITY_TYPES = {"vulnerability", "security_hotspot"}
# Not about the code under test: dependency audits, live pages, coverage import, duplication.
SKIPPED_ANALYZERS = ["pip-audit", "axe", "coverage", "jscpd"]
SNIPPET_RE = re.compile(r"vuln-code-snippet vuln-line ([\w ]{1,500})")
NEARBY_LINES = 3


def git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def fetch(suite):
    target = CACHE / suite["name"]
    target.mkdir(parents=True, exist_ok=True)
    if not (target / ".git").exists():
        git("init", "-q", cwd=target)
    git("fetch", "-q", "--depth", "1", suite["repo"], suite["commit"], cwd=target)
    git("checkout", "-q", "--force", "FETCH_HEAD", cwd=target)
    return target


def scan(root, log):
    files = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, text=True,
                           check=True).stdout.split("\0")
    files = [f for f in files if f]
    cfg = ScanConfig(disabled_analyzers=SKIPPED_ANALYZERS, custom_rules=catalog.custom_semgrep_rules())
    return collect(cfg, ScanInput(root, files, "benchmark"), log)["issues"]


def related(a, b, parents):
    """Same weakness, or one is an ancestor of the other in MITRE's hierarchy (e.g. CWE-327 and CWE-328)."""
    return a == b or a in catalog.ancestors(b, parents) or b in catalog.ancestors(a, parents)


def issue_cwes(issue):
    """CWEs of the rule, and of every other rule that reported the same finding before it was merged."""
    cwes = set()
    for tool, rule in [(issue["tool"], issue["rule"]),
                       *(s.split(":", 1) for s in issue.get("also_reported_by") or [] if ":" in s)]:
        entry = catalog.lookup(tool, rule)
        cwes.update(entry["cwe"] if entry else [])
    return cwes


# Verdict mode counts only findings that claim a vulnerability (data flow or definite flaw), which is what the
# Security rating uses; review mode adds security hotspots, i.e. everything a reviewer is asked to look at.
MODES = {"verdict": {"vulnerability"}, "review": SECURITY_TYPES}


def issues_by_file(issues, types):
    by_file = defaultdict(list)
    for i in issues:
        if i["type"] in types:
            by_file[i["path"]].append(i)
    return by_file


# --- OWASP Benchmark --------------------------------------------------------------------------------------


def owasp_cases(root, suite):
    with open(root / suite["expected"], newline="") as f:
        rows = [r for r in csv.reader(f) if r and not r[0].startswith("#")]
    return [{"test": r[0].strip(), "category": r[1].strip(), "real": r[2].strip() == "true", "cwe": int(r[3])}
            for r in rows]


def flagged(case, findings, parents):
    """The case counts as flagged if a security finding in its file maps to the expected CWE family."""
    return any(any(related(c, case["cwe"], parents) for c in issue_cwes(i)) for i in findings)


def rates(s):
    tpr = s["tp"] / (s["tp"] + s["fn"]) if s["tp"] + s["fn"] else 0.0
    fpr = s["fp"] / (s["fp"] + s["tn"]) if s["fp"] + s["tn"] else 0.0
    return {**s, "tpr": round(tpr, 3), "fpr": round(fpr, 3), "score": round(tpr - fpr, 3)}


def score_owasp_mode(cases, suite, by_file, parents):
    stats = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0, "cwe": None})
    missed = []
    for case in cases:
        hit = flagged(case, by_file.get(f"{suite['test_dir']}/{case['test']}.py", []), parents)
        s = stats[case["category"]]
        s["cwe"] = case["cwe"]
        s[("tp" if hit else "fn") if case["real"] else ("fp" if hit else "tn")] += 1
        if case["real"] != hit:
            missed.append({**case, "flagged": hit})
    categories = {name: rates(s) for name, s in sorted(stats.items())}
    overall = {k: round(sum(c[k] for c in categories.values()) / len(categories), 3) for k in ("tpr", "fpr", "score")}
    return {"overall": overall, "categories": categories, "mistakes": missed[:300]}


def score_owasp(root, suite, issues):
    parents = catalog.load()[1].get("cwe_parents", {})
    cases = owasp_cases(root, suite)
    return {mode: score_owasp_mode(cases, suite, issues_by_file(issues, types), parents)
            for mode, types in MODES.items()}


# --- Juice Shop style snippets ----------------------------------------------------------------------------


def marked_lines(root):
    """{challenge: [(path, line)]} from 'vuln-code-snippet vuln-line <challenges>' markers."""
    files = subprocess.run(["git", "grep", "-l", "vuln-code-snippet vuln-line"], cwd=root, capture_output=True,
                           text=True, check=False).stdout.split()
    marks = defaultdict(list)
    for path in files:
        if "codefixes" in path:
            continue
        for n, line in enumerate((root / path).read_text(errors="replace").splitlines(), 1):
            if match := SNIPPET_RE.search(line):
                for challenge in match[1].split():
                    marks[challenge].append((path, n))
    return marks


def score_snippets_mode(marks, categories, by_file):
    results, per_category = [], defaultdict(lambda: {"found": 0, "total": 0})
    for challenge, lines in sorted(marks.items()):
        near = [i for path, n in lines for i in by_file.get(path, []) if abs((i["line"] or 0) - n) <= NEARBY_LINES]
        category = categories.get(challenge, "?")
        per_category[category]["total"] += 1
        per_category[category]["found"] += bool(near)
        results.append({"challenge": challenge, "category": category, "lines": lines, "found": bool(near),
                        "by": sorted({f"{i['tool']}:{i['rule']}" for i in near})})
    found = sum(r["found"] for r in results)
    return {"overall": {"found": found, "total": len(results), "recall": round(found / len(results), 3)},
            "categories": dict(sorted(per_category.items())), "challenges": results}


def score_snippets(root, suite, issues):
    categories = {c["key"]: c.get("category", "?") for c in yaml.safe_load((root / suite["challenges"]).read_text())}
    marks = marked_lines(root)
    return {mode: score_snippets_mode(marks, categories, issues_by_file(issues, types))
            for mode, types in MODES.items()}


# --- CWE-labelled folders (SecurityEval style) -------------------------------------------------------------


CWE_DIR_RE = re.compile(r"CWE-(\d{1,5})")


def cwe_cases(root, suite):
    """Every file under test_dir/CWE-<n>/ (or a folder the suite maps to a CWE) is a vulnerable sample of it."""
    folders = suite.get("folders", {})
    extensions = tuple(suite.get("extensions", [".py"]))
    cases = []
    for path in sorted((root / suite["test_dir"]).glob("*/*")):
        if not path.name.endswith(extensions):
            continue
        match = CWE_DIR_RE.fullmatch(path.parent.name)
        cwe = int(match[1]) if match else folders.get(path.parent.name)
        if cwe:
            cases.append({"path": path.relative_to(root).as_posix(), "cwe": cwe})
    return cases


def score_cwe_mode(cases, by_file, parents):
    per_cwe, results = defaultdict(lambda: {"found": 0, "total": 0}), []
    for case in cases:
        findings = by_file.get(case["path"], [])
        hit = flagged(case, findings, parents)
        per_cwe[case["cwe"]]["total"] += 1
        per_cwe[case["cwe"]]["found"] += hit
        results.append({**case, "found": hit, "any_security": bool(findings),
                        "by": sorted({f"{i['tool']}:{i['rule']}" for i in findings})})
    found = sum(r["found"] for r in results)
    flagged_any = sum(r["any_security"] for r in results)
    return {"overall": {"found": found, "total": len(results), "recall": round(found / len(results), 3),
                        "any_security": round(flagged_any / len(results), 3)},
            "categories": {f"CWE-{k}": v for k, v in sorted(per_cwe.items())}, "cases": results}


def score_cwe_folders(root, suite, issues):
    parents = catalog.load()[1].get("cwe_parents", {})
    cases = cwe_cases(root, suite)
    return {mode: score_cwe_mode(cases, issues_by_file(issues, types), parents) for mode, types in MODES.items()}


# --- Labelled files (a CSV of CWE, file and a manual vulnerable/safe verdict) --------------------------------


def labelled_cases(root, suite):
    with open(root / suite["labels"], newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    cases = []
    for row in rows:
        verdict, match = row.get(suite["label_column"], "").strip(), CWE_DIR_RE.fullmatch(row["CWEID"].strip())
        path = f"{suite['test_dir']}/{row['CWEID'].strip()}/{row['SampleID'].strip()}"
        if verdict in ("0", "1") and match and (root / path).exists():
            cases.append({"path": path, "cwe": int(match[1]), "real": verdict == "1"})
    return cases


def score_labelled_mode(cases, by_file, parents):
    totals, per_cwe, mistakes = {"tp": 0, "fn": 0, "fp": 0, "tn": 0}, defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0}), []
    for case in cases:
        hit = flagged(case, by_file.get(case["path"], []), parents)
        key = ("tp" if hit else "fn") if case["real"] else ("fp" if hit else "tn")
        totals[key] += 1
        per_cwe[f"CWE-{case['cwe']}"][key] += 1
        if case["real"] != hit:
            mistakes.append({**case, "flagged": hit,
                             "by": sorted({f"{i['tool']}:{i['rule']}" for i in by_file.get(case["path"], [])})})
    return {"overall": rates(totals), "categories": dict(sorted(per_cwe.items())), "mistakes": mistakes}


def score_labelled(root, suite, issues):
    parents = catalog.load()[1].get("cwe_parents", {})
    cases = labelled_cases(root, suite)
    return {mode: score_labelled_mode(cases, issues_by_file(issues, types), parents) for mode, types in MODES.items()}


SCORERS = {"owasp-benchmark": score_owasp, "vuln-snippets": score_snippets, "cwe-folders": score_cwe_folders,
           "labelled-files": score_labelled}


def run(names=None, log=print):
    suites = json.loads((ROOT / "suites.json").read_text())["suites"]
    out = {}
    for suite in suites:
        if names and suite["name"] not in names:
            continue
        log(f"== {suite['name']}: fetching {suite['commit'][:10]}")
        root = fetch(suite)
        issues = scan(root, log)
        (CACHE / f"{suite['name']}.issues.json").write_text(json.dumps(issues))
        scored = SCORERS[suite["kind"]](root, suite, issues)
        result = {**scored, "suite": suite["name"], "commit": suite["commit"],
                  "scanned_at": datetime.now(UTC).isoformat(timespec="seconds"),
                  "overall": {mode: scored[mode]["overall"] for mode in MODES}}
        write(suite, result)
        out[suite["name"]] = result
    return out


def write(suite, result):
    results_dir = ROOT / "results"
    results_dir.mkdir(exist_ok=True)
    (results_dir / f"{suite['name']}.json").write_text(json.dumps(result, indent=1) + "\n")
    (results_dir / f"{suite['name']}.md").write_text(render(suite, result))


def render_owasp(mode, r):
    o = r["overall"]
    return [f"## {mode.capitalize()} mode", "",
            (f"**Detection {o['tpr']:.0%}, false alarms {o['fpr']:.0%}, score {o['score']:+.0%}** "
             "(detection minus false alarms, averaged over categories)"), "",
            "| Category | CWE | Detected | Missed | False alarms | Correctly quiet | Detection | False alarms | Score |",
            "|---|---|---|---|---|---|---|---|---|",
            *(f"| {name} | {c['cwe']} | {c['tp']} | {c['fn']} | {c['fp']} | {c['tn']} | {c['tpr']:.0%} | "
              f"{c['fpr']:.0%} | {c['score']:+.0%} |" for name, c in r["categories"].items()), ""]


def render_snippets(mode, r):
    o = r["overall"]
    return [f"## {mode.capitalize()} mode", "",
            f"**{o['found']} of {o['total']} vulnerable challenges flagged ({o['recall']:.0%})**", "",
            "| Category | Flagged | Challenges |", "|---|---|---|",
            *(f"| {k} | {v['found']} | {v['total']} |" for k, v in r["categories"].items()), "",
            "| Challenge | Category | Flagged by |", "|---|---|---|",
            *(f"| {c['challenge']} | {c['category']} | {', '.join(c['by']) or 'missed'} |" for c in r["challenges"]),
            ""]


def render_cwe(mode, r):
    o = r["overall"]
    return [f"## {mode.capitalize()} mode", "",
            (f"**{o['found']} of {o['total']} vulnerable files flagged for their CWE ({o['recall']:.0%}); "
             f"{o['any_security']:.0%} have some security finding**"), "",
            "| CWE | Flagged | Files |", "|---|---|---|",
            *(f"| {k} | {v['found']} | {v['total']} |" for k, v in r["categories"].items()), ""]


def render_labelled(mode, r):
    o = r["overall"]
    return [f"## {mode.capitalize()} mode", "",
            (f"**Detection {o['tpr']:.0%} ({o['tp']} of {o['tp'] + o['fn']} vulnerable files), false alarms "
             f"{o['fpr']:.0%} ({o['fp']} of {o['fp'] + o['tn']} safe files)**"), "",
            "| CWE | Detected | Missed | False alarms | Correctly quiet |", "|---|---|---|---|---|",
            *(f"| {k} | {v['tp']} | {v['fn']} | {v['fp']} | {v['tn']} |" for k, v in r["categories"].items()), ""]


RENDERERS = {"owasp-benchmark": render_owasp, "vuln-snippets": render_snippets, "cwe-folders": render_cwe,
             "labelled-files": render_labelled}


def render(suite, result):
    lines = [f"# {suite['name']}", "", suite["about"], "",
             f"Commit `{suite['commit'][:10]}` ({suite['license']}), scanned {result['scanned_at']}.", "",
             "Verdict mode counts only findings that claim a vulnerability; review mode adds security hotspots.", ""]
    renderer = RENDERERS[suite["kind"]]
    for mode in MODES:
        lines += renderer(mode, result[mode])
    return "\n".join(lines) + "\n"
