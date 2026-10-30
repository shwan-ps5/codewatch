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
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


def fetch(suite):
    target = CACHE / suite["name"]
    target.mkdir(parents=True, exist_ok=True)
    if not (target / ".git").exists():
        git("init", "-q", cwd=target)
    git("fetch", "-q", "--depth", "1", suite["repo"], suite["commit"], cwd=target)
    git("checkout", "-q", "--force", "FETCH_HEAD", cwd=target)
    return target


def scan(root, log, paths=()):
    files = [f for f in git("ls-files", "-z", "--", *paths, cwd=root).split("\0") if f]
    cfg = ScanConfig(disabled_analyzers=SKIPPED_ANALYZERS, custom_rules=catalog.custom_semgrep_rules())
    out = collect(cfg, ScanInput(root, files, "benchmark"), log)
    # A suite scored without Semgrep would look like a run of misses and quiet fixed code.
    if (semgrep := out["tools"].get("semgrep", {})).get("status") == "error":
        raise RuntimeError(f"semgrep failed on {root}: {semgrep['detail']}")
    return out["issues"]


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
    """The case counts as flagged if a security finding in its file maps to the expected CWE family; a clean
    control (no CWE) is flagged by any security finding."""
    if case["cwe"] is None:
        return bool(findings)
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
        per_cwe[f"CWE-{case['cwe']}" if case["cwe"] else "clean controls"][key] += 1
        if case["real"] != hit:
            mistakes.append({**case, "flagged": hit,
                             "by": sorted({f"{i['tool']}:{i['rule']}" for i in by_file.get(case["path"], [])})})
    return {"overall": rates(totals), "categories": dict(sorted(per_cwe.items())), "mistakes": mistakes}


def seed_cases(root, suite):
    """Seed files from a ground-truth YAML ({seeds: [{file, cwe}]}) plus clean controls that must stay quiet."""
    truth = yaml.safe_load((root / suite["ground_truth"]).read_text())
    cases = [{"path": f"{suite['test_dir']}/{seed['file']}", "cwe": int(CWE_DIR_RE.fullmatch(seed["cwe"])[1]),
              "real": True} for seed in truth["seeds"]]
    cases += [{"path": f"{suite['test_dir']}/{p.name}", "cwe": None, "real": False}
              for p in sorted((root / suite["test_dir"]).glob(suite["clean_glob"]))]
    return cases


def score_seeds(root, suite, issues):
    parents = catalog.load()[1].get("cwe_parents", {})
    cases = seed_cases(root, suite)
    return {mode: score_labelled_mode(cases, issues_by_file(issues, types), parents) for mode, types in MODES.items()}


def score_labelled(root, suite, issues):
    parents = catalog.load()[1].get("cwe_parents", {})
    cases = labelled_cases(root, suite)
    return {mode: score_labelled_mode(cases, issues_by_file(issues, types), parents) for mode, types in MODES.items()}


# --- CVE fix pairs: the commit before a published fix (vulnerable) and the fix itself ------------------------


SOURCE_EXTENSIONS = {"python": (".py",), "javascript": (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")}
TEST_PATH_RE = re.compile(r"(^|/)(tests?|__tests__|spec|e2e)/|(^|/)(test_[^/]*|[^/]*_test\.py|tests?\.py)$"
                          r"|\.(test|spec)\.[cm]?[jt]sx?$|\.d\.ts$")
HUNK_RE = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def fetch_pair(suite, case):
    """Fix commit and its parent, blobs fetched lazily; a case's scope limits the checkout to those folders."""
    target = CACHE / suite["name"] / case["id"]
    target.mkdir(parents=True, exist_ok=True)
    if not (target / ".git").exists():
        git("init", "-q", cwd=target)
        git("remote", "add", "origin", case["repo"], cwd=target)
        if case.get("scope"):
            git("sparse-checkout", "set", *case["scope"], cwd=target)
    git("fetch", "-q", "--depth", "2", "--filter=blob:none", "origin", case["fix"], cwd=target)
    return target, git("rev-parse", f"{case['fix']}^", cwd=target).strip()


def span(start, count):
    """Lines a hunk side covers; a pure insertion or deletion (count 0) is the gap after line `start`."""
    start, count = int(start), int(count or 1)
    return (max(start, 1), start + 1) if count == 0 else (start, start + count - 1)


def fix_spots(diff, extensions):
    """{"before": {path: [(first, last)]}, "after": ...} for non-test source files changed by the fix."""
    spots = {"before": defaultdict(list), "after": defaultdict(list)}
    old = new = None
    for line in diff.splitlines():
        if line.startswith("--- "):
            old = line[6:] if line.startswith("--- a/") else None
        elif line.startswith("+++ "):
            new = line[6:] if line.startswith("+++ b/") else None
        elif match := HUNK_RE.match(line):
            for side, path, (start, count) in (("before", old, match.group(1, 2)), ("after", new, match.group(3, 4))):
                if path and path.endswith(extensions) and not TEST_PATH_RE.search(path):
                    spots[side][path].append(span(start, count))
    return {side: dict(paths) for side, paths in spots.items()}


def with_code(root, issues):
    """Each finding with its stripped source line, so the same finding can be recognised on both sides of a fix."""
    lines = {}
    for i in issues:
        if i["path"] not in lines:
            path = root / i["path"]
            lines[i["path"]] = path.read_text(errors="replace").splitlines() if path.is_file() else []
        text = lines[i["path"]]
        i["code"] = text[i["line"] - 1].strip() if i["line"] and i["line"] <= len(text) else ""
    return issues


def scan_pair(suite, case, log):
    root, parent = fetch_pair(suite, case)
    spots = fix_spots(git("diff", "-U0", "--no-renames", parent, case["fix"], cwd=root),
                      SOURCE_EXTENSIONS[suite["language"]])
    sides = {}
    for side, commit in (("before", parent), ("after", case["fix"])):
        git("checkout", "-q", "--force", commit, cwd=root)
        found = [i for i in scan(root, log, case.get("scope", [])) if i["type"] in SECURITY_TYPES]
        sides[side] = with_code(root, [i for i in found if i["path"] in spots[side]])
    return spots, sides


def near(issue, spans):
    return any(first - NEARBY_LINES <= (issue["line"] or 0) <= last + NEARBY_LINES for first, last in spans)


def score_pair(case, spots, sides, types, parents):
    """Detected: a finding of the advisory's weakness at the fixed spot, or one the fix makes go away. Still
    flagged (a false alarm on fixed code): such a finding survives the fix, or a new one appears at the fix."""
    def relevant(side):
        return [i for i in sides[side] if i["type"] in types
                and any(related(c, w, parents) for c in issue_cwes(i) for w in case["cwe"])]

    def key(i):
        return i["path"], i["rule"], i["code"]

    before, after = relevant("before"), relevant("after")
    after_keys = {key(i) for i in after}
    hits = [i for i in before if near(i, spots["before"][i["path"]]) or key(i) not in after_keys]
    hit_keys = {key(i) for i in hits}
    still = [i for i in after if key(i) in hit_keys or near(i, spots["after"][i["path"]])]
    return {"id": case["id"], "repo": case["repo"], "cwe": case["cwe"], "detected": bool(hits),
            "still_flagged": bool(still), "by": sorted({f"{i['tool']}:{i['rule']}@{i['line']}" for i in hits}),
            "still_by": sorted({f"{i['tool']}:{i['rule']}@{i['line']}" for i in still})}


def score_pairs_mode(cases, scanned, types, parents):
    totals, per_cwe, results = {"tp": 0, "fn": 0, "fp": 0, "tn": 0}, defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0}), []
    for case in cases:
        r = score_pair(case, *scanned[case["id"]], types, parents)
        for key in ("tp" if r["detected"] else "fn", "fp" if r["still_flagged"] else "tn"):
            totals[key] += 1
            per_cwe[f"CWE-{case['cwe'][0]}"][key] += 1
        results.append(r)
    return {"overall": rates(totals), "categories": dict(sorted(per_cwe.items())), "cases": results}


def score_cve_pairs(suite, log):
    parents = catalog.load()[1].get("cwe_parents", {})
    scanned = {}
    for case in suite["cases"]:
        log(f"   {case['id']}: {case['repo']} {case['fix'][:10]}")
        scanned[case["id"]] = scan_pair(suite, case, log)
    (CACHE / f"{suite['name']}.issues.json").write_text(json.dumps(scanned))
    return {mode: score_pairs_mode(suite["cases"], scanned, types, parents) for mode, types in MODES.items()}


SCORERS = {"owasp-benchmark": score_owasp, "vuln-snippets": score_snippets, "cwe-folders": score_cwe_folders,
           "labelled-files": score_labelled, "seed-files": score_seeds}


def run_suite(suite, log):
    if suite["kind"] == "cve-pairs":
        log(f"== {suite['name']}: {len(suite['cases'])} fix commits")
        return score_cve_pairs(suite, log)
    log(f"== {suite['name']}: fetching {suite['commit'][:10]}")
    root = fetch(suite)
    issues = scan(root, log)
    (CACHE / f"{suite['name']}.issues.json").write_text(json.dumps(issues))
    return SCORERS[suite["kind"]](root, suite, issues)


def run(names=None, log=print):
    """Score the named suites, or every suite except blind ones, which run only when named."""
    suites = json.loads((ROOT / "suites.json").read_text())["suites"]
    out = {}
    for suite in suites:
        if (names and suite["name"] not in names) or (not names and suite.get("blind")):
            continue
        scored = run_suite(suite, log)
        result = {**scored, "suite": suite["name"], "commit": suite.get("commit", "per case"),
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


def render_pairs(mode, r):
    o = r["overall"]
    return [f"## {mode.capitalize()} mode", "",
            (f"**Detection {o['tpr']:.0%} ({o['tp']} of {o['tp'] + o['fn']} vulnerable commits), still flagged after "
             f"the fix {o['fpr']:.0%} ({o['fp']} of {o['fp'] + o['tn']})**"), "",
            "| Advisory | CWE | Vulnerable commit | Fixed commit |", "|---|---|---|---|",
            *(f"| {c['id']} | {', '.join(map(str, c['cwe']))} | {', '.join(c['by']) or 'missed'} | "
              f"{', '.join(c['still_by']) or 'quiet'} |" for c in r["cases"]), ""]


RENDERERS = {"owasp-benchmark": render_owasp, "vuln-snippets": render_snippets, "cwe-folders": render_cwe,
             "labelled-files": render_labelled, "seed-files": render_labelled, "cve-pairs": render_pairs}


def render(suite, result):
    pinned = (f"Commit `{suite['commit'][:10]}` ({suite['license']})" if "commit" in suite
              else "Fix commits and licenses pinned per case in `benchmarks/suites.json`")
    lines = [f"# {suite['name']}", "", suite["about"], "", f"{pinned}, scanned {result['scanned_at']}.", "",
             "Verdict mode counts only findings that claim a vulnerability; review mode adds security hotspots.", ""]
    renderer = RENDERERS[suite["kind"]]
    for mode in MODES:
        lines += renderer(mode, result[mode])
    return "\n".join(lines) + "\n"
