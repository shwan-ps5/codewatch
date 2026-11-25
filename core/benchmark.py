"""Benchmarks: scan third-party code with published ground truth and score what codewatch catches.

Suites are listed in benchmarks/suites.json, fetched at a pinned commit into the cache directory, scanned
(never executed) and scored. Results go to benchmarks/results/<suite>.json and .md.
"""
import ast
import csv
import json
import multiprocessing
import os
import re
import subprocess
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path

import yaml

from . import catalog
from .analyzers import php_template_sinks
from .analyzers.base import python_tree
from .analyzers.template_sinks import TEMPLATE_EXTENSIONS, TEMPLATE_RULE, XSS_RULE, template_name
from .collect import ScanConfig, ScanInput, collect

ROOT = Path(__file__).resolve().parents[1] / "benchmarks"
CACHE = Path(os.environ.get("CODEWATCH_CACHE", Path.home() / ".cache" / "codewatch")) / "benchmarks"
SECURITY_TYPES = {"vulnerability", "security_hotspot"}
# Not about the code under test: dependency audits, live pages, coverage import, duplication.
SKIPPED_ANALYZERS = ["pip-audit", "osv", "axe", "coverage", "jscpd"]
# Scans run in parallel by default from the command line (devtools bench, codewatch benchmark): each suite or CVE
# case is its own process. A third of the CPUs, since each Semgrep run also uses several; memory is about 1-3 GB a run.
WORKERS = int(os.environ.get("CODEWATCH_BENCH_WORKERS") or max(1, (os.cpu_count() or 2) // 3))
SNIPPET_RE = re.compile(r"vuln-code-snippet vuln-line ([\w ]{1,500})")
NEARBY_LINES = 3


def git(*args, cwd):
    # errors="replace": a diff of a file that isn't UTF-8 (TBDev GHSA-88jc's Windows-1251 page) failed the case.
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True,
                          errors="replace").stdout


BEFORE, AFTER = "before", "after"
FETCH, GAVE_UP, CVE_PAIRS = "fetch", "gave_up", "cve-pairs"
ANY_FILE = "*"  # Semgrep gave up on some file it didn't name


def lenient_text(path):
    """A file's text, undecodable bytes replaced (a checkout's files needn't be UTF-8)."""
    return path.read_text(errors="replace")


def file_text(path):
    return lenient_text(path) if path.is_file() else ""


def tracked(root, paths):
    """The checkout's tracked files under paths (all of them for none)."""
    return git("ls-files", "-z", "--", *paths, cwd=root).split("\0")


def cwe_parents():
    return catalog.load()[1].get("cwe_parents", {})


def case_scope(case):
    return case.get("scope", [])


def fetch(suite):
    target = CACHE / suite["name"]
    target.mkdir(parents=True, exist_ok=True)
    if not (target / ".git").exists():
        git("init", "-q", cwd=target)
    git(FETCH, "-q", "--depth", "1", suite["repo"], suite["commit"], cwd=target)
    git("checkout", "-q", "--force", "FETCH_HEAD", cwd=target)
    return target


def timing(log, label, seconds, parts=None, gave_up=False):
    """Logs one line per fetch or scan: "timing", suite, case ("-" for a whole-repository suite), phase, seconds, then
    its parts' seconds, slowest first (each analyzer, and "prep" for the template renderers and importers looked up
    before them), and whether Semgrep gave up on some files. devtools.py bench writes them to
    $CODEWATCH_BENCH_TIMINGS."""
    parts = [f"{name}={sec:.0f}" for name, sec in sorted((parts or {}).items(), key=lambda kv: -kv[1]) if sec >= 1]
    log("\t".join(["timing", *label, f"{seconds:.0f}", " ".join(parts + ([GAVE_UP] if gave_up else []))]))


def fetch_and_scan(suite, log):
    """A whole-repository suite's checkout and issues, with the time of each logged."""
    start = time.monotonic()
    root = fetch(suite)
    timing(log, (suite["name"], "-", FETCH), time.monotonic() - start)
    start, tools = time.monotonic(), {}
    issues, gave_up = scan_and_gave_up(root, log, tools=tools)
    timing(log, (suite["name"], "-", "scan"), time.monotonic() - start, tools, gave_up=gave_up)
    return root, issues


def scan(root, log, paths=(), focus=None):
    return scan_and_gave_up(root, log, paths, focus)[0]


def scan_and_gave_up(root, log, paths=(), focus=None, tools=None):
    """The scan's issues, and the files Semgrep gave up on some rules in ([] when none; [ANY_FILE] when it said so
    without naming them). tools, when given, is filled with each analyzer's seconds."""
    files = [f for f in tracked(root, paths) if f]
    cfg = ScanConfig(disabled_analyzers=SKIPPED_ANALYZERS, custom_rules=catalog.custom_semgrep_rules())
    out = collect(cfg, ScanInput(root, files, "benchmark", focus=focus), log)
    if tools is not None:
        tools.update({name: tool.get("seconds") or 0 for name, tool in out["tools"].items()})
    # A suite scored without Semgrep would look like a run of misses and quiet fixed code.
    if (semgrep := out["tools"].get("semgrep", {})).get("status") == "error":
        raise RuntimeError(f"semgrep failed on {root}: {semgrep['detail']}")
    if semgrep.get("detail"):
        log(f"  {root}: {semgrep['detail']}")
    return out["issues"], semgrep.get("gave_up") or ([ANY_FILE] if semgrep.get("detail") else [])


def related(a, b, parents):
    """Same weakness, or one is an ancestor of the other in MITRE's hierarchy (e.g. CWE-327 and CWE-328)."""
    return a == b or a in catalog.ancestors(b, parents) or b in catalog.ancestors(a, parents)


# Rules built at scan time, which have no catalogue entry of their own: scored with the CWEs of the rule they copy.
DERIVED_RULES = {TEMPLATE_RULE: XSS_RULE, php_template_sinks.TEMPLATE_RULE: php_template_sinks.XSS_RULE}


def issue_cwes(issue):
    """CWEs of the rule, and of every other rule that reported the same finding before it was merged."""
    cwes = set()
    for tool, rule in [(issue["tool"], issue["rule"]),
                       *(s.split(":", 1) for s in issue.get("also_reported_by") or [] if ":" in s)]:
        entry = catalog.lookup(tool, DERIVED_RULES.get(rule, rule))
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
    parents = cwe_parents()
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
        for n, line in enumerate(lenient_text(root / path).splitlines(), 1):
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
    parents = cwe_parents()
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


def cwe_of_dir(name):
    """The CWE number of a seed directory name such as CWE-089."""
    found = CWE_DIR_RE.fullmatch(name)
    if not found:
        raise ValueError(f"not a CWE directory name: {name!r}")
    return int(found[1])


def seed_cases(root, suite):
    """Seed files from a ground-truth YAML ({seeds: [{file, cwe}]}) plus clean controls that must stay quiet."""
    truth = yaml.safe_load((root / suite["ground_truth"]).read_text())
    cases = [{"path": f"{suite['test_dir']}/{seed['file']}", "cwe": cwe_of_dir(seed["cwe"]), "real": True}
             for seed in truth["seeds"]]
    cases += [{"path": f"{suite['test_dir']}/{p.name}", "cwe": None, "real": False}
              for p in sorted((root / suite["test_dir"]).glob(suite["clean_glob"]))]
    return cases


def score_seeds(root, suite, issues):
    parents = cwe_parents()
    cases = seed_cases(root, suite)
    return {mode: score_labelled_mode(cases, issues_by_file(issues, types), parents) for mode, types in MODES.items()}


def score_labelled(root, suite, issues):
    parents = cwe_parents()
    cases = labelled_cases(root, suite)
    return {mode: score_labelled_mode(cases, issues_by_file(issues, types), parents) for mode, types in MODES.items()}


# --- CVE fix pairs: the commit before a published fix (vulnerable) and the fix itself ------------------------


SOURCE_EXTENSIONS = {"python": (".py",), "javascript": (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")}
# A Python web app's own templates and front-end scripts (cve-pairs-python-frontend).
SOURCE_EXTENSIONS["python-web"] = (*SOURCE_EXTENSIONS["python"], *SOURCE_EXTENSIONS["javascript"],
                                   ".vue", ".html", ".htm", ".jinja", ".jinja2", ".j2")
# PHP apps and CMSs: their code, templates (Twig, Smarty, Latte, Blade is .blade.php) and the JS they ship.
SOURCE_EXTENSIONS["php"] = (".php", ".phtml", ".ctp", ".inc", ".module", ".install", ".theme", ".twig", ".tpl", ".latte",
                            *SOURCE_EXTENSIONS["javascript"], ".vue", ".html", ".htm")
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
    # Every time, so a scope widened in suites.json reaches a clone made before (SQLBot GHSA-fghj: its request model
    # sat outside the first scope).
    if case_scope(case):
        # --skip-checks: a folder named like a pattern, such as Next.js's `[[...path]]` (Postiz GHSA-2p7p), is
        # refused without it, and that refusal once stopped a whole night's suites.
        git("sparse-checkout", "set", "--skip-checks", *case_scope(case), cwd=target)
    else:
        git("sparse-checkout", "disable", cwd=target)
    git(FETCH, "-q", "--depth", "2", "--filter=blob:none", "origin", case["fix"], cwd=target)
    return target, git("rev-parse", f"{case['fix']}^", cwd=target).strip()


def span(start, count):
    """Lines a hunk side covers; a pure insertion or deletion (count 0) is the gap after line `start`."""
    start, count = int(start), int(count or 1)
    return (max(start, 1), start + 1) if count == 0 else (start, start + count - 1)


def hunk_spots(match, old, new):
    """(side, path, (first, last)) for both sides of a hunk header."""
    return ((BEFORE, old, span(*match.group(1, 2))), (AFTER, new, span(*match.group(3, 4))))


def diff_path(line, prefix):
    """The path of a ---/+++ line, or None for /dev/null."""
    return line[6:] if line.startswith(prefix) else None


def fix_spots(diff, extensions):
    """{"before": {path: [(first, last)]}, "after": ...} for non-test source files changed by the fix."""
    spots = {BEFORE: defaultdict(list), AFTER: defaultdict(list)}
    old = new = None
    for line in diff.splitlines():
        if line.startswith("--- "):
            old = diff_path(line, "--- a/")
        elif line.startswith("+++ "):
            new = diff_path(line, "+++ b/")
        elif match := HUNK_RE.match(line):
            for side, path, lines in hunk_spots(match, old, new):
                if path and path.endswith(extensions) and not TEST_PATH_RE.search(path):
                    spots[side][path].append(lines)
    return {side: dict(paths) for side, paths in spots.items()}


# The calls that render a template by name, as template_sinks' patterns see them: the template is the first argument
# of render_template/render_to_string and the second of Django's render/TemplateResponse (after the request).
RENDER_CALLS = {"render_template": 0, "render_to_string": 0, "render": 1, "TemplateResponse": 1}


def changed_templates(diff):
    """Names (as a view gives them, template_sinks.template_name) of the non-test templates a fix changed."""
    names = set()
    for line in diff.splitlines():
        if line.startswith(("--- a/", "+++ b/")):
            path = line[6:]
            if path.endswith(tuple(TEMPLATE_EXTENSIONS)) and not TEST_PATH_RE.search(path):
                names.add(template_name(path))
    return names


def rendered_template(node):
    """The template argument of a render call (render_template(x), render(request, x)), or None."""
    if not isinstance(node, ast.Call):
        return None
    func = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", None)
    if func not in RENDER_CALLS:
        return None
    index = RENDER_CALLS[func]
    return node.args[index] if len(node.args) > index else next(
        (k.value for k in node.keywords if k.arg in ("template_name", "template_name_or_list")), None)


def render_spans(text, names):
    """[(first, last)] lines of the calls in a Python file's text that render one of the named templates."""
    if not any(name in text for name in names):
        return []
    tree = python_tree(text)
    if tree is None:
        return []
    return sorted((node.lineno, node.end_lineno or node.lineno) for node in ast.walk(tree)
                  if isinstance(arg := rendered_template(node), ast.Constant) and arg.value in names)


def template_renderers(root, paths, names):
    """{python file: [render call spans]} for the files in the checkout that render a changed template by name."""
    if not names:
        return {}
    found = {}
    for path in tracked(root, paths):
        if (path.endswith(".py") and not TEST_PATH_RE.search(path) and (root / path).is_file()
                and (spans := render_spans(lenient_text(root / path), names))):
            found[path] = spans
    return found


def importers(root, paths, changed):
    """Python files in the checkout that import a changed Python module (summaries.visible): a fix inside a helper
    removes the finding at its caller (Dagster GHSA-q93c: the containment check went into the log manager, the
    FileResponse is in the webserver). Their findings count only when the fix makes them go away."""
    from .analyzers.summaries import visible

    modules = {c for c in changed if c.endswith(".py")}
    if not modules:
        return set()
    found = set()
    for path in tracked(root, paths):
        if (path.endswith(".py") and path not in modules and not TEST_PATH_RE.search(path) and (root / path).is_file()
                and visible(path, modules, lambda rel: lenient_text(root / rel))):
            found.add(path)
    return found


PHP_KEY_RE = re.compile(r"template variable ['\"](\w+)['\"]")
PHP_NAME_RE = re.compile(r"\(template ['\"]([^'\"]+)['\"]\)")


def changed_php_templates(root, changed):
    """{path: (template kind, text)} for the changed files that are templates."""
    templates = {}
    for path in changed:
        text = file_text(root / path)
        if (kind := php_template_sinks.kind(path, text)) is not None:
            templates[path] = (kind, text)
    return templates


def renders_changed(issue, templates, raw):
    """A template-rule finding setting a variable a changed template prints unescaped, through a call naming that
    template or naming none."""
    if issue["rule"] != php_template_sinks.TEMPLATE_RULE or not (key := PHP_KEY_RE.search(issue.get("message") or "")):
        return False
    name = PHP_NAME_RE.search(issue["message"])
    return any(key.group(1) in raw[path]
               and (name is None or name.group(1) in php_template_sinks.names(path, templates[path][0]))
               for path in templates)


def php_template_renders(root, changed, found):
    """{path: [(line, line)]} of the PHP template rule's findings that set a variable one of the changed templates
    prints unescaped, through a call naming that template or (Smarty's assign(), CakePHP's set()) naming none: a fix
    in the template removes the finding at the controller, in a file the fix didn't change (oc-server3 GHSA-w8rr)."""
    templates = changed_php_templates(root, changed)
    if not templates:
        return {}
    joined = "\n".join(text for path, (_, text) in templates.items() if path.endswith(".php"))
    settings = {"twig_off": bool(php_template_sinks.TWIG_OFF_RE.search(joined)), "smarty_escapes": False}
    raw = {path: php_template_sinks.raw_variables(text, kind, settings) for path, (kind, text) in templates.items()}
    renders = {}
    for i in (i for i in found if renders_changed(i, templates, raw)):
        renders.setdefault(i["path"], []).append((i["line"], i["line"]))
    return renders


PHP_CALLER_SUFFIXES = (".php", ".ctp", ".phtml", ".inc", ".module", ".tpl")


def printed_variable_words(root, changed):
    """How a PHP file would name a variable the changed templates print unescaped: 'x', "x" or ->x =."""
    words = set()
    for kind, text in changed_php_templates(root, changed).values():
        variables = php_template_sinks.raw_variables(text, kind, {"twig_off": True, "smarty_escapes": False})
        words |= {f"'{v}'" for v in variables} | {f'"{v}"' for v in variables} | {f"->{v} =" for v in variables}
    return words


def php_template_callers(root, paths, changed):
    """PHP files in the checkout that might set a variable a changed template prints unescaped: they name the
    template, or quote the variable (assign('x', ...), set('x', ...)). The focus of the scan, so the template
    rule's finding at the controller is seen."""
    words = printed_variable_words(root, changed)
    if not words:
        return set()
    candidates = (path for path in tracked(root, paths) if path.endswith(PHP_CALLER_SUFFIXES)
                  and path not in changed and not TEST_PATH_RE.search(path) and (root / path).is_file())
    return {path for path in candidates if any(w in lenient_text(root / path) for w in words)}


def at_render(issue, renders):
    """A finding of the template rule inside a call that renders a changed template."""
    return issue["rule"] in (TEMPLATE_RULE, php_template_sinks.TEMPLATE_RULE) and any(
        first <= (issue["line"] or 0) <= last for first, last in renders.get(issue["path"], ()))


def with_code(root, issues):
    """Each finding with its stripped source line, so the same finding can be recognised on both sides of a fix."""
    lines = {}
    for i in issues:
        if i["path"] not in lines:
            path = root / i["path"]
            lines[i["path"]] = file_text(path).splitlines()
        text = lines[i["path"]]
        i["code"] = text[i["line"] - 1].strip() if i["line"] and i["line"] <= len(text) else ""
    return issues


def scan_side(suite, case, checkout, known, log):
    """One side of a fix pair: the security findings in the changed files, at the calls that render a changed
    template, and in the changed modules' importers. checkout: (root, side, commit); known: (spots, templates)."""
    (root, side, commit), (spots, templates) = checkout, known
    start, tools = time.monotonic(), {}
    git("checkout", "-q", "--force", commit, cwd=root)
    renders = spots["renders"][side] = template_renderers(root, case_scope(case), templates)
    callers = importers(root, case_scope(case), set(spots[side]))
    # A PHP template's unescaped variable is set in a controller the fix may not touch.
    php_callers = (php_template_callers(root, case_scope(case), set(spots[side]))
                   if suite["language"] == "php" else set())
    prep = time.monotonic() - start
    # Only findings in the changed files (and those render calls, and the changed modules' importers) are
    # scored, so Semgrep's per-file pass looks only at those files.
    found, spots[GAVE_UP][side] = scan_and_gave_up(root, log, case_scope(case),
                                                    focus=sorted({*spots[side], *renders, *callers, *php_callers}),
                                                    tools=tools)
    if suite["language"] == "php":
        renders = spots["renders"][side] = php_template_renders(root, set(spots[side]), found)
    timing(log, (suite["name"], case["id"], side), time.monotonic() - start, {"prep": prep, **tools},
           spots[GAVE_UP][side])
    found = [i for i in found if i["type"] in SECURITY_TYPES]
    return with_code(root, [i for i in found if i["path"] in spots[side] or at_render(i, renders)
                            or i["path"] in callers])


def scan_pair(suite, case, log):
    start = time.monotonic()
    root, parent = fetch_pair(suite, case)
    timing(log, (suite["name"], case["id"], FETCH), time.monotonic() - start)
    diff = git("diff", "-U0", "--no-renames", parent, case["fix"], cwd=root)
    spots: dict = fix_spots(diff, SOURCE_EXTENSIONS[suite["language"]])
    # A fix in a template (dropping |safe) leaves the finding at the Python call that renders it, in a file the
    # fix didn't change: those calls are scored too, for the template rule only.
    templates = changed_templates(diff) if suite["language"].startswith("python") else set()
    spots["renders"], spots[GAVE_UP] = {}, {}
    sides = {side: scan_side(suite, case, (root, side, commit), (spots, templates), log)
             for side, commit in ((BEFORE, parent), (AFTER, case["fix"]))}
    return spots, sides


def near(issue, spans):
    return any(first - NEARBY_LINES <= (issue["line"] or 0) <= last + NEARBY_LINES for first, last in spans)


def relevant_issues(issues, types, case, parents):
    """The findings of the given types for the advisory's weakness (or a related one)."""
    return [i for i in issues if i["type"] in types
            and any(related(c, w, parents) for c in issue_cwes(i) for w in case["cwe"])]


def issue_key(issue):
    return issue["path"], issue["rule"], issue["code"]


def at_spot(issue, spots, side):
    return near(issue, spots[side].get(issue["path"], ())) or at_render(issue, spots.get("renders", {}).get(side, {}))


def rule_lines(issues):
    return sorted({f"{i['tool']}:{i['rule']}@{i['line']}" for i in issues})


def gave_up_files(flag):
    """A side's gave-up record as a set of paths: a bare True (results from before 2026-11-25) names no file."""
    return set(flag) if isinstance(flag, (list, tuple, set)) else ({ANY_FILE} if flag else set())


def complete_for(issue, spots):
    """Whether the fixed side's scan can be trusted to have kept this finding had it still been there. Semgrep
    giving up on a file under load (the 2026-11-07 nightly, mlflow GHSA-wqmh) drops its findings there without an
    error, and a summary pass giving up drops what its functions hand on. So: no giving up on the fixed side, or
    only on files the vulnerable side gave up on too (the same handicap on both sides, which the vulnerable side
    found the finding despite) and not on the finding's own file (clawmetry da1d1d8fd021: 29 unrelated files on
    both sides hid the finding its fix removes)."""
    after = gave_up_files(spots.get(GAVE_UP, {}).get(AFTER))
    if not after:
        return True
    before = gave_up_files(spots.get(GAVE_UP, {}).get(BEFORE))
    return ANY_FILE not in after and after <= before and issue["path"] not in after


def hits_and_still(before, after, spots):
    """(findings that detect the advisory, findings still there after its fix)."""
    after_keys = {issue_key(i) for i in after}
    # A finding the fix makes go away counts only when the fixed side's scan was complete for it.
    hits = [i for i in before if at_spot(i, spots, BEFORE) or (complete_for(i, spots) and issue_key(i) not in after_keys)]
    hit_keys = {issue_key(i) for i in hits}
    return hits, [i for i in after if issue_key(i) in hit_keys or at_spot(i, spots, AFTER)]


def score_pair(case, spots, sides, types, parents):
    """Detected: a finding of the advisory's weakness at the fixed spot, or one the fix makes go away. Still
    flagged (a false alarm on fixed code): such a finding survives the fix, or a new one appears at the fix."""
    before = relevant_issues(sides[BEFORE], types, case, parents)
    after = relevant_issues(sides[AFTER], types, case, parents)
    hits, still = hits_and_still(before, after, spots)
    gave_up = sorted(side for side, flag in spots.get(GAVE_UP, {}).items() if flag)
    return {"id": case["id"], "repo": case["repo"], "cwe": case["cwe"], **({GAVE_UP: gave_up} if gave_up else {}),
            "detected": bool(hits), "still_flagged": bool(still), "by": rule_lines(hits), "still_by": rule_lines(still)}


def score_pairs_mode(cases, scanned, types, parents):
    totals, per_cwe, results = {"tp": 0, "fn": 0, "fp": 0, "tn": 0}, defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0}), []
    for case in cases:
        spots, sides = scanned[case["id"]]
        r = score_pair(case, spots, sides, types, parents)
        for key in ("tp" if r["detected"] else "fn", "fp" if r["still_flagged"] else "tn"):
            totals[key] += 1
            per_cwe[f"CWE-{case['cwe'][0]}"][key] += 1
        results.append(r)
    return {"overall": rates(totals), "categories": dict(sorted(per_cwe.items())), "cases": results}


def score_cve_pairs(suite, log):
    scanned = {}
    for case in suite["cases"]:
        log(f"   {case['id']}: {case['repo']} {case['fix'][:10]}")
        scanned[case["id"]] = scan_pair_or_none(suite, case, log)
    return score_scanned_pairs(suite, scanned)


def scan_pair_or_none(suite, case, log):
    """scan_pair, or None (logged as a failure) when fetching or scanning the case fails: one case that can't be
    fetched shouldn't stop every other suite of the night."""
    try:
        return scan_pair(suite, case, log)
    except Exception as error:  # noqa: BLE001 - any failure of one case is reported and the run goes on
        detail = getattr(error, "stderr", "") or ""
        log(f"   {case['id']}: scan failed: {error} {detail.strip()}".rstrip())
        return None


def score_scanned_pairs(suite, scanned):
    """Scores of the cases that were scanned; a case whose scan failed (None) is left out of this run's scores."""
    parents = cwe_parents()
    scanned = {case_id: pair for case_id, pair in scanned.items() if pair is not None}
    cases = [case for case in suite["cases"] if case["id"] in scanned]
    (CACHE / f"{suite['name']}.issues.json").write_text(json.dumps(scanned))
    return {mode: score_pairs_mode(cases, scanned, types, parents) for mode, types in MODES.items()}


SCORERS = {"owasp-benchmark": score_owasp, "vuln-snippets": score_snippets, "cwe-folders": score_cwe_folders,
           "labelled-files": score_labelled, "seed-files": score_seeds}


def run_suite(suite, log):
    if suite["kind"] == CVE_PAIRS:
        log(f"== {suite['name']}: {len(suite['cases'])} fix commits")
        return score_cve_pairs(suite, log)
    log(f"== {suite['name']}: fetching {suite['commit'][:10]}")
    return score_scanned_suite(suite, *fetch_and_scan(suite, log))


def score_scanned_suite(suite, root, issues):
    (CACHE / f"{suite['name']}.issues.json").write_text(json.dumps(issues))
    return SCORERS[suite["kind"]](root, suite, issues)


def setup_worker(workers=1):
    """A parallel run's process: Django, and its share of the CPUs for Semgrep."""
    os.environ["CODEWATCH_SEMGREP_JOBS"] = str(max(1, (os.cpu_count() or 2) // workers))
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "codewatch.settings")
    import django  # only in a worker process, which starts without Django

    django.setup()


def scan_job(suite, case=None):
    """One unit of a parallel run: a whole suite, or one CVE case. Returns its scan and the log lines."""
    lines = []
    if case is None:
        lines.append(f"== {suite['name']}: fetching {suite['commit'][:10]}")
        root, issues = fetch_and_scan(suite, lines.append)
        return suite["name"], None, (str(root), issues), lines
    lines.append(f"   {suite['name']} {case['id']}: {case['repo']} {case['fix'][:10]}")
    return suite["name"], case["id"], scan_pair_or_none(suite, case, lines.append), lines


def parallel_jobs(suites):
    """(suite, None) for a whole-repository suite and (suite, case) for each CVE case."""
    return ([(suite, None) for suite in suites if suite["kind"] != CVE_PAIRS]
            + [(suite, case) for suite in suites if suite["kind"] == CVE_PAIRS for case in suite["cases"]])


def scan_parallel(suites, log, workers):
    """{suite name: (root, issues) or {case id: pair}}, every suite and CVE case scanned in its own process."""
    jobs = parallel_jobs(suites)
    scanned: dict = {suite["name"]: {} for suite in suites if suite["kind"] == CVE_PAIRS}
    # spawn: a worker starts clean rather than forking a process that may hold threads or open connections.
    with ProcessPoolExecutor(workers, mp_context=multiprocessing.get_context("spawn"),
                             initializer=setup_worker, initargs=(workers,)) as pool:
        for future in as_completed([pool.submit(scan_job, suite, case) for suite, case in jobs]):
            name, case_id, result, lines = future.result()
            for line in lines:
                log(line)
            if case_id is None:
                scanned[name] = result
            else:
                scanned[name][case_id] = result
    return scanned


def chosen_cases(ids):
    """The open CVE suites, each with only its cases whose id starts with one of ids; suites left with none dropped."""
    suites = [suite for suite in json.loads((ROOT / "suites.json").read_text())["suites"]
              if suite["kind"] == CVE_PAIRS and not suite.get("blind")]
    chosen = [{**suite, "cases": [c for c in suite["cases"] if c["id"].startswith(tuple(ids))]} for suite in suites]
    return [suite for suite in chosen if suite["cases"]]


def score_cases(ids, log=print, workers=1):
    """Scan only the CVE cases whose id starts with one of ids (from suites that aren't blind) and score each,
    without writing results: a quick check of the cases a rule change is meant to move. Returns
    [(suite name, {mode: case result})]. A case whose scan fails is logged and left out, as in run()."""
    chosen = chosen_cases(ids)
    workers = max(1, min(workers, sum(len(suite["cases"]) for suite in chosen)))
    scanned = scan_parallel(chosen, log, workers) if workers > 1 else {
        suite["name"]: {case["id"]: scan_pair_or_none(suite, case, log) for case in suite["cases"]} for suite in chosen}
    parents = cwe_parents()
    pairs = [(suite["name"], case, scanned[suite["name"]].get(case["id"])) for suite in chosen for case in suite["cases"]]
    return [(name, {mode: score_pair(case, pair[0], pair[1], types, parents) for mode, types in MODES.items()})
            for name, case, pair in pairs if pair is not None]


def selected_suites(names):
    """The named suites, or every suite except blind and deferred ones."""
    return [suite for suite in json.loads((ROOT / "suites.json").read_text())["suites"]
            if not ((names and suite["name"] not in names)
                    or (not names and (suite.get("blind") or suite.get("deferred"))))]


def scored_suite(suite, scanned, log):
    """A suite's scores, from its parallel scan when there is one."""
    if suite["name"] not in scanned:
        return run_suite(suite, log)
    if suite["kind"] == CVE_PAIRS:
        # In the suite's order, as a sequential run writes them.
        return score_scanned_pairs(suite, {c["id"]: scanned[suite["name"]][c["id"]] for c in suite["cases"]})
    root, issues = scanned[suite["name"]]
    return score_scanned_suite(suite, Path(root), issues)


def run(names=None, log=print, workers=1):
    """Score the named suites, or every suite except blind and deferred ones, which run only when named (a deferred
    suite is ground truth kept for rules that don't exist yet, such as PHP's). With workers > 1 the scans run in
    that many processes; scoring and the order of the results are the same."""
    suites = selected_suites(names)
    scanned = scan_parallel(suites, log, workers) if workers > 1 else {}
    out = {}
    for suite in suites:
        scored = scored_suite(suite, scanned, log)
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
             "labelled-files": render_labelled, "seed-files": render_labelled, CVE_PAIRS: render_pairs}


def render(suite, result):
    pinned = (f"Commit `{suite['commit'][:10]}` ({suite['license']})" if "commit" in suite
              else "Fix commits and licenses pinned per case in `benchmarks/suites.json`")
    lines = [f"# {suite['name']}", "", suite["about"], "", f"{pinned}, scanned {result['scanned_at']}.", "",
             "Verdict mode counts only findings that claim a vulnerability; review mode adds security hotspots.", ""]
    renderer = RENDERERS[suite["kind"]]
    for mode in MODES:
        lines += renderer(mode, result[mode])
    return "\n".join(lines) + "\n"


def parse_timings(lines):
    """The `timing` lines a bench run wrote (without their "timing" word), as dicts."""
    rows = []
    for line in lines:
        fields = line.rstrip("\n").split("\t")
        if len(fields) < 4:
            continue
        extra = fields[4].split() if len(fields) > 4 else []
        rows.append({"suite": fields[0], "case": fields[1], "phase": fields[2], "seconds": float(fields[3]),
                     "parts": {k: float(v) for k, v in (p.split("=", 1) for p in extra if "=" in p)},
                     GAVE_UP: GAVE_UP in extra})
    return rows


def minutes(seconds):
    return f"{seconds / 60:.0f} min"


def summed(key, rows, part=False):
    """[(name, seconds)] summed per row[key], or per analyzer part, largest first."""
    totals = defaultdict(float)
    for row in rows:
        for name, seconds in (row["parts"].items() if part else [(row[key], row["seconds"])]):
            totals[name] += seconds
    return sorted(totals.items(), key=lambda kv: -kv[1])


def per_case(rows):
    totals = defaultdict(float)
    for row in rows:
        totals[row["suite"], row["case"]] += row["seconds"]
    return totals


def slowest(rows, top):
    lines = []
    for row in sorted((r for r in rows if r["phase"] != FETCH), key=lambda r: -r["seconds"])[:top]:
        parts = " ".join(f"{k}={v:.0f}" for k, v in list(row["parts"].items())[:4])
        lines.append(f"  {row['seconds']:.0f}s {row['suite']} {row['case']} {row['phase']} {parts}"
                     + (" gave_up" if row[GAVE_UP] else ""))
    return lines


def moved_cases(rows, before, top):
    """The cases whose time moved by half or more (and a minute) since the previous run."""
    now, then = per_case(rows), per_case(before)
    moved = sorted(((now[k] - then[k], k) for k in now.keys() & then.keys()
                    if abs(now[k] - then[k]) >= max(60, then[k] / 2)), key=lambda d: -abs(d[0]))
    return (["moved most since the previous run:" if moved else "no case's time moved by half or more"]
            + [f"  {then[k]:.0f}s -> {now[k]:.0f}s {k[0]} {k[1]}" for _, k in moved[:top]])


def timing_report(lines, previous=(), top=10):
    """Where a bench run's time went: per suite, per analyzer, the slowest scans, and (given the previous run's
    lines) the cases whose time moved most. Times are summed over the parallel processes and are wall time inside
    each, so they rise with the load of the other scans running beside them."""
    rows, before = parse_timings(lines), parse_timings(previous)
    total = sum(r["seconds"] for r in rows)
    fetching = sum(r["seconds"] for r in rows if r["phase"] == FETCH)
    out = [f"{minutes(total)} of scans summed over processes, {minutes(fetching)} of it fetching"
           + (f" (previous run {minutes(sum(r['seconds'] for r in before))})" if before else ""),
           "by suite: " + ", ".join(f"{name} {minutes(s)}" for name, s in summed("suite", rows)),
           "by analyzer: " + ", ".join(f"{name} {minutes(s)}" for name, s in summed(None, rows, part=True)[:8]),
           "slowest:", *slowest(rows, top)]
    if before:
        out += moved_cases(rows, before, top)
    return "\n".join(out)
