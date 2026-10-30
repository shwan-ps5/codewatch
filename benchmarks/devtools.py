"""Quick loops for rule work, without the server.

    venv/bin/python benchmarks/devtools.py bench [SUITE...]          # score suites (all by default), one line each
    venv/bin/python benchmarks/devtools.py rules SUBSTR FILE...      # one Semgrep pass of matching built-in rules
    venv/bin/python benchmarks/devtools.py repos [--via|--entry] DIR...
                                                                     # full Semgrep analyzer on git working copies
    venv/bin/python benchmarks/devtools.py owasp [CATEGORY...]      # OWASP Python cases scored wrong (verdict mode)
    venv/bin/python benchmarks/devtools.py sonar-only [NAME...]     # Sonar vulnerabilities with no codewatch
                                                                     # security finding within a line (after compare.py)

`rules` scans the same line-preserving rewritten copy of Python files that the analyzer does, but skips summaries;
`repos` runs everything (summaries, via-findings, entry-point hotspots) and prints vulnerabilities, or only
via-findings (--via) or only entry-point hotspots (--entry).
"""
import collections
import fnmatch
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "codewatch.settings")

import django

django.setup()

import yaml

from core import benchmark, catalog
from core.analyzers.base import Context, isolated_tool
from core.analyzers.multi_tools import Semgrep, analysis_copy
from core.collect import DEFAULT_EXCLUSIONS

HERE = Path(__file__).resolve().parent
CACHE = Path.home() / ".cache" / "codewatch"
ENTRY_MARK = "nothing in the project calls"


def bench(suites):
    out = benchmark.run(suites, log=lambda m: print(m) if "fail" in m else None)
    for name, r in out.items():
        print(name, "verdict", r["verdict"]["overall"], "review", r["review"]["overall"])


def rules(rule_filter, files):
    chosen = [r for r in yaml.safe_load(catalog.custom_semgrep_rules())["rules"] if rule_filter in r["id"]]
    with tempfile.TemporaryDirectory() as work:
        config = Path(work, "rules.yml")
        config.write_text(yaml.safe_dump({"rules": chosen}))
        targets, back = [], {}
        for i, f in enumerate(files):
            source = Path(f).read_text()
            target = Path(work, f"{i}_{Path(f).name}")
            target.write_text((analysis_copy(source) if f.endswith(".py") else None) or source)
            targets.append(str(target))
            back[str(target)] = f
        semgrep = isolated_tool("semgrep") or "semgrep"
        run = subprocess.run([semgrep, "scan", "--config", str(config), "--json", "--metrics=off", "--quiet",
                              "--disable-version-check", *targets], check=False, capture_output=True, text=True)
        data = json.loads(run.stdout)
    for error in data.get("errors", []):
        print("ERROR", error.get("message", "")[:300])
    hits = collections.defaultdict(list)
    for r in data["results"]:
        hits[back[r["path"]]].append(f'{r["check_id"].rsplit(".", 1)[-1]}@{r["start"]["line"]}')
    for f in files:
        print(f, hits.get(f, []))


def repos(args):
    mode = args[0] if args and args[0] in ("--via", "--entry") else None
    for arg in args[1:] if mode else args:
        root = Path(arg).expanduser()
        listed = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=False, capture_output=True, text=True).stdout
        files = [f for f in listed.split("\0") if f and not any(fnmatch.fnmatch(f, ex) for ex in DEFAULT_EXCLUSIONS)]
        start = time.time()
        ctx = Context(root=root, files=files, semgrep_config="", custom_rules=catalog.custom_semgrep_rules())
        found = Semgrep().run(ctx).findings
        print(f"== {root.name}: {len(files)} files, {time.time() - start:.0f}s")
        for f in found:
            if mode == "--entry":
                keep = ENTRY_MARK in f.message
            else:
                keep = f.type == "vulnerability" and (mode != "--via" or "[via " in f.message)
            if keep:
                print("  ", f.path, f.line, f.rule.rsplit(".", 1)[-1], f.message[-40:] if mode else "")


def owasp(categories):
    results = json.loads((HERE / "results" / "owasp-benchmark-python.json").read_text())
    issues = json.loads((CACHE / "benchmarks" / "owasp-benchmark-python.issues.json").read_text())
    parents = catalog.load()[1].get("cwe_parents", {})
    by_path = collections.defaultdict(list)
    for i in issues:
        if i["type"] == "vulnerability":
            by_path[i["path"]].append(i)
    for m in results["verdict"]["mistakes"]:
        if categories and m["category"] not in categories:
            continue
        related = [f"{i['rule']}@{i['line']}" for i in by_path.get(f"testcode/{m['test']}.py", [])
                   if any(benchmark.related(c, m["cwe"], parents) for c in benchmark.issue_cwes(i))]
        print(m["category"], m["test"], "FP" if m["flagged"] else "FN", related)


def sonar_only(names):
    import compare

    names = names or [r["name"] for r in json.loads((HERE / "compare.json").read_text())["repos"]]
    for name in names:
        data = json.loads((CACHE / "compare" / f"{name}.issues.json").read_text())
        cw, sq = data["codewatch"]["issues"], data["sonar"]["issues"]
        sonar_vulns = [i for i in compare.distinct(sq) if i["type"] == "vulnerability"]
        missed = [s for s in sonar_vulns
                  if not any(i["path"] == s["path"] and abs((i.get("line") or 0) - (s.get("line") or 0)) <= 1
                             and i["type"] in ("vulnerability", "security_hotspot") for i in cw)]
        print(f"== {name}: sonar vulnerabilities {len(sonar_vulns)}, without a codewatch finding nearby {len(missed)}")
        for s in missed:
            print("    ", s["path"], s.get("line"), s["rule"], (s.get("message") or "")[:90])


def main(argv):
    if not argv or argv[0] not in COMMANDS:
        sys.exit(__doc__)
    command, rest = argv[0], argv[1:]
    if command == "rules":
        rules(rest[0], rest[1:])
    else:
        COMMANDS[command](rest)


COMMANDS = {"bench": bench, "rules": rules, "repos": repos, "owasp": owasp, "sonar-only": sonar_only}

if __name__ == "__main__":
    main(sys.argv[1:])
