"""Quick loops for rule work, without the server.

    venv/bin/python benchmarks/devtools.py bench [SUITE...]          # score suites (all by default), one line each
    venv/bin/python benchmarks/devtools.py cases ID...               # only these CVE pairs (id prefixes), no files
                                                                     # written: a minute instead of the whole suite
    venv/bin/python benchmarks/devtools.py rules SUBSTR FILE...      # one Semgrep pass of matching built-in rules
    venv/bin/python benchmarks/devtools.py repos [--via|--entry|--messages] DIR...
                                                                     # full Semgrep analyzer on projects (git or not)
    venv/bin/python benchmarks/devtools.py owasp [CATEGORY...]      # OWASP Python cases scored wrong (verdict mode)
    venv/bin/python benchmarks/devtools.py timings FILE [PREVIOUS]   # where a bench run's time went; bench writes
                                                                     # FILE when CODEWATCH_BENCH_TIMINGS names it

`rules` scans the same line-preserving rewritten copy of Python files that the analyzer does, but skips summaries;
`repos` runs everything (summaries, via-findings, entry-point hotspots) and prints vulnerabilities, or only
via-findings (--via) or only entry-point hotspots (--entry); --messages prints every vulnerability with the end of
its message, which names the helper a via/from/field finding went through.
"""
import collections
import fnmatch
import json
import multiprocessing
import os
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
# One line per suite or project as it finishes, also when the output goes to a file.
sys.stdout.reconfigure(line_buffering=True)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "codewatch.settings")

import django

django.setup()

import yaml

from core import benchmark, catalog
from core.analyzers.base import Context, isolated_tool
from core.analyzers.multi_tools import Semgrep, analysis_copy
from core.collect import DEFAULT_EXCLUSIONS, without_third_party

HERE = Path(__file__).resolve().parent
CACHE = Path.home() / ".cache" / "codewatch"
ENTRY_MARK = "nothing in the project calls"


def bench_log():
    """Prints failures; writes the scans' timing lines to $CODEWATCH_BENCH_TIMINGS when it is set (nightly.sh sets
    it), or drops them."""
    path = os.environ.get("CODEWATCH_BENCH_TIMINGS")
    timings = open(path, "a") if path else None  # noqa: SIM115 - open for the whole run, closed at exit

    def log(message):
        if message.startswith("timing\t"):
            if timings:
                timings.write(message.removeprefix("timing\t") + "\n")
                timings.flush()
        elif "fail" in message:
            print(message)
    return log


def bench(suites):
    out = benchmark.run(suites, log=bench_log(), workers=benchmark.WORKERS)
    for name, r in out.items():
        print(name, "verdict", r["verdict"]["overall"], "review", r["review"]["overall"])


def cases(ids):
    """Each named CVE pair's row, in both modes."""
    for suite, modes in benchmark.score_cases(ids, log=bench_log(), workers=benchmark.WORKERS):
        for mode, r in modes.items():
            print(f"{r['id']} {suite} {mode}: {', '.join(r['by']) or 'missed'} | {', '.join(r['still_by']) or 'quiet'}")


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


SKIPPED_DIRS = {".git", "node_modules", "venv", ".venv", "env", "__pycache__", "dist", "build", "vendor", ".next"}


def project_files(root):
    """Tracked files of a git working copy, or every file under a plain directory (minus dependencies and
    build output), relative to root."""
    listed = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=False, capture_output=True, text=True)
    if listed.returncode == 0 and (root / ".git").exists():
        return [f for f in listed.stdout.split("\0") if f]
    files = []
    for top, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIPPED_DIRS and not d.startswith(".")]
        files += [str((Path(top) / n).relative_to(root)) for n in names]
    return files


def repos(args):
    """Projects scanned in parallel (benchmark.WORKERS processes), printed in the order given."""
    mode = args[0] if args and args[0] in ("--via", "--entry", "--messages") else None
    roots = [str(Path(arg).expanduser()) for arg in (args[1:] if mode else args)]
    workers = min(benchmark.WORKERS, len(roots) or 1)
    with ProcessPoolExecutor(workers, mp_context=multiprocessing.get_context("spawn"),
                             initializer=benchmark.setup_worker, initargs=(workers,)) as pool:
        for lines in pool.map(scan_repo, roots, [mode] * len(roots)):
            print("\n".join(lines))


def scan_repo(root, mode):
    """The lines repos() prints for one project. Its time is wall time, so it rises with the other scans running."""
    root, lines = Path(root), []
    files = [f for f in project_files(root) if not any(fnmatch.fnmatch(f, ex) for ex in DEFAULT_EXCLUSIONS)]
    files = without_third_party(root, files, log=lambda message: lines.append(f"-- note: {message}"))
    start = time.time()
    ctx = Context(root=root, files=files, semgrep_config="", custom_rules=catalog.custom_semgrep_rules())
    result = Semgrep().run(ctx)
    lines.append(f"== {root.name}: {len(files)} files, {time.time() - start:.0f}s")
    lines += [f"-- note: {note}" for note in result.notes]
    for f in result.findings:
        if mode == "--entry":
            keep = ENTRY_MARK in f.message
        else:
            keep = f.type == "vulnerability" and (mode != "--via" or "[via " in f.message)
        if keep:
            lines.append(f"   {f.path} {f.line} {f.rule.rsplit('.', 1)[-1]} {f.message[-40:] if mode else ''}")
    return lines


def timings(args):
    """Where a bench run's time went (the file $CODEWATCH_BENCH_TIMINGS named), compared with an earlier run's."""
    if not args:
        sys.exit("usage: devtools.py timings FILE [PREVIOUS_FILE]")
    previous = Path(args[1]).read_text().splitlines() if len(args) > 1 and Path(args[1]).exists() else []
    print(benchmark.timing_report(Path(args[0]).read_text().splitlines(), previous))


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


def main(argv):
    if not argv or argv[0] not in COMMANDS:
        sys.exit(__doc__)
    command, rest = argv[0], argv[1:]
    if command == "rules":
        rules(rest[0], rest[1:])
    else:
        COMMANDS[command](rest)


COMMANDS = {"bench": bench, "cases": cases, "rules": rules, "repos": repos, "owasp": owasp, "timings": timings}

if __name__ == "__main__":
    main(sys.argv[1:])
