"""Which advisories and fix commits have already been looked at, so nobody reads them twice.

Reads every benchmarks/cve-candidates-*.tsv (one row per advisory read, accepted or rejected) and every
cve-pairs suite in benchmarks/suites.json, blind ones included. An advisory's other ids (a GHSA's CVE, or the GHSA
of a CVE) count as known too, from a local github/advisory-database clone (CODEWATCH_ADVISORY_DB, default
~/advisory-database) when there is one. Standard library only, so it runs anywhere:

    python3 -I benchmarks/reviewed.py                    every known advisory: id, status, where recorded
    python3 -I benchmarks/reviewed.py GHSA-... SHA ...   just these (advisory ids or fix commits, 7+ hex chars);
                                                         exits 1 when any of them is already known
    python3 -I benchmarks/reviewed.py --split GHSA-...   blind or open under PLAN.md step 22's rule
    python3 -I benchmarks/reviewed.py size OWNER/REPO SHA [--python]
                                                         a fix commit's size as the review counts it (needs gh)
    python3 -I benchmarks/reviewed.py guard BASE [HEAD]  checks a research agent's commits since BASE before they
                                                         are pushed (tools/research-batch.sh); exits 1 on a problem
    python3 -I benchmarks/reviewed.py pending [--gaps]   how many candidate batches (or gap notes) are waiting for
                                                         review

A status is "suite:<name>" (in that suite), "rejected", "accepted" (accepted but not in a suite yet) or "unsure".
Blind cases show only their suite name: their reasons are never written down.
"""

import csv
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ADVISORY_DB = Path(os.environ.get("CODEWATCH_ADVISORY_DB") or Path.home() / "advisory-database")
ALIASES_FIELD = re.compile(rb'"aliases":\s*\[([^\]]*)\]')
QUOTED = re.compile(rb'"([^"]+)"')


def is_blind(advisory_id):
    return int(hashlib.sha256(advisory_id.encode()).hexdigest(), 16) % 3 == 0


ACCEPTED = "accepted"


def tsv_rows(lines):
    """The rows of a candidate TSV, without blank and comment lines."""
    return csv.reader((x for x in lines if x.strip() and not x.startswith("#")), delimiter="\t")


def tsv_decisions(root):
    """{advisory id: (decision, TSV file)} from every candidate batch."""
    seen = {}
    for tsv in sorted(root.glob("cve-candidates-*.tsv")):
        for row in tsv_rows(tsv.open()):
            if len(row) >= 4 and row[1] != "id":
                seen[row[1]] = ({"accept": ACCEPTED, "reject": "rejected"}.get(row[3], row[3] or "unsure"), tsv.name)
    return seen


def advisory_aliases(db):
    """{GHSA id: its other ids} from a github/advisory-database clone; empty without one. Reads only the start of
    each advisory file, where its aliases are: about 3 seconds for 400,000 advisories."""
    aliases = {}
    for folder in sorted((db / "advisories").glob("*/*/*/GHSA-*")):
        try:
            with (folder / f"{folder.name}.json").open("rb") as file:
                field = ALIASES_FIELD.search(file.read(4096))
        except OSError:
            continue
        if field and (names := [n.decode() for n in QUOTED.findall(field.group(1))]):
            aliases[folder.name] = names
    return aliases


def add_aliases(seen, aliases):
    """Every id of a known advisory, recorded as known under the id it was read as (GHSA-w3fm was read again as a
    new advisory though its CVE, CVE-2026-133116, had been rejected the hour before, 2026-11-19)."""
    for ghsa, names in aliases.items():
        ids = [ghsa, *names]
        if (read_as := next((i for i in ids if i in seen), None)) is None:
            continue
        status, where = seen[read_as]
        for other in ids:
            seen.setdefault(other, (status, f"{where} (as {read_as})"))
    return seen


def known(root=HERE, db=ADVISORY_DB):
    """{advisory id: (status, where recorded)} and {fix commit: advisory id}, with the aliases of each known advisory
    from db (None for ids as written only). On by default: the research agents' own scripts call this, and with it
    off they read Moodle GHSA-fr4r again though its CVE had been rejected the day before (2026-11-19)."""
    seen, fixes = tsv_decisions(root), {}
    for suite in json.loads((root / "suites.json").read_text())["suites"]:
        cases = [c for c in suite.get("cases", []) if isinstance(c, dict) and c.get("id")]
        for case in cases:
            seen[case["id"]] = (f"suite:{suite['name']}", "suites.json")
        fixes |= {case["fix"]: case["id"] for case in cases if case.get("fix")}
    return (add_aliases(seen, advisory_aliases(db)) if db else seen), fixes


# Not source code for the size limits: tests and test-runner configs, docs, changelogs, lockfiles, manifests, and
# translation catalogs (SQLBot GHSA-fghj and Openpanel GHSA-wfxj were rejected as too large over locale JSON and
# vitest.config.ts, 2026-11-04).
NOT_SOURCE = re.compile(r"(^|/)(tests?|spec|__tests__|docs?|changelog\.d)/|test_|_test\.|\.(test|spec)\.|\.(md|mdx|rst|txt|lock|po)$"
                        r"|(^|/)(package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|\.gitignore|CHANGELOG[^/]*)$"
                        r"|(^|/)(vitest|jest|playwright|karma|cypress)\.config\.[cm]?[jt]s$",
                        re.IGNORECASE)
TRANSLATION_DIR = re.compile(r"(^|/)(locales?|i18n|lang|translations?)/", re.IGNORECASE)
CATALOG_EXTENSIONS = (".json", ".yml", ".yaml", ".po", ".properties")


def not_source(name):
    """A file the size limits leave out: NOT_SOURCE, or a translation catalog under a translations folder."""
    return bool(NOT_SOURCE.search(name)
                or (TRANSLATION_DIR.search(name) and name.lower().endswith(CATALOG_EXTENSIONS)))
LIMITS = {"default": (3, 120), "python": (5, 200)}  # PLAN.md step 22; step 24 widened Python's


def _squash(text):
    return "".join(text.split())


def diff_files(diff):
    """{file: its added and removed lines} of a unified diff."""
    files, current = {}, None
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            current = line.rsplit(" b/", 1)[-1]
            files[current] = []
        elif current and line[:1] in "+-" and not line.startswith(("+++ ", "--- ")):
            files[current].append(line)
    return files


def changed_lines(lines):
    """Lines changed beyond whitespace: one removed and added again with only whitespace changed, and blank lines,
    don't count."""
    def squashed(sign):
        return Counter(_squash(x[1:]) for x in lines if x[0] == sign and x[1:].strip())
    added, removed = squashed("+"), squashed("-")
    return sum((added - removed).values()) + sum((removed - added).values())


def measure(diff):
    """{source file: changed lines}, ignoring whitespace-only changes and files that aren't source."""
    sizes = {name: changed_lines(lines) for name, lines in diff_files(diff).items() if not not_source(name)}
    return {name: n for name, n in sizes.items() if n}


def size(repo, sha, python=False):
    gh = ["gh", "api", f"repos/{repo}/commits/{sha}"]
    parents = int(subprocess.run([*gh, "--jq", ".parents|length"], check=True, capture_output=True, text=True).stdout)
    diff = subprocess.run([*gh, "-H", "Accept: application/vnd.github.diff"], check=True, capture_output=True,
                          text=True).stdout
    sizes = measure(diff)
    max_files, max_lines = LIMITS["python" if python else "default"]
    total = sum(sizes.values())
    within = len(sizes) <= max_files and total <= max_lines
    for name, n in sorted(sizes.items()):
        print(f"{n}\t{name}")
    verdict = "within" if within else "OVER"
    print(f"{len(sizes)} source files, {total} lines ignoring whitespace; {parents} parent(s); "
          f"{verdict} the {max_files}-file/{max_lines}-line limit")
    return 0 if within and parents == 1 else 1


ALLOWED = re.compile(r"^(benchmarks/cve-candidates-[A-Za-z0-9._-]+\.(tsv|json)|benchmarks/gap-notes-[A-Za-z0-9._-]+\.json"
                     r"|AGENTS\.md)$")
IDENTITY = "Shwan <344055753+shwan-ps5@users.noreply.github.com>"
WITHHELD = "accepted; reason withheld so the case stays blind"
UNREVIEWED = "research only"


def _git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


def identity_problems(base, head, repo):
    problems = []
    for line in _git("log", "--format=%an <%ae>|%cn <%ce>|%h", f"{base}..{head}", cwd=repo).splitlines():
        author, committer, commit = line.split("|")
        if author != IDENTITY or committer != IDENTITY:
            problems.append(f"{commit}: committed as {author} / {committer}")
    return problems


def tsv_problems(name, text):
    """A blind case accepted with its reason written out."""
    return [f"{name}: blind case {row[1]} has a reason" for row in tsv_rows(text.splitlines())
            if len(row) >= 6 and row[3] == "accept" and is_blind(row[1]) and row[5] != WITHHELD]


def accepted_ids(head, stem, repo):
    """Advisory ids with an accept row in the batch's TSV at head."""
    try:
        rows = _git("show", f"{head}:{stem}.tsv", cwd=repo).splitlines()
    except subprocess.CalledProcessError:
        rows = []
    return {r[1] for r in tsv_rows(rows) if len(r) >= 4 and r[3] == "accept"}


def case_problems(name, case, accepted_rows, stem):
    """An accepted case missing from the TSV, a blind one described beyond its entry, or one in the wrong half."""
    problems = []
    blind = is_blind(case.get("id", ""))
    if case.get("id") not in accepted_rows:
        problems.append(f"{name}: {case.get('id')} is accepted here but has no accept row in {stem}.tsv")
    extra = set(case) - {"id", "suite", "entry", "reason_withheld"}
    if blind and extra:
        problems.append(f"{name}: blind case {case['id']} has {sorted(extra)}")
    if ("blind" in str(case.get("suite", ""))) != blind:
        problems.append(f"{name}: {case.get('id')} is in the wrong half ({case.get('suite')})")
    return problems


def shared_fix_problems(name, accepted, head, repo):
    """Open cases whose fix commit is a blind case's. Scanning an open case scans its fix commit, so a shared one
    would expose the blind case (NginxProxyManager GHSA-mhxx and -5rqg shared 99cce7e with a blind advisory,
    2026-11-04)."""
    blind_fixes = _blind_fixes(head, repo) | {c.get("entry", {}).get("fix") for c in accepted
                                              if is_blind(c.get("id", ""))}
    return [f"{name}: open case {case.get('id')} has a blind case's fix commit; reject it" for case in accepted
            if (fix := case.get("entry", {}).get("fix")) and not is_blind(case.get("id", "")) and fix in blind_fixes]


def batch_problems(name, text, head, repo):
    try:
        batch = json.loads(text)
    except ValueError as error:
        return [f"{name}: not JSON ({error})"]
    stem = name[: -len(".json")]
    accepted, accepted_rows = batch.get(ACCEPTED, []), accepted_ids(head, stem, repo)
    problems = [p for case in accepted for p in case_problems(name, case, accepted_rows, stem)]
    return problems + shared_fix_problems(name, accepted, head, repo)


def gap_note_problems(name, text, head, repo):
    """A gap note (AGENTS.md section 9) about anything but an open CVE-pair case, or filed under the wrong suite."""
    try:
        notes = json.loads(text).get("notes", [])
    except (ValueError, AttributeError) as error:
        return [f"{name}: not a JSON object with notes ({error})"]
    try:
        suites = json.loads(_git("show", f"{head}:benchmarks/suites.json", cwd=repo)).get("suites", [])
    except (subprocess.CalledProcessError, ValueError):
        suites = []
    where = {c.get("id"): s["name"] for s in suites if s.get("kind") == "cve-pairs" and not s.get("blind")
             and "blind" not in s.get("name", "") for c in s.get("cases", []) if isinstance(c, dict)}
    blind = {c.get("id") for s in suites if s.get("blind") or "blind" in s.get("name", "")
             for c in s.get("cases", []) if isinstance(c, dict)}
    problems = []
    for note in notes:
        case_id = note.get("id") if isinstance(note, dict) else None
        if case_id in blind or case_id not in where:
            problems.append(f"{name}: {case_id} is not an open CVE-pair case; gap notes are for those only")
        elif note.get("suite") != where[case_id]:
            problems.append(f"{name}: {case_id} is in {where[case_id]}, not {note.get('suite')}")
    return problems


def guard(base, head="HEAD", repo=HERE.parent):
    """Problems with the commits since base, which an unattended research run made: only candidate files, gap notes
    (and AGENTS.md) touched, the maintainer's noreply identity, blind cases described by nothing but their entry, and
    gap notes about open cases only."""
    problems = identity_problems(base, head, repo)
    changed = [f for f in _git("diff", "--name-only", "--diff-filter=AM", f"{base}..{head}", cwd=repo).splitlines() if f]
    problems += [f"{name}: not a file research may change" for name in changed if not ALLOWED.match(name)]
    for name in changed:
        if not ALLOWED.match(name) or name == "AGENTS.md":
            continue
        text = _git("show", f"{head}:{name}", cwd=repo)
        if name.startswith("benchmarks/gap-notes-"):
            problems += gap_note_problems(name, text, head, repo)
        else:
            problems += tsv_problems(name, text) if name.endswith(".tsv") else batch_problems(name, text, head, repo)
    return problems


def _blind_fixes(head, repo):
    """Fix commits of the blind suites in suites.json at head."""
    try:
        suites = json.loads(_git("show", f"{head}:benchmarks/suites.json", cwd=repo)).get("suites", [])
    except (subprocess.CalledProcessError, ValueError):
        return set()
    return {c.get("fix") for s in suites if s.get("blind") for c in s.get("cases", []) if isinstance(c, dict)}


def pending(root=HERE, prefix="cve-candidates-"):
    """Candidate batches (or, with prefix "gap-notes-", gap notes) a review session hasn't looked at yet."""
    waiting = []
    for path in sorted(root.glob(f"{prefix}*.json")):
        try:
            status = str(json.loads(path.read_text()).get("status", ""))
        except ValueError:
            continue
        if status.startswith(UNREVIEWED):
            waiting.append(path.name)
    return waiting


def lookup(key, seen, fixes):
    if key in seen:
        return key, *seen[key]
    if len(key) >= 7 and all(c in "0123456789abcdef" for c in key.lower()):
        for fix, advisory in fixes.items():
            if fix.startswith(key.lower()):
                return f"{key} ({advisory})", *seen[advisory]
        # A FIX- id ends in its commit's first 12 hex digits; rejected ones are only in the TSVs, under that id.
        for case_id in seen:
            if case_id.startswith("FIX-") and _commit_matches(case_id.rsplit("-", 1)[-1], key.lower()):
                return f"{key} ({case_id})", *seen[case_id]
    return None


def _commit_matches(short, key):
    """Whether a FIX- id's 12-digit commit prefix and a looked-up commit (7 to 40 hex digits) are the same commit."""
    return short.startswith(key) if len(key) <= len(short) else key.startswith(short)


def guard_command(argv, _root):
    problems = guard(*argv[1:3])
    print("\n".join(problems) or "ok")
    return 1 if problems else 0


def pending_command(argv, root):
    waiting = pending(root, "gap-notes-" if "--gaps" in argv else "cve-candidates-")
    print(len(waiting), *waiting, sep="\n")
    return 0


def split_command(argv, _root):
    for advisory in argv[1:]:
        print(advisory, "blind" if is_blind(advisory) else "open")
    return 0


COMMANDS = {"size": lambda argv, _root: size(argv[1], argv[2], python="--python" in argv),
            "guard": guard_command, "pending": pending_command, "--split": split_command}


def main(argv, root=HERE, db=ADVISORY_DB):
    if argv[:1] and argv[0] in COMMANDS:
        return COMMANDS[argv[0]](argv, root)
    seen, fixes = known(root, db)
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
