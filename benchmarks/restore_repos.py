"""Re-clone the pinned app repositories listed in PLAN.md's "Repos" section, e.g. after ~/.cache was cleaned.

Each table there follows a line naming its folder (`~/.cache/codewatch/fresh/`). Every row
(`| https://github.com/O/R | <commit> | ... |`) is cloned to <folder>/<R> and checked out at that commit. Repositories
already present are left alone. Cloning doesn't scan anything, so blind folders are safe to restore.

    python3 -I benchmarks/restore_repos.py                 fresh/ and blind4/ (the ones in use)
    python3 -I benchmarks/restore_repos.py fresh blind2    the named folders
"""

import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
FOLDER = re.compile(r"`~/\.cache/codewatch/([\w-]+)/`")
ROW = re.compile(r"^\| (https://github\.com/[\w.-]+/([\w.-]+?)(?:\.git)?) \| ([0-9a-f]{7,40}) \|")


def pinned(plan):
    """[(folder, url, name, commit)] from the Repos section."""
    repos, folder = [], None
    section = plan.split("\n## Repos", 1)[-1]
    for line in section.splitlines():
        if found := FOLDER.search(line):
            folder = found.group(1)
        elif folder and (row := ROW.match(line)):
            repos.append((folder, row.group(1), row.group(2), row.group(3)))
    return repos


def run(*args):
    return subprocess.run(args, check=False, capture_output=True, text=True)


def restore(folder, url, name, commit, base):
    target = base / folder / name
    if (target / ".git").exists():
        return f"present  {folder}/{name}"
    target.parent.mkdir(parents=True, exist_ok=True)
    clone = run("git", "clone", "-q", "--filter=blob:none", "--no-checkout", url, str(target))
    if clone.returncode:
        return f"FAILED   {folder}/{name}: {clone.stderr.strip()[-200:]}"
    checkout = run("git", "-C", str(target), "checkout", "-q", "--detach", commit)
    if checkout.returncode:
        return f"FAILED   {folder}/{name} at {commit}: {checkout.stderr.strip()[-200:]}"
    return f"restored {folder}/{name} at {commit}"


def main(argv):
    wanted = set(argv) or {"fresh", "blind4"}
    base = Path.home() / ".cache" / "codewatch"
    repos = [r for r in pinned((HERE.parent / "PLAN.md").read_text()) if r[0] in wanted]
    with ThreadPoolExecutor(4) as pool:
        results = list(pool.map(lambda r: restore(*r, base), repos))
    print("\n".join(results))
    return 1 if any(r.startswith("FAILED") for r in results) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
