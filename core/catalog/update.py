"""Keeping the imported rules current: on demand (button / command) or on a schedule.

An update optionally upgrades the analyzers themselves (new tool versions bring new rules), then re-imports.
"""
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ..analyzers.base import TOOLS_DIR
from . import RUNTIME_DIR, imported_dir, read_json, reload
from .build import build

PYTHON_ANALYZERS = ["ruff", "bandit", "radon", "lizard", "pip-audit", "complexipy", "basedpyright",
                    "detect-secrets"]
ISOLATED_ANALYZERS = ["semgrep", "checkov"]
# Held at a major version because a dependent plugin doesn't support the next one yet.
NODE_MAJOR_PINS = {"eslint": "9", "@eslint/js": "9"}
STATUS_FILE = RUNTIME_DIR / "status.json"
STALE_RUN = timedelta(hours=2)


def update_interval():
    return timedelta(days=float(os.environ.get("CODEWATCH_CATALOG_UPDATE_DAYS", "7")))


def status():
    return read_json(STATUS_FILE, {})


def write_status(**fields):
    STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATUS_FILE.write_text(json.dumps({**status(), **fields}, indent=1))


def run_step(args, log, cwd=None):
    log("$ " + " ".join(str(a) for a in args))
    proc = subprocess.run(args, capture_output=True, text=True, check=False, cwd=cwd)
    if proc.returncode:
        log(proc.stderr.strip()[-1500:])
    return proc.returncode == 0


def upgrade_tools(log):
    ok = run_step([sys.executable, "-m", "pip", "install", "-q", "-U", *PYTHON_ANALYZERS], log)
    for name in ISOLATED_ANALYZERS:
        pip = TOOLS_DIR / f"{name}-venv" / "bin" / "pip"
        if pip.exists():
            ok &= run_step([str(pip), "install", "-q", "-U", name], log)
    package = TOOLS_DIR / "package.json"
    if package.exists():
        deps = json.loads(package.read_text()).get("dependencies", {})
        specs = [f"{name}@{NODE_MAJOR_PINS.get(name, 'latest')}" for name in deps]
        ok &= run_step(["npm", "install", "--save-exact", "--no-fund", "--no-audit", *specs], log, cwd=TOOLS_DIR)
        ok &= run_step([str(TOOLS_DIR / "node_modules/.bin/playwright"), "install", "--only-shell", "chromium"], log)
    return ok


def run_update(upgrade=False, log=print):
    """Re-import into the server's cache directory; catalog/custom/ is never modified."""
    lines = []

    def record(message):
        lines.append(message)
        log(message)

    write_status(state="running", started_at=now(), upgrade=upgrade, pid=os.getpid())
    try:
        if upgrade:
            record("Upgrading analyzers")
            upgrade_tools(record)
        previous = read_json(imported_dir() / "rules.json", [])
        meta = build(RUNTIME_DIR / "imported", log=record, previous=previous)
    except Exception as exc:
        write_status(state="failed", finished_at=now(), log=lines[-200:], error=str(exc)[:2000])
        raise
    reload()
    write_status(state="done", finished_at=now(), log=lines[-200:], rules=meta["rules"],
                 failed_sources=meta["failed_sources"])
    return meta


def now():
    return datetime.now(UTC).isoformat(timespec="seconds")


def running():
    s = status()
    if s.get("state") != "running":
        return False
    started = datetime.fromisoformat(s["started_at"])
    return datetime.now(UTC) - started < STALE_RUN


def due():
    interval = update_interval()
    if interval <= timedelta(0) or running():
        return False
    imported = read_json(imported_dir() / "meta.json", {}).get("imported_at")
    if not imported:
        return True
    return datetime.now(UTC) - datetime.fromisoformat(imported) >= interval


def launch(upgrade=False, manage_py=None):
    """Start `manage.py updatecatalog` in the background."""
    manage_py = manage_py or Path(__file__).resolve().parents[2] / "manage.py"
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    write_status(state="running", started_at=now(), upgrade=upgrade)
    args = [sys.executable, str(manage_py), "updatecatalog"] + (["--upgrade-tools"] if upgrade else [])
    with open(RUNTIME_DIR / "update.log", "w") as out:
        subprocess.Popen(args, stdout=out, stderr=subprocess.STDOUT, start_new_session=True,
                         cwd=manage_py.parent)


def maybe_launch():
    """Called on page loads: start the scheduled update when it's due. Cheap when it isn't."""
    if due():
        launch(upgrade=os.environ.get("CODEWATCH_CATALOG_UPGRADE_TOOLS") == "1")
        return True
    return False
