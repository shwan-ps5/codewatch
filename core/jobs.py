import fcntl
import os
import re
import subprocess
import sys
from contextlib import contextmanager
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from .models import Analysis

# A branch name as git allows it, and nothing an option parser or a log line could take for something else.
BRANCH_RE = re.compile(r"^(?!-)[^\x00-\x20\x7f~^:?*\[\\]{1,200}$")
# Scans at once across the server: each runs every analyzer over a whole repository.
MAX_RUNNING_SCANS = int(os.environ.get("CODEWATCH_MAX_SCANS") or 4)
# A scan still marked running after this long died without saying so.
STALE_SCAN = timedelta(hours=1)


def scan_refusal(project, branch=None):
    """Why a scan can't start now, or None."""
    if branch and not BRANCH_RE.match(branch):
        return "That isn't a branch name."
    running = Analysis.objects.filter(status=Analysis.RUNNING, started_at__gte=timezone.now() - STALE_SCAN)
    if running.filter(project=project, branch=branch or project.main_branch).exists():
        return f"{branch or 'The main branch'} is already being analysed."
    if running.count() >= MAX_RUNNING_SCANS:
        return f"The server is already running {MAX_RUNNING_SCANS} scans; try again when one has finished."
    return None


@contextmanager
def project_lock(project):
    """One scan of a project at a time (they share its git mirror); a second waits for the first."""
    path = settings.CODEWATCH_CACHE / project.key / "scan.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def launch_scan(project, branch=None, coverage=None):
    """Run `manage.py scan` detached; returns None if scan_refusal says it can't start."""
    if scan_refusal(project, branch):
        return None
    log_dir = settings.CODEWATCH_CACHE / project.key / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{timezone.now():%Y%m%d-%H%M%S}-{(branch or 'main').replace('/', '_')}.log"
    args = [sys.executable, str(settings.BASE_DIR / "manage.py"), "scan", project.key]
    if branch:
        args += ["--branch", branch]
    if coverage:
        args += ["--coverage", str(coverage)]
    with open(log_path, "w") as log:
        subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, start_new_session=True, cwd=settings.BASE_DIR)
    return log_path


def save_coverage_upload(project, upload):
    suffix = ".info" if upload.name.endswith((".info", ".lcov")) else ".xml"
    upload_dir = settings.CODEWATCH_CACHE / project.key / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    path = upload_dir / f"{timezone.now():%Y%m%d-%H%M%S-%f}{suffix}"
    with open(path, "wb") as out:
        out.writelines(upload.chunks())
    return path
