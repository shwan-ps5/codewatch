import subprocess
import sys
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from .models import Analysis


def launch_scan(project, branch=None, coverage=None):
    """Run `manage.py scan` detached; returns None if that branch is already being analysed."""
    if branch and project.analyses.filter(
        branch=branch, status=Analysis.RUNNING, started_at__gte=timezone.now() - timedelta(hours=1)
    ).exists():
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
