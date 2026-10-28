from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from core.git import Mirror, git
from core.models import Project
from core.runner import ensure_main_branch, scan

COVERAGE_CANDIDATES = ["coverage.xml", "coverage/cobertura-coverage.xml", "coverage/lcov.info", "lcov.info"]


def local_coverage(project, commit, log):
    """Pick up a coverage report from the user's working copy, but only if it was produced at the scanned commit."""
    repo = Path(project.repo_url)
    if not repo.is_dir():
        return None
    report = next((repo / c for c in COVERAGE_CANDIDATES if (repo / c).exists()), None)
    if report is None:
        return None
    head = git("rev-parse", "HEAD", cwd=repo, check=False).strip()
    if head != commit:
        log(f"Skipping {report}: working copy is at {head[:8]}, not {commit[:8]}")
        return None
    return report


class Command(BaseCommand):
    help = "Analyse one or more branches of a project."

    def scan_branch(self, project, mirror, branch, coverage, coverage_base):
        """Returns False if the analysis failed or its gate did."""
        log = self.stdout.write
        log(f"== {project.key} @ {branch}")
        if coverage is None:
            coverage = local_coverage(project, mirror.rev_parse(branch), log)
            coverage_base = project.repo_url if coverage else None
        analysis = scan(project, branch, coverage_report=coverage, coverage_base=coverage_base, log=log)
        return analysis.status == analysis.SUCCESS and analysis.gate_passed is not False

    def add_arguments(self, parser):
        parser.add_argument("project")
        parser.add_argument("--branch", action="append", help="Repeatable; defaults to the main branch")
        parser.add_argument("--all-branches", action="store_true")
        parser.add_argument("--coverage", help="Cobertura XML or LCOV report from the project's test run")
        parser.add_argument("--coverage-base", help="Directory the report's paths are relative to")
        parser.add_argument("--fail-on-gate", action="store_true", help="Exit 1 if any quality gate fails")

    def handle(self, project, branch, all_branches, coverage, coverage_base, fail_on_gate, **_):
        try:
            proj = Project.objects.get(key=project)
        except Project.DoesNotExist as exc:
            raise CommandError(f"Unknown project {project}") from exc
        mirror = Mirror(proj)
        mirror.sync()
        ensure_main_branch(proj, mirror)
        branches = mirror.branches() if all_branches else (branch or [proj.main_branch])
        # Main first, so branches compare against a fresh baseline.
        branches.sort(key=lambda b: b != proj.main_branch)
        results = [self.scan_branch(proj, mirror, b, coverage, coverage_base) for b in branches]
        if fail_on_gate and not all(results):
            raise SystemExit(1)
