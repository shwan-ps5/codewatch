from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from core.git import GitError, Mirror
from core.models import DEFAULT_GATE, GateCondition, Project


class Command(BaseCommand):
    help = "Register a git repository (local path or URL) for analysis."

    def add_arguments(self, parser):
        parser.add_argument("key")
        parser.add_argument("repo")
        parser.add_argument("--name")
        parser.add_argument("--main-branch", help="Defaults to the repository's HEAD branch")

    def handle(self, key, repo, name, main_branch, **_):
        if Project.objects.filter(key=key).exists():
            raise CommandError(f"Project {key} already exists")
        local = Path(repo).expanduser()
        repo_url = str(local.resolve()) if local.exists() else repo
        project = Project(key=key, name=name or key, repo_url=repo_url)
        mirror = Mirror(project)
        try:
            mirror.sync()
        except GitError as exc:
            raise CommandError(str(exc)) from exc
        project.main_branch = main_branch or mirror.default_branch()
        project.save()
        GateCondition.objects.bulk_create(
            GateCondition(project=project, metric=m, op=op, threshold=t) for m, op, t in DEFAULT_GATE
        )
        self.stdout.write(f"Added {key} (main branch: {project.main_branch}, branches: {', '.join(mirror.branches())})")
