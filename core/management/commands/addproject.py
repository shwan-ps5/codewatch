from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from core.git import GitError, Mirror, validate_repo_url
from core.models import DEFAULT_GATE, GateCondition, Project


class Command(BaseCommand):
    help = "Register a git repository (local path or URL) for analysis."

    def add_arguments(self, parser):
        parser.add_argument("key")
        parser.add_argument("repo")
        parser.add_argument("--name")
        parser.add_argument("--main-branch", help="Defaults to the repository's HEAD branch")
        parser.add_argument("--owner", help="Username (default: the first administrator)")

    def handle(self, key, repo, name, main_branch, owner, **_):
        if Project.objects.filter(key=key).exists():
            raise CommandError(f"Project {key} already exists")
        users = get_user_model().objects
        owner_user = users.filter(username=owner).first() if owner else users.filter(is_superuser=True).first()
        if owner_user is None:
            raise CommandError("No such owner")
        try:
            repo_url = validate_repo_url(repo, allow_local=True)
        except ValueError as exc:
            raise CommandError(str(exc)) from exc
        project = Project(key=key, name=name or key, repo_url=repo_url, owner=owner_user)
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
