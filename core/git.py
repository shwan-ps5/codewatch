import os
import re
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path

from django.conf import settings

from .collect import GitError, parse_diff, run_git

__all__ = ["GitError", "Mirror", "validate_repo_url"]

REMOTE_URL_RE = re.compile(r"^(https?://|ssh://|git@[\w.-]+:)\S+$")
# Blocks transports such as ext:: that run arbitrary commands from a crafted URL.
GIT_ENV = {**os.environ, "GIT_ALLOW_PROTOCOL": "https:http:ssh:git:file", "GIT_TERMINAL_PROMPT": "0"}


def git(*args, cwd=None, check=True):
    return run_git(*args, cwd=cwd, check=check, env=GIT_ENV)


def validate_repo_url(url, allow_local):
    """Remote URLs for everyone; server-local paths only for admins, since they expose the server's filesystem."""
    if REMOTE_URL_RE.match(url):
        return url
    if allow_local:
        path = Path(url).expanduser()
        if path.is_dir():
            return str(path.resolve())
        raise ValueError(f"{url} is not a directory on the server")
    raise ValueError("Repository must be an https://, ssh:// or git@host: URL")


class Mirror:
    """A bare mirror of the project repo for server-side scans; the user's working copy is never touched."""

    def __init__(self, project):
        self.project = project
        self.root = Path(settings.CODEWATCH_CACHE) / project.key
        self.path = self.root / "mirror.git"

    def sync(self):
        if not self.project.repo_url:
            raise GitError("This project has no repository URL; it is scanned with codewatch-scan from a local copy")
        if not self.path.exists():
            self.root.mkdir(parents=True, exist_ok=True)
            git("clone", "--mirror", "--quiet", self.project.repo_url, str(self.path))
        else:
            git("remote", "update", "--prune", cwd=self.path)

    def branches(self):
        if not self.path.exists():
            return []
        out = git("for-each-ref", "--format=%(refname:short)", "refs/heads", cwd=self.path)
        return [b for b in out.splitlines() if b]

    def default_branch(self):
        # A mirror of a local clone inherits whatever branch happened to be checked out.
        branches = self.branches()
        for name in ("main", "master", "trunk", "develop"):
            if name in branches:
                return name
        return git("symbolic-ref", "--short", "HEAD", cwd=self.path).strip()

    def rev_parse(self, ref):
        return git("rev-parse", "--verify", f"{ref}^{{commit}}", cwd=self.path).strip()

    def resolve_main(self, main_branch):
        return self.rev_parse(main_branch)

    def has_commit(self, commit):
        if not commit:
            return False
        return subprocess.run(["git", "cat-file", "-e", f"{commit}^{{commit}}"], cwd=self.path, check=False,
                              capture_output=True).returncode == 0

    def merge_base(self, a, b):
        return git("merge-base", a, b, cwd=self.path, check=False).strip() or None

    def is_ancestor(self, a, b):
        return subprocess.run(["git", "merge-base", "--is-ancestor", a, b], cwd=self.path, check=False).returncode == 0

    def tracked_files(self, commit):
        return git("ls-tree", "-r", "--name-only", commit, cwd=self.path).splitlines()

    def show(self, commit, path):
        return git("show", f"{commit}:{path}", cwd=self.path)

    def changed_lines(self, base, head):
        return parse_diff(git("diff", "-U0", "--no-renames", "--no-color", base, head, cwd=self.path))

    @contextmanager
    def worktree(self, commit, name):
        path = self.root / "worktrees" / name
        if path.exists():
            shutil.rmtree(path)
        git("worktree", "prune", cwd=self.path)
        git("worktree", "add", "--force", "--detach", str(path), commit, cwd=self.path)
        try:
            yield path
        finally:
            shutil.rmtree(path, ignore_errors=True)
            git("worktree", "prune", cwd=self.path, check=False)
