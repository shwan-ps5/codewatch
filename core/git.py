import re
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path

from django.conf import settings

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


class GitError(RuntimeError):
    pass


def git(*args, cwd=None, check=True):
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=False)
    if check and proc.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


class Mirror:
    """A bare mirror of the project repo, so scans never touch the user's working copy."""

    def __init__(self, project):
        self.project = project
        self.root = Path(settings.CODEWATCH_CACHE) / project.key
        self.path = self.root / "mirror.git"

    def sync(self):
        if not self.path.exists():
            self.root.mkdir(parents=True, exist_ok=True)
            git("clone", "--mirror", "--quiet", self.project.repo_url, str(self.path))
        else:
            git("remote", "update", "--prune", cwd=self.path)

    def branches(self):
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

    def has_commit(self, commit):
        if not commit:
            return False
        return subprocess.run(["git", "cat-file", "-e", f"{commit}^{{commit}}"], cwd=self.path, check=False).returncode == 0

    def merge_base(self, a, b):
        out = git("merge-base", a, b, cwd=self.path, check=False).strip()
        return out or None

    def is_ancestor(self, a, b):
        return subprocess.run(["git", "merge-base", "--is-ancestor", a, b], cwd=self.path, check=False).returncode == 0

    def tracked_files(self, commit):
        return git("ls-tree", "-r", "--name-only", commit, cwd=self.path).splitlines()

    def show(self, commit, path):
        return git("show", f"{commit}:{path}", cwd=self.path)

    def changed_lines(self, base, head):
        """Map of path -> set of line numbers added or modified in head relative to base."""
        out = git("diff", "-U0", "--no-renames", "--no-color", base, head, cwd=self.path)
        changed, current = {}, None
        for line in out.splitlines():
            if line.startswith("+++ "):
                target = line[4:]
                current = None if target == "/dev/null" else target.removeprefix("b/")
                if current:
                    changed.setdefault(current, set())
            elif current and (m := HUNK_RE.match(line)):
                start, count = int(m[1]), int(m[2]) if m[2] is not None else 1
                changed[current].update(range(start, start + count))
        return changed

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
