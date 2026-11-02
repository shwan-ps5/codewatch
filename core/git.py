import os
import re
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path

from django.conf import settings

from .collect import END_OF_OPTIONS, GitError, parse_diff, run_git
from .network import check_public, trusted_owner

__all__ = ["GitError", "Mirror", "validate_repo_url"]

REMOTE_URL_RE = re.compile(r"^(https?://|ssh://|git@[\w.-]+:)\S+$")
# Blocks transports such as ext:: that run arbitrary commands from a crafted URL.
GIT_ENV = {**os.environ, "GIT_ALLOW_PROTOCOL": "https:http:ssh:git:file", "GIT_TERMINAL_PROMPT": "0"}


def git(*args, cwd=None, check=True, env=None):
    return run_git(*args, cwd=cwd, check=check, env=env or GIT_ENV)


def anonymous_env(home):
    """git with none of the server account's credentials: no global or system config (credential helpers,
    ~/.git-credentials), an empty HOME (~/.netrc), no SSH agent or keys. Otherwise anyone could register a private
    repository the server can reach and read its code here."""
    home.mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in GIT_ENV.items() if k not in ("SSH_AUTH_SOCK", "GIT_ASKPASS", "SSH_ASKPASS")}
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home), GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_SSH_COMMAND=(f"ssh -F {os.devnull} -o IdentitiesOnly=yes -o IdentityFile=none -o IdentityAgent=none"
                                f" -o BatchMode=yes -o UserKnownHostsFile={home / 'known_hosts'}"
                                " -o StrictHostKeyChecking=accept-new"))
    return env


def validate_repo_url(url, allow_local):
    """Remote URLs for everyone; server-local paths and hosts on the server's own network only for admins."""
    if REMOTE_URL_RE.match(url):
        return url if allow_local else check_public(url)
    if allow_local:
        path = Path(url).expanduser()
        if path.is_dir():
            return str(path.resolve())
        raise ValueError(f"{url} is not a directory on the server")
    raise ValueError("Repository must be an https://, ssh:// or git@host: URL")


def without_links(root):
    """Delete every symlink in a checkout: one can point anywhere on the server, and analyzers that walk the tree
    themselves would follow it. The checkout is the scan's own copy."""
    for top, dirs, names in os.walk(root):
        for name in dirs + names:
            if (Path(top) / name).is_symlink():
                (Path(top) / name).unlink()


class Mirror:
    """A bare mirror of the project repo for server-side scans; the user's working copy is never touched."""

    def __init__(self, project):
        self.project = project
        self.root = Path(settings.CODEWATCH_CACHE) / project.key
        self.path = self.root / "mirror.git"

    def env(self):
        """The server's own git credentials only for a project an administrator registered."""
        return GIT_ENV if trusted_owner(self.project) else anonymous_env(self.root / "git-home")

    def sync(self):
        if not self.project.repo_url:
            raise GitError("This project has no repository URL; it is scanned with codewatch-scan from a local copy")
        if not trusted_owner(self.project):
            try:
                check_public(self.project.repo_url)
            except ValueError as exc:
                raise GitError(str(exc)) from exc
        # A mirror left by a deleted project with the same key is another repository.
        if self.path.exists() and git("config", "--get", "remote.origin.url", cwd=self.path,
                                      check=False).strip() != self.project.repo_url:
            shutil.rmtree(self.path)
        if not self.path.exists():
            self.root.mkdir(parents=True, exist_ok=True)
            git("clone", "--mirror", "--quiet", "--", self.project.repo_url, str(self.path), env=self.env())
        else:
            git("remote", "update", "--prune", cwd=self.path, env=self.env())

    def delete(self):
        """Everything kept for the project: mirror, worktrees, logs, uploaded coverage."""
        shutil.rmtree(self.root, ignore_errors=True)

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
        return git("rev-parse", "--verify", END_OF_OPTIONS, f"{ref}^{{commit}}", cwd=self.path).strip()

    def resolve_commit(self, ref):
        return git("rev-parse", "--verify", "--quiet", END_OF_OPTIONS, f"{ref}^{{commit}}", cwd=self.path,
                   check=False).strip() or None

    def resolve_main(self, main_branch):
        return self.rev_parse(main_branch)

    def has_commit(self, commit):
        if not commit:
            return False
        return subprocess.run(["git", "cat-file", "-e", END_OF_OPTIONS, f"{commit}^{{commit}}"], cwd=self.path, check=False,
                              capture_output=True).returncode == 0

    def merge_base(self, a, b):
        return git("merge-base", END_OF_OPTIONS, a, b, cwd=self.path, check=False).strip() or None

    def is_ancestor(self, a, b):
        return subprocess.run(["git", "merge-base", "--is-ancestor", END_OF_OPTIONS, a, b], cwd=self.path, check=False).returncode == 0

    def tracked_files(self, commit):
        return git("ls-tree", "-r", "--name-only", END_OF_OPTIONS, commit, cwd=self.path).splitlines()

    def show(self, commit, path):
        return git("show", END_OF_OPTIONS, f"{commit}:{path}", cwd=self.path)

    def changed_lines(self, base, head):
        return parse_diff(git("diff", "-U0", "--no-renames", "--no-color", END_OF_OPTIONS, base, head, cwd=self.path))

    @contextmanager
    def worktree(self, commit, name):
        path = self.root / "worktrees" / name
        if path.exists():
            shutil.rmtree(path)
        git("worktree", "prune", cwd=self.path)
        git("worktree", "add", "--force", "--detach", END_OF_OPTIONS, str(path), commit, cwd=self.path)
        without_links(path)
        try:
            yield path
        finally:
            shutil.rmtree(path, ignore_errors=True)
            git("worktree", "prune", cwd=self.path, check=False)
