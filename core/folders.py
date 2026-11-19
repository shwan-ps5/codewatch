"""Server-side folder browsing for the new-project page: an administrator picks a local repository by name.

A browser's folder picker can't do this: it uploads the files and never tells the page where the folder is. The
server lists folders itself, only under CODEWATCH_BROWSE_ROOT (the home directory by default), and only folder
names: no file is read.
"""
from pathlib import Path

from django.conf import settings
from django.utils.text import slugify

from .models import Project

MAX_FOLDERS = 500


def browse_root():
    return Path(getattr(settings, "CODEWATCH_BROWSE_ROOT", None) or Path.home()).resolve()


def under_root(requested):
    """The requested folder, resolved, if it is a folder under the browse root; else None."""
    root = browse_root()
    path = (root / requested).resolve()
    return path if path.is_relative_to(root) and path.is_dir() else None


def within_root(requested):
    """The requested folder under the browse root, or the root itself."""
    return (under_root(requested) if requested else None) or browse_root()


def is_repository(path):
    return (path / ".git").exists()


def listing(requested):
    """{path, parent, repository, folders: [{name, path, repository}]} for a folder under the browse root. Paths are
    relative to the root; hidden folders are left out."""
    root = browse_root()
    path = within_root(requested)
    try:
        children = sorted((c for c in path.iterdir() if c.is_dir() and not c.name.startswith(".")),
                          key=lambda c: c.name.lower())[:MAX_FOLDERS]
    except OSError:
        children = []
    return {
        "path": path.relative_to(root).as_posix() if path != root else "",
        "absolute": str(path),
        "parent": None if path == root else (path.parent.relative_to(root).as_posix() if path.parent != root else ""),
        "repository": is_repository(path),
        "folders": [{"name": c.name, "path": c.relative_to(root).as_posix(), "repository": is_repository(c)}
                    for c in children],
    }


def unused_key(name):
    base = slugify(name)[:40] or "project"
    key, n = base, 2
    while Project.objects.filter(key=key).exists():
        key, n = f"{base}-{n}", n + 1
    return key


def suggestion(requested):
    """Form values for a chosen repository folder under the browse root (else None): its path, its name as the title
    and a free key from it."""
    path = under_root(requested) if requested else None
    if path is None or path == browse_root():
        return None
    return {"repo_url": str(path), "name": path.name, "key": unused_key(path.name)}
