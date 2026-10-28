import subprocess

import pytest
from django.contrib.auth.models import User

from core.analyzers import ANALYZERS
from core.models import ApiToken

ONLY_RUFF = [a.name for a in ANALYZERS if a.name not in ("ruff", "coverage")]


def sh(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path, settings):
    settings.CODEWATCH_CACHE = tmp_path / "cache"
    repo = tmp_path / "repo"
    repo.mkdir()
    sh(repo, "init", "-q", "-b", "main")
    sh(repo, "config", "user.email", "t@example.com")
    sh(repo, "config", "user.name", "t")
    (repo / "app.py").write_text("import os\n\n\ndef f():\n    return 1\n")
    sh(repo, "add", ".")
    sh(repo, "commit", "-qm", "init")
    return repo


@pytest.fixture
def alice(db):
    return User.objects.create_user("alice", password="pw-alice-123")


@pytest.fixture
def bob(db):
    return User.objects.create_user("bob", password="pw-bob-123")


def token_for(user, scope=ApiToken.SCAN):
    return ApiToken.issue(user, "test", scope)[1]


def auth(raw):
    return {"HTTP_AUTHORIZATION": f"Bearer {raw}"}
