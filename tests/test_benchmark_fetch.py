"""fetch_pair keeps a cached clone's checkout in step with the case's scope (SQLBot GHSA-fghj-qqgj-7rxf)."""
import subprocess

from core import benchmark


def _git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


def test_a_widened_scope_reaches_an_existing_clone(tmp_path, monkeypatch):
    origin = tmp_path / "origin"
    (origin / "app" / "api").mkdir(parents=True)
    (origin / "app" / "models").mkdir()
    _git("init", "-q", cwd=origin)
    _git("config", "user.email", "t@example.com", cwd=origin)
    _git("config", "user.name", "t", cwd=origin)
    (origin / "app" / "api" / "views.py").write_text("a = 1\n")
    (origin / "app" / "models" / "models.py").write_text("b = 1\n")
    _git("add", ".", cwd=origin)
    _git("commit", "-qm", "one", cwd=origin)
    (origin / "app" / "api" / "views.py").write_text("a = 2\n")
    _git("commit", "-qam", "fix", cwd=origin)
    fix = _git("rev-parse", "HEAD", cwd=origin).strip()
    _git("config", "uploadpack.allowFilter", "true", cwd=origin)
    _git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=origin)
    monkeypatch.setattr(benchmark, "CACHE", tmp_path / "cache")
    suite = {"name": "s"}
    case = {"id": "GHSA-x", "repo": f"file://{origin}", "fix": fix, "scope": ["app/api"]}
    target, _ = benchmark.fetch_pair(suite, case)
    _git("checkout", "-q", fix, cwd=target)
    assert not (target / "app" / "models" / "models.py").exists()
    target, _ = benchmark.fetch_pair(suite, {**case, "scope": ["app"]})
    assert (target / "app" / "models" / "models.py").exists()
