"""The repository's own tool configuration must not stop ruff or radon (langflow, nightly 2026-11-04), nor make
them (or checkov) change its files (flaskbb's `fix = true`, nightly 2026-11-19)."""
import pytest

from core.analyzers.base import Context
from core.analyzers.extra import Checkov
from core.analyzers.python_tools import Radon, Ruff

PYPROJECT = """
[tool.ruff]
required-version = "==0.1.1"

[tool.pytest.ini_options]
log_cli_date_format = "%Y-%m-%d %H:%M:%S"
"""

CODE = "import os\n\n\ndef f(a):\n" + "".join(f"    if a == {i}:\n        return {i}\n" for i in range(12))


@pytest.fixture
def ctx(tmp_path):
    (tmp_path / "pyproject.toml").write_text(PYPROJECT)
    (tmp_path / "app.py").write_text(CODE)
    return Context(root=tmp_path, files=["app.py"])


def test_ruff_runs_despite_pinned_required_version(ctx):
    assert "F401" in [f.rule for f in Ruff().run(ctx).findings]


def test_radon_runs_despite_percent_in_tool_table(ctx):
    result = Radon().run(ctx)
    assert [f.rule for f in result.findings] == ["cyclomatic-complexity"]
    assert "maintainability_index" in result.metrics


def test_ruff_never_fixes_the_scanned_files_whatever_their_config_says(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.ruff]\nfix = true\nunsafe-fixes = true\n")
    (tmp_path / "app.py").write_text(CODE)
    findings = Ruff().run(Context(root=tmp_path, files=["app.py"])).findings
    assert "F401" in [f.rule for f in findings]
    assert (tmp_path / "app.py").read_text() == CODE


def test_checkov_ignores_the_scanned_repositorys_own_config(tmp_path):
    (tmp_path / ".checkov.yaml").write_text("output-file-path: reports\nskip-check: CKV_DOCKER_2,CKV_DOCKER_3\n")
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nRUN pip install flask\n")
    findings = Checkov().run(Context(root=tmp_path, files=["Dockerfile"])).findings
    assert {"CKV_DOCKER_2", "CKV_DOCKER_3"} <= {f.rule for f in findings}
    assert {f.path for f in findings} == {"Dockerfile"}
    assert sorted(p.name for p in tmp_path.iterdir()) == [".checkov.yaml", "Dockerfile"]
