"""The repository's own tool configuration must not stop ruff or radon (langflow, nightly 2026-11-04)."""
import pytest

from core.analyzers.base import Context
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
