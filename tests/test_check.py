"""codewatch check: every analyzer on the changed files, nothing uploaded or run, for a pre-commit hook."""
import json

import pytest

from core import client as cli
from core.analyzers.python_tools import Ruff

from .conftest import ONLY_RUFF, sh

OLD = "def old():\n    return undefined_old\n"  # a critical bug already committed
NEW = OLD + "\n\ndef new():\n    return undefined_new\n"


@pytest.fixture
def work(repo, monkeypatch, capsys):
    """The repo with ruff alone (fast), an old bug committed, and no server configured."""
    monkeypatch.delenv("CODEWATCH_URL", raising=False)
    monkeypatch.delenv("CODEWATCH_TOKEN", raising=False)
    monkeypatch.chdir(repo)
    (repo / "codewatch-project.json").write_text(json.dumps({"projectKey": "demo", "disabledAnalyzers": ONLY_RUFF}))
    (repo / "app.py").write_text(OLD)
    sh(repo, "add", ".")
    sh(repo, "commit", "-qm", "old bug")
    return repo


def check(capsys, *args):
    code = cli.main(["check", *args])
    return code, capsys.readouterr().out.splitlines()


def test_a_staged_change_with_a_bug_on_a_changed_line_blocks(work, capsys):
    (work / "app.py").write_text(NEW)
    sh(work, "add", "app.py")
    code, lines = check(capsys)
    assert code == 1
    assert [line[0] for line in lines if "F821" in line] == [" ", "!"], "only the new line's bug blocks"
    assert any(line.startswith("! app.py:6:") for line in lines)


def test_old_issues_in_a_touched_file_are_listed_but_do_not_block(work, capsys):
    (work / "app.py").write_text(OLD + "\n\ndef fine():\n    return 1\n")
    code, lines = check(capsys)
    assert code == 0 and any("undefined_old" in line for line in lines)


def test_all_lines_blocks_on_any_issue_in_a_named_file(work, capsys):
    assert check(capsys, "app.py")[0] == 0, "nothing changed in it"
    assert check(capsys, "--all-lines", "app.py")[0] == 1


def test_nothing_changed_checks_nothing(work, capsys):
    assert check(capsys) == (0, [])


def test_an_analyzer_failing_means_the_files_were_not_checked(work, capsys, monkeypatch):
    def broken(self, ctx):
        raise RuntimeError("tool crashed")
    monkeypatch.setattr(Ruff, "run", broken)
    (work / "app.py").write_text(OLD + "\nx = 1\n")
    assert check(capsys)[0] == 2


def test_the_pre_commit_hook_runs_check(work):
    assert cli.main(["init", str(work), "--hook", "pre-commit"]) == 0
    hook = (work / ".git" / "hooks" / "pre-commit").read_text()
    assert hook.rstrip().endswith(" check") and "scan" not in hook.split("\n", 3)[-1]


def test_strict_all_blocks_on_any_open_issue_until_it_is_reviewed(work, capsys, monkeypatch, tmp_path):
    (work / "app.py").write_text("import os\n")  # an unused import: a minor smell, which only --strict blocks
    sh(work, "commit", "-qam", "smell")
    assert check(capsys, "--all")[0] == 0
    code, lines = check(capsys, "--all", "--strict")
    assert code == 1 and lines[0].startswith("! app.py:1:")
    fingerprint = _fingerprint(work)
    (work / cli.REVIEWS_FILE).write_text(json.dumps([{"fingerprint": fingerprint, "status": "false_positive",
                                                      "comment": "Kept for the test."}]))
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    code, lines = check(capsys, "--all", "--strict")
    assert code == 0 and lines[0].startswith("= app.py:1:") and "reviewed false_positive: Kept for the test." in lines[1]
    text = summary.read_text()
    assert "## codewatch check passes" in text and "| false_positive | Kept for the test. |" in text


def test_a_review_without_a_reason_is_refused(work, capsys):
    (work / cli.REVIEWS_FILE).write_text(json.dumps([{"fingerprint": "f", "status": "safe", "comment": ""}]))
    assert check(capsys, "--all")[0] == 2


def _fingerprint(work):
    """The unused import's fingerprint, as the check computes it."""
    from core.collect import ScanConfig, ScanInput, collect
    cfg = ScanConfig(disabled_analyzers=ONLY_RUFF)
    payload = collect(cfg, ScanInput(work, ["app.py"], "main", None, local=True), lambda m: None)
    return next(i["fingerprint"] for i in payload["issues"] if i["rule"] == "F401")
