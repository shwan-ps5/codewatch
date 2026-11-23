"""tools/research_report.py: the nightly summary's account of the research runs."""

import importlib.util
from datetime import UTC, datetime
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("research_report",
                                              Path(__file__).parent.parent / "tools" / "research_report.py")
assert SPEC is not None and SPEC.loader is not None
research_report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(research_report)

NOW = datetime(2026, 11, 22, 9, 0, tzinfo=UTC)
USAGE = "usage: ses_x deepseek: 46 min, 34 turns, 39 tool calls (0 failed), 1 chars read"


def write_runs(logs, runs):
    for name, lines in runs.items():
        (logs / f"{name}.log").write_text("\n".join(lines) + "\n")


def test_runs_are_counted_and_problems_listed(tmp_path):
    write_runs(tmp_path, {
        "2026-11-21-1000": ["2026-11-21 10:00:06 starting a batch", "2026-11-21 10:40:00 opencode exited 0",
                            "2026-11-21 10:40:00 pushed to research: abc Research: x (12 read, 1 accepted: 1 open, 0 blind);"],
        "2026-11-21-2011": ["2026-11-21 20:11:16 starting a batch", "2026-11-21 22:11:16 opencode exited 124",
                            f"2026-11-21 22:11:16 {USAGE}",
                            "2026-11-21 22:11:16 uncommitted changes left behind, copied to x and removed:"],
        "2026-11-21-2211": ["2026-11-21 22:11:16 working tree not clean (left over from an earlier run?); skipping."],
        "2026-11-22-0300": ["2026-11-22 03:00:07 starting a batch",
                            "\x1b[91mError: \x1b[0mModel unavailable: ollama/model",
                            "2026-11-22 03:00:08 opencode exited 1", f"2026-11-22 03:00:08 {USAGE}",
                            "2026-11-22 03:00:08 no commits; nothing to push"],
        "2026-11-22-0400": ["2026-11-22 04:00:06 starting a batch", "2026-11-22 04:46:04 opencode exited 0",
                            f"2026-11-22 04:46:04 {USAGE}",
                            "2026-11-22 04:46:05 pushed to research: d Research: y (9 read, 1 accepted: 0 open, 1 blind);"],
        "2026-11-22-0500": ["2026-11-22 05:00:06 starting a batch", "2026-11-22 05:10:00 opencode exited 0",
                            f"2026-11-22 05:10:00 {USAGE}", "2026-11-22 05:10:00 no commits; nothing to push"],
        "2026-11-22-0600": ["2026-11-22 06:00:06 3 batches waiting for review; skipping"],
        "2026-11-20-0400": ["2026-11-20 04:00:06 git fetch failed"],             # older than 24 hours
    })
    (tmp_path / "leftover-2026-11-21-2211").mkdir()
    (tmp_path / "leftover-2026-11-19-1000").mkdir()                              # older than 24 hours
    states = {"codewatch-research.timer": "active", "codewatch-research.service": "inactive"}
    lines = research_report.report(tmp_path, 24, now=NOW, states=states).splitlines()
    assert lines[0] == ("runs: 7 in 24 h (2 pushed a batch, 1 found nothing to commit, 1 skipped, 3 with problems); "
                        "read 21, accepted by the agents 2 (1 open, 1 blind)")
    assert lines[1:] == [
        "  2026-11-21 20:11 problem: agent stopped at the time limit; batch left uncommitted",
        "  2026-11-21 22:11 problem: working tree not clean (left over from an earlier run?); skipping.",
        "  2026-11-22 03:00 problem: agent exited 1: Error: Model unavailable: ollama/model",
        "  2026-11-22 06:00 skipped: 3 batches waiting for review; skipping",
        "left uncommitted, kept for a look: leftover-2026-11-21-2211",
    ]


def test_a_stalled_runner_is_a_warning(tmp_path):
    write_runs(tmp_path, {"2026-11-22-0100": ["2026-11-22 01:00:06 working tree not clean; skipping."]})
    states = {"codewatch-research.timer": "inactive", "codewatch-research.service": "failed"}
    report = research_report.report(tmp_path, 24, now=NOW, states=states)
    assert "WARNING: the codewatch-research timer is inactive" in report
    assert "WARNING: the last codewatch-research run failed" in report
    assert "WARNING: no batch pushed in 24 h" in report
    assert "WARNING: no research runs in 1 h" in research_report.report(tmp_path, 1, now=NOW, states=states)


def test_the_gap_notes_runner_is_asked_about_its_own_units(tmp_path):
    write_runs(tmp_path, {"2026-11-22-0830": ["2026-11-22 08:30:06 starting a batch"]})
    states = {"codewatch-research-gaps.timer": "inactive", "codewatch-research.timer": "active"}
    report = research_report.report(tmp_path, 24, now=NOW, states=states, unit="codewatch-research-gaps")
    assert "WARNING: the codewatch-research-gaps timer is inactive" in report


def test_gap_notes_batches_count_as_pushed(tmp_path):
    write_runs(tmp_path, {"2026-11-22-2338": [
        "2026-11-22 23:38:24 starting a batch", "2026-11-22 23:40:46 opencode exited 0",
        "2026-11-22 23:40:48 pushed to research-gaps: 95a3077 Gap notes: 15 cases (2 source, 1 sink);"]})
    states = {"codewatch-research-gaps.timer": "active"}
    first = research_report.report(tmp_path, 24, now=NOW, states=states, unit="codewatch-research-gaps").splitlines()[0]
    assert first.startswith("runs: 1 in 24 h (1 pushed a batch, 0 found nothing to commit")
    assert "read 15," in first
