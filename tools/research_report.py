"""What the unattended research runs did lately, for the nightly summary: runs, batches pushed, and anything that
went wrong (a failed or timed-out agent, a skipped run, a batch left uncommitted), so a stalled runner shows up in
the morning report instead of as a quiet run of empty hours.

    python3 -I tools/research_report.py [--logs DIR] [--unit NAME] [--hours N]

Reads tools/research-batch.sh's logs (one file per run, named YYYY-MM-DD-HHMM.log, lines "YYYY-MM-DD HH:MM:SS
message") from ~/.cache/codewatch/research by default, and asks systemd about NAME.timer and NAME.service
(codewatch-research by default; the gap-notes runner's are research-gaps and codewatch-research-gaps). Standard
library only.
"""

import argparse
import re
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

LOG_NAME = re.compile(r"^(\d{4}-\d{2}-\d{2}-\d{4})\.log$")
LINE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} (.*)$")
COUNTS = re.compile(r"\((\d+) read, (\d+) accepted: (\d+) open, (\d+) blind\)")
NOTED = re.compile(r"Gap notes: (\d+) cases?\b")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
# research-batch.sh's own failure messages (not the usage line's "(0 failed)" tool-call count).
FAILURE = re.compile(r"^(git fetch( of \S+)? failed|working tree not clean|local commits not on origin|gh pr list failed"
                     r"|can't |check failed|push failed)")


def runs_since(logs, since):
    """(start time, path) of each run's log since `since`, oldest first."""
    found = []
    for path in logs.glob("*.log"):
        match = LOG_NAME.match(path.name)
        if match:
            # The log names are the runner's local clock, which is the clock `since` was taken on.
            started = datetime.strptime(match.group(1), "%Y-%m-%d-%H%M").replace(tzinfo=since.tzinfo)
            if started >= since:
                found.append((started, path))
    return sorted(found)


def first_error(text):
    """The agent's own error line, when it printed one (e.g. "Error: Model unavailable: ...")."""
    for line in ANSI.sub("", text).splitlines():
        if line.strip().startswith("Error"):
            return line.strip()[:160]
    return ""


def starting(messages, prefix):
    """The script's messages that start with `prefix`."""
    return [m for m in messages if m.startswith(prefix)]


def agent_note(messages, text):
    """How the agent ended, when it didn't end normally."""
    exited = starting(messages, "opencode exited ")
    code = exited[-1].rsplit(" ", 1)[-1] if exited else "0"
    if code == "124":
        return ["agent stopped at the time limit"]
    if code == "0":
        return []
    error = first_error(text)
    return [f"agent exited {code}: {error}" if error else f"agent exited {code}"]


def batch_counts(pushes):
    """(read, accepted, open, blind) of each batch pushed. A gap-notes batch (AGENTS.md section 9) counts its cases as
    read; it accepts nothing."""
    counts = [tuple(map(int, c)) for m in pushes for c in COUNTS.findall(m)]
    return counts + [(int(n), 0, 0, 0) for m in pushes for n in NOTED.findall(m)]


def classify(text):
    """One run's outcome: (kind, detail, counts of each batch pushed). kind is batch, empty, skipped or problem."""
    messages = [m.group(1) for m in map(LINE.match, text.splitlines()) if m]
    counts = batch_counts(starting(messages, "pushed to "))
    notes = agent_note(messages, text)
    notes += ["batch left uncommitted"] * len(starting(messages, "uncommitted changes left behind"))
    notes += list(filter(FAILURE.match, messages))
    if notes:
        return "problem", "; ".join(notes), counts
    if counts:
        return "batch", "", counts
    skipped = [m for m in messages if m.endswith("skipping")]
    return ("skipped", skipped[-1], counts) if skipped else ("empty", "", counts)


def unit_state(unit):
    """systemctl's word for a user unit, or None where systemd isn't there to ask."""
    try:
        result = subprocess.run(["systemctl", "--user", "is-active", unit], capture_output=True, text=True,
                                timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() or None


def tally_runs(runs):
    """(runs per kind, totals of read/accepted/open/blind, runs that pushed a batch, one line per problem run)."""
    tally = {"batch": 0, "empty": 0, "skipped": 0, "problem": 0}
    totals = [0, 0, 0, 0]
    pushed = 0
    problems = []
    for started, path in runs:
        kind, detail, counts = classify(path.read_text(errors="replace"))
        tally[kind] += 1
        pushed += bool(counts)
        for batch in counts:
            totals = [a + b for a, b in zip(totals, batch, strict=True)]
        if kind in ("problem", "skipped"):
            problems.append(f"  {started:%Y-%m-%d %H:%M} {kind}: {detail}")
    return tally, totals, pushed, problems


def warnings(states, runs, pushed, hours, unit="codewatch-research"):
    """What needs a look before anything else: the timer stopped, the last run failed, nothing coming through."""
    found = []
    timer = states.get(f"{unit}.timer")
    if timer not in (None, "active"):
        found.append(f"WARNING: the {unit} timer is {timer}")
    if states.get(f"{unit}.service") == "failed":
        found.append(f"WARNING: the last {unit} run failed (systemctl --user status {unit}.service)")
    if not runs:
        found.append(f"WARNING: no research runs in {hours} h")
    elif not pushed:
        found.append(f"WARNING: no batch pushed in {hours} h")
    return found


def report(logs, hours, now=None, states=None, unit="codewatch-research"):
    now = now or datetime.now().astimezone()
    since = now - timedelta(hours=hours)
    runs = runs_since(logs, since)
    tally, totals, pushed, problems = tally_runs(runs)
    lines = [(f"runs: {len(runs)} in {hours} h ({pushed} pushed a batch, {tally['empty']} found nothing to commit, "
              f"{tally['skipped']} skipped, {tally['problem']} with problems); read {totals[0]}, accepted by the "
              f"agents {totals[1]} ({totals[2]} open, {totals[3]} blind)")]
    if states is None:
        states = {name: unit_state(name) for name in (f"{unit}.timer", f"{unit}.service")}
    lines += warnings(states, runs, pushed, hours, unit) + problems
    oldest = f"leftover-{since:%Y-%m-%d-%H%M}"
    leftovers = sorted(p.name for p in logs.glob("leftover-*") if p.is_dir() and p.name >= oldest)
    if leftovers:
        lines.append(f"left uncommitted, kept for a look: {', '.join(leftovers)}")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="What the unattended research runs did lately.")
    parser.add_argument("--logs", type=Path, default=Path.home() / ".cache/codewatch/research")
    parser.add_argument("--unit", default="codewatch-research", help="the systemd units' name, without .timer")
    parser.add_argument("--hours", type=int, default=24)
    args = parser.parse_args(argv)
    if not args.logs.is_dir():
        print(f"no research logs ({args.logs})")
        return 0
    print(report(args.logs, args.hours, unit=args.unit))
    return 0


if __name__ == "__main__":
    sys.exit(main())
