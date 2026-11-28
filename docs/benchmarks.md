# Running the benchmarks yourself

Everything the README's numbers come from is in this repository: the suite definitions and ground truth
(`benchmarks/suites.json`), the scorer (`core/benchmark.py`) and the nightly script (`benchmarks/nightly.sh`).
Anyone with a Linux machine can reproduce them. Nothing depends on the maintainer's machine except the private
apps used as a false-alarm check, which are listed only by count.

## Setup

```
python3 -m venv venv && venv/bin/pip install -e '.[dev]'
make tools
venv/bin/pytest -q -n auto      # the detection tests must run, not skip
```

## Commands

| What | Command | Time |
|---|---|---|
| The smoke set CI runs (23 CVE pairs) | `venv/bin/python benchmarks/smoke.py` | ~10 min |
| Some CVE pairs, by id prefix | `venv/bin/python benchmarks/devtools.py cases GHSA-xxxx ...` | a minute each |
| One suite | `venv/bin/python benchmarks/devtools.py bench cve-pairs-python` | ~1 h |
| Every non-blind suite | `venv/bin/python benchmarks/devtools.py bench` | several hours |
| The whole nightly (lint, tests, suites, apps) | `benchmarks/nightly.sh detection-gaps` | overnight |

`CODEWATCH_BENCH_WORKERS` sets how many scans run at once (default: a third of the CPUs). Each takes up to a few
GB of memory. CVE pairs are fetched shallowly (two commits, blobs on demand, only the case's `scope` folders)
into `~/.cache/codewatch/benchmarks/`. Results go to `benchmarks/results/`; run `git checkout benchmarks/results`
afterwards unless you mean to commit them.

For a run against apps that should be clean, list their directories in `~/.config/codewatch/nightly-apps.txt`,
one per line. Any finding there is a false alarm until read.

## How a CVE pair is scored

Each side of the fix is scanned, limited to the files the fix changed plus what renders or imports them.

- **Found:** a finding of the advisory's weakness (its CWE or a parent) lands near the lines the fix changed,
  or the fix makes a finding of that weakness disappear.
- **Still flagged:** a finding of that weakness survives on the fixed side.

**Verdict** mode counts only findings that claim a vulnerability. **Review** mode adds security hotspots.

## Blind and held-out suites

- **Blind suites** are split off before any scan by a fixed rule: `int(sha256(id), 16) % 3 == 0`. They are run
  once, at the end of a round. Don't run them to check a rule change; once run, a suite is no longer blind.
- **Held-out suites** were never used to write or tune rules. They're the fairer measure.

The README lists both first for that reason.
