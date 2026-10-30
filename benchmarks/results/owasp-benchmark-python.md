# owasp-benchmark-python

OWASP Benchmark for Python: each test case is a small Flask handler that is or is not really vulnerable to one CWE. Measures detection and false alarms.

Commit `f129148580` (GPL-3.0), scanned 2026-10-30T13:25:34+00:00.

Verdict mode counts only findings that claim a vulnerability; review mode adds security hotspots.

## Verdict mode

**Detection 100%, false alarms 0%, score +100%** (detection minus false alarms, averaged over categories)

| Category | CWE | Detected | Missed | False alarms | Correctly quiet | Detection | False alarms | Score |
|---|---|---|---|---|---|---|---|---|
| cmdi | 78 | 13 | 0 | 0 | 7 | 100% | 0% | +100% |
| codeinj | 94 | 20 | 0 | 0 | 33 | 100% | 0% | +100% |
| deserialization | 502 | 18 | 0 | 0 | 36 | 100% | 0% | +100% |
| hash | 328 | 71 | 0 | 0 | 80 | 100% | 0% | +100% |
| ldapi | 90 | 16 | 0 | 0 | 13 | 100% | 0% | +100% |
| pathtraver | 22 | 65 | 0 | 0 | 103 | 100% | 0% | +100% |
| redirect | 601 | 13 | 0 | 0 | 21 | 100% | 0% | +100% |
| securecookie | 614 | 24 | 0 | 0 | 15 | 100% | 0% | +100% |
| sqli | 89 | 5 | 0 | 0 | 11 | 100% | 0% | +100% |
| trustbound | 501 | 18 | 0 | 0 | 19 | 100% | 0% | +100% |
| weakrand | 330 | 99 | 0 | 0 | 227 | 100% | 0% | +100% |
| xpathi | 643 | 51 | 0 | 0 | 135 | 100% | 0% | +100% |
| xss | 79 | 31 | 0 | 0 | 58 | 100% | 0% | +100% |
| xxe | 611 | 8 | 0 | 0 | 20 | 100% | 0% | +100% |

## Review mode

**Detection 100%, false alarms 35%, score +65%** (detection minus false alarms, averaged over categories)

| Category | CWE | Detected | Missed | False alarms | Correctly quiet | Detection | False alarms | Score |
|---|---|---|---|---|---|---|---|---|
| cmdi | 78 | 13 | 0 | 7 | 0 | 100% | 100% | +0% |
| codeinj | 94 | 20 | 0 | 29 | 4 | 100% | 88% | +12% |
| deserialization | 502 | 18 | 0 | 12 | 24 | 100% | 33% | +67% |
| hash | 328 | 71 | 0 | 0 | 80 | 100% | 0% | +100% |
| ldapi | 90 | 16 | 0 | 0 | 13 | 100% | 0% | +100% |
| pathtraver | 22 | 65 | 0 | 2 | 101 | 100% | 2% | +98% |
| redirect | 601 | 13 | 0 | 1 | 20 | 100% | 5% | +95% |
| securecookie | 614 | 24 | 0 | 15 | 0 | 100% | 100% | +0% |
| sqli | 89 | 5 | 0 | 11 | 0 | 100% | 100% | +0% |
| trustbound | 501 | 18 | 0 | 0 | 19 | 100% | 0% | +100% |
| weakrand | 330 | 99 | 0 | 0 | 227 | 100% | 0% | +100% |
| xpathi | 643 | 51 | 0 | 0 | 135 | 100% | 0% | +100% |
| xss | 79 | 31 | 0 | 16 | 42 | 100% | 28% | +72% |
| xxe | 611 | 8 | 0 | 7 | 13 | 100% | 35% | +65% |

