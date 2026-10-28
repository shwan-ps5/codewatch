# owasp-benchmark-python

OWASP Benchmark for Python: each test case is a small Flask handler that is or is not really vulnerable to one CWE. Measures detection and false alarms.

Commit `f129148580` (GPL-3.0), scanned 2026-10-28T23:38:53+00:00.

Verdict mode counts only findings that claim a vulnerability; review mode adds security hotspots.

## Verdict mode

**Detection 74%, false alarms 35%, score +40%** (detection minus false alarms, averaged over categories)

| Category | CWE | Detected | Missed | False alarms | Correctly quiet | Detection | False alarms | Score |
|---|---|---|---|---|---|---|---|---|
| cmdi | 78 | 10 | 3 | 4 | 3 | 77% | 57% | +20% |
| codeinj | 94 | 17 | 3 | 10 | 23 | 85% | 30% | +55% |
| deserialization | 502 | 12 | 6 | 7 | 29 | 67% | 19% | +47% |
| hash | 328 | 68 | 3 | 0 | 80 | 96% | 0% | +96% |
| ldapi | 90 | 13 | 3 | 9 | 4 | 81% | 69% | +12% |
| pathtraver | 22 | 29 | 36 | 41 | 62 | 45% | 40% | +5% |
| redirect | 601 | 9 | 4 | 9 | 12 | 69% | 43% | +26% |
| securecookie | 614 | 24 | 0 | 0 | 15 | 100% | 0% | +100% |
| sqli | 89 | 3 | 2 | 0 | 11 | 60% | 0% | +60% |
| trustbound | 501 | 12 | 6 | 15 | 4 | 67% | 79% | -12% |
| weakrand | 330 | 56 | 43 | 0 | 227 | 57% | 0% | +57% |
| xpathi | 643 | 40 | 11 | 83 | 52 | 78% | 62% | +17% |
| xss | 79 | 18 | 13 | 29 | 29 | 58% | 50% | +8% |
| xxe | 611 | 8 | 0 | 7 | 13 | 100% | 35% | +65% |

## Review mode

**Detection 84%, false alarms 59%, score +25%** (detection minus false alarms, averaged over categories)

| Category | CWE | Detected | Missed | False alarms | Correctly quiet | Detection | False alarms | Score |
|---|---|---|---|---|---|---|---|---|
| cmdi | 78 | 13 | 0 | 7 | 0 | 100% | 100% | +0% |
| codeinj | 94 | 20 | 0 | 33 | 0 | 100% | 100% | +0% |
| deserialization | 502 | 18 | 0 | 12 | 24 | 100% | 33% | +67% |
| hash | 328 | 69 | 2 | 0 | 80 | 97% | 0% | +97% |
| ldapi | 90 | 13 | 3 | 9 | 4 | 81% | 69% | +12% |
| pathtraver | 22 | 29 | 36 | 41 | 62 | 45% | 40% | +5% |
| redirect | 601 | 9 | 4 | 10 | 11 | 69% | 48% | +22% |
| securecookie | 614 | 24 | 0 | 15 | 0 | 100% | 100% | +0% |
| sqli | 89 | 5 | 0 | 11 | 0 | 100% | 100% | +0% |
| trustbound | 501 | 12 | 6 | 15 | 4 | 67% | 79% | -12% |
| weakrand | 330 | 77 | 22 | 0 | 227 | 78% | 0% | +78% |
| xpathi | 643 | 40 | 11 | 83 | 52 | 78% | 62% | +17% |
| xss | 79 | 18 | 13 | 36 | 22 | 58% | 62% | -4% |
| xxe | 611 | 8 | 0 | 7 | 13 | 100% | 35% | +65% |

