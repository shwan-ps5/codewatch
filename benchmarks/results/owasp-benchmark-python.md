# owasp-benchmark-python

OWASP Benchmark for Python: each test case is a small Flask handler that is or is not really vulnerable to one CWE. Measures detection and false alarms.

Commit `f129148580` (GPL-3.0), scanned 2026-10-30T02:01:11+00:00.

Verdict mode counts only findings that claim a vulnerability; review mode adds security hotspots.

## Verdict mode

**Detection 88%, false alarms 21%, score +67%** (detection minus false alarms, averaged over categories)

| Category | CWE | Detected | Missed | False alarms | Correctly quiet | Detection | False alarms | Score |
|---|---|---|---|---|---|---|---|---|
| cmdi | 78 | 11 | 2 | 4 | 3 | 85% | 57% | +28% |
| codeinj | 94 | 20 | 0 | 4 | 29 | 100% | 12% | +88% |
| deserialization | 502 | 16 | 2 | 4 | 32 | 89% | 11% | +78% |
| hash | 328 | 68 | 3 | 0 | 80 | 96% | 0% | +96% |
| ldapi | 90 | 15 | 1 | 6 | 7 | 94% | 46% | +48% |
| pathtraver | 22 | 39 | 26 | 16 | 87 | 60% | 16% | +44% |
| redirect | 601 | 12 | 1 | 5 | 16 | 92% | 24% | +68% |
| securecookie | 614 | 24 | 0 | 0 | 15 | 100% | 0% | +100% |
| sqli | 89 | 3 | 2 | 0 | 11 | 60% | 0% | +60% |
| trustbound | 501 | 16 | 2 | 10 | 9 | 89% | 53% | +36% |
| weakrand | 330 | 99 | 0 | 0 | 227 | 100% | 0% | +100% |
| xpathi | 643 | 47 | 4 | 21 | 114 | 92% | 16% | +77% |
| xss | 79 | 23 | 8 | 13 | 45 | 74% | 22% | +52% |
| xxe | 611 | 8 | 0 | 7 | 13 | 100% | 35% | +65% |

## Review mode

**Detection 92%, false alarms 48%, score +44%** (detection minus false alarms, averaged over categories)

| Category | CWE | Detected | Missed | False alarms | Correctly quiet | Detection | False alarms | Score |
|---|---|---|---|---|---|---|---|---|
| cmdi | 78 | 12 | 1 | 7 | 0 | 92% | 100% | -8% |
| codeinj | 94 | 20 | 0 | 33 | 0 | 100% | 100% | +0% |
| deserialization | 502 | 18 | 0 | 12 | 24 | 100% | 33% | +67% |
| hash | 328 | 71 | 0 | 0 | 80 | 100% | 0% | +100% |
| ldapi | 90 | 15 | 1 | 6 | 7 | 94% | 46% | +48% |
| pathtraver | 22 | 39 | 26 | 16 | 87 | 60% | 16% | +44% |
| redirect | 601 | 12 | 1 | 6 | 15 | 92% | 29% | +64% |
| securecookie | 614 | 24 | 0 | 15 | 0 | 100% | 100% | +0% |
| sqli | 89 | 5 | 0 | 11 | 0 | 100% | 100% | +0% |
| trustbound | 501 | 16 | 2 | 10 | 9 | 89% | 53% | +36% |
| weakrand | 330 | 99 | 0 | 0 | 227 | 100% | 0% | +100% |
| xpathi | 643 | 47 | 4 | 21 | 114 | 92% | 16% | +77% |
| xss | 79 | 23 | 8 | 29 | 29 | 74% | 50% | +24% |
| xxe | 611 | 8 | 0 | 7 | 13 | 100% | 35% | +65% |

