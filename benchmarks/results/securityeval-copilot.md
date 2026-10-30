# securityeval-copilot

SecurityEval's Copilot-generated answers to the same prompts, each manually labelled vulnerable or safe. Held out: never used to write or tune codewatch rules. Measures detection and false alarms.

Commit `6f4fb70f78` (none stated (research dataset)), scanned 2026-10-30T22:11:57+00:00.

Verdict mode counts only findings that claim a vulnerability; review mode adds security hotspots.

## Verdict mode

**Detection 34% (33 of 96 vulnerable files), false alarms 0% (0 of 34 safe files)**

| CWE | Detected | Missed | False alarms | Correctly quiet |
|---|---|---|---|---|
| CWE-113 | 0 | 2 | 0 | 0 |
| CWE-116 | 0 | 2 | 0 | 0 |
| CWE-117 | 0 | 2 | 0 | 1 |
| CWE-1204 | 1 | 0 | 0 | 0 |
| CWE-193 | 0 | 0 | 0 | 1 |
| CWE-20 | 0 | 6 | 0 | 0 |
| CWE-200 | 0 | 0 | 0 | 1 |
| CWE-209 | 0 | 1 | 0 | 0 |
| CWE-215 | 0 | 1 | 0 | 1 |
| CWE-22 | 3 | 0 | 0 | 1 |
| CWE-250 | 0 | 0 | 0 | 1 |
| CWE-252 | 0 | 1 | 0 | 0 |
| CWE-259 | 0 | 2 | 0 | 0 |
| CWE-269 | 0 | 0 | 0 | 1 |
| CWE-283 | 0 | 1 | 0 | 0 |
| CWE-284 | 0 | 0 | 0 | 1 |
| CWE-285 | 0 | 1 | 0 | 0 |
| CWE-295 | 0 | 2 | 0 | 1 |
| CWE-297 | 2 | 0 | 0 | 2 |
| CWE-306 | 0 | 0 | 0 | 1 |
| CWE-312 | 0 | 1 | 0 | 0 |
| CWE-319 | 1 | 1 | 0 | 0 |
| CWE-321 | 0 | 0 | 0 | 1 |
| CWE-326 | 0 | 0 | 0 | 2 |
| CWE-327 | 1 | 3 | 0 | 0 |
| CWE-329 | 0 | 0 | 0 | 1 |
| CWE-330 | 1 | 0 | 0 | 0 |
| CWE-331 | 0 | 1 | 0 | 0 |
| CWE-339 | 0 | 1 | 0 | 0 |
| CWE-347 | 0 | 0 | 0 | 3 |
| CWE-352 | 0 | 0 | 0 | 1 |
| CWE-367 | 0 | 0 | 0 | 1 |
| CWE-377 | 1 | 0 | 0 | 0 |
| CWE-379 | 0 | 0 | 0 | 1 |
| CWE-384 | 0 | 1 | 0 | 0 |
| CWE-385 | 0 | 1 | 0 | 0 |
| CWE-400 | 1 | 0 | 0 | 0 |
| CWE-406 | 0 | 0 | 0 | 1 |
| CWE-414 | 0 | 1 | 0 | 0 |
| CWE-425 | 0 | 1 | 0 | 0 |
| CWE-434 | 0 | 2 | 0 | 0 |
| CWE-454 | 0 | 1 | 0 | 0 |
| CWE-462 | 0 | 0 | 0 | 1 |
| CWE-477 | 0 | 0 | 0 | 1 |
| CWE-488 | 0 | 0 | 0 | 1 |
| CWE-502 | 1 | 3 | 0 | 0 |
| CWE-521 | 0 | 0 | 0 | 2 |
| CWE-522 | 0 | 2 | 0 | 0 |
| CWE-595 | 0 | 1 | 0 | 0 |
| CWE-601 | 5 | 0 | 0 | 0 |
| CWE-605 | 0 | 1 | 0 | 0 |
| CWE-611 | 2 | 4 | 0 | 0 |
| CWE-641 | 0 | 1 | 0 | 0 |
| CWE-643 | 1 | 1 | 0 | 0 |
| CWE-703 | 0 | 0 | 0 | 3 |
| CWE-730 | 2 | 0 | 0 | 1 |
| CWE-732 | 0 | 0 | 0 | 1 |
| CWE-759 | 0 | 1 | 0 | 0 |
| CWE-760 | 0 | 1 | 0 | 0 |
| CWE-776 | 0 | 1 | 0 | 0 |
| CWE-78 | 1 | 1 | 0 | 0 |
| CWE-79 | 3 | 0 | 0 | 0 |
| CWE-798 | 0 | 2 | 0 | 0 |
| CWE-80 | 1 | 0 | 0 | 0 |
| CWE-827 | 0 | 1 | 0 | 0 |
| CWE-835 | 0 | 1 | 0 | 0 |
| CWE-841 | 0 | 1 | 0 | 0 |
| CWE-89 | 0 | 2 | 0 | 0 |
| CWE-90 | 2 | 0 | 0 | 0 |
| CWE-918 | 1 | 1 | 0 | 0 |
| CWE-94 | 3 | 0 | 0 | 0 |
| CWE-941 | 0 | 0 | 0 | 1 |
| CWE-943 | 0 | 1 | 0 | 0 |
| CWE-95 | 0 | 1 | 0 | 0 |
| CWE-99 | 0 | 1 | 0 | 0 |

## Review mode

**Detection 51% (49 of 96 vulnerable files), false alarms 6% (2 of 34 safe files)**

| CWE | Detected | Missed | False alarms | Correctly quiet |
|---|---|---|---|---|
| CWE-113 | 0 | 2 | 0 | 0 |
| CWE-116 | 0 | 2 | 0 | 0 |
| CWE-117 | 2 | 0 | 0 | 1 |
| CWE-1204 | 1 | 0 | 0 | 0 |
| CWE-193 | 0 | 0 | 0 | 1 |
| CWE-20 | 2 | 4 | 0 | 0 |
| CWE-200 | 0 | 0 | 0 | 1 |
| CWE-209 | 0 | 1 | 0 | 0 |
| CWE-215 | 0 | 1 | 0 | 1 |
| CWE-22 | 3 | 0 | 1 | 0 |
| CWE-250 | 0 | 0 | 0 | 1 |
| CWE-252 | 0 | 1 | 0 | 0 |
| CWE-259 | 2 | 0 | 0 | 0 |
| CWE-269 | 0 | 0 | 0 | 1 |
| CWE-283 | 0 | 1 | 0 | 0 |
| CWE-284 | 0 | 0 | 0 | 1 |
| CWE-285 | 0 | 1 | 0 | 0 |
| CWE-295 | 0 | 2 | 0 | 1 |
| CWE-297 | 2 | 0 | 0 | 2 |
| CWE-306 | 0 | 0 | 0 | 1 |
| CWE-312 | 0 | 1 | 0 | 0 |
| CWE-319 | 1 | 1 | 0 | 0 |
| CWE-321 | 0 | 0 | 1 | 0 |
| CWE-326 | 0 | 0 | 0 | 2 |
| CWE-327 | 1 | 3 | 0 | 0 |
| CWE-329 | 0 | 0 | 0 | 1 |
| CWE-330 | 1 | 0 | 0 | 0 |
| CWE-331 | 0 | 1 | 0 | 0 |
| CWE-339 | 0 | 1 | 0 | 0 |
| CWE-347 | 0 | 0 | 0 | 3 |
| CWE-352 | 0 | 0 | 0 | 1 |
| CWE-367 | 0 | 0 | 0 | 1 |
| CWE-377 | 1 | 0 | 0 | 0 |
| CWE-379 | 0 | 0 | 0 | 1 |
| CWE-384 | 0 | 1 | 0 | 0 |
| CWE-385 | 0 | 1 | 0 | 0 |
| CWE-400 | 1 | 0 | 0 | 0 |
| CWE-406 | 0 | 0 | 0 | 1 |
| CWE-414 | 0 | 1 | 0 | 0 |
| CWE-425 | 0 | 1 | 0 | 0 |
| CWE-434 | 2 | 0 | 0 | 0 |
| CWE-454 | 0 | 1 | 0 | 0 |
| CWE-462 | 0 | 0 | 0 | 1 |
| CWE-477 | 0 | 0 | 0 | 1 |
| CWE-488 | 0 | 0 | 0 | 1 |
| CWE-502 | 4 | 0 | 0 | 0 |
| CWE-521 | 0 | 0 | 0 | 2 |
| CWE-522 | 0 | 2 | 0 | 0 |
| CWE-595 | 0 | 1 | 0 | 0 |
| CWE-601 | 5 | 0 | 0 | 0 |
| CWE-605 | 0 | 1 | 0 | 0 |
| CWE-611 | 2 | 4 | 0 | 0 |
| CWE-641 | 0 | 1 | 0 | 0 |
| CWE-643 | 1 | 1 | 0 | 0 |
| CWE-703 | 0 | 0 | 0 | 3 |
| CWE-730 | 2 | 0 | 0 | 1 |
| CWE-732 | 0 | 0 | 0 | 1 |
| CWE-759 | 0 | 1 | 0 | 0 |
| CWE-760 | 0 | 1 | 0 | 0 |
| CWE-776 | 0 | 1 | 0 | 0 |
| CWE-78 | 2 | 0 | 0 | 0 |
| CWE-79 | 3 | 0 | 0 | 0 |
| CWE-798 | 2 | 0 | 0 | 0 |
| CWE-80 | 1 | 0 | 0 | 0 |
| CWE-827 | 0 | 1 | 0 | 0 |
| CWE-835 | 0 | 1 | 0 | 0 |
| CWE-841 | 0 | 1 | 0 | 0 |
| CWE-89 | 0 | 2 | 0 | 0 |
| CWE-90 | 2 | 0 | 0 | 0 |
| CWE-918 | 2 | 0 | 0 | 0 |
| CWE-94 | 3 | 0 | 0 | 0 |
| CWE-941 | 0 | 0 | 0 | 1 |
| CWE-943 | 0 | 1 | 0 | 0 |
| CWE-95 | 1 | 0 | 0 | 0 |
| CWE-99 | 0 | 1 | 0 | 0 |

