# securityeval

SecurityEval: 121 insecure Python samples filed under the CWE they demonstrate. Measures detection only; every sample is vulnerable. Was held out until 2026-10-30, when its misses against SonarQube were used to add codewatch's crypto/TLS rules.

Commit `6f4fb70f78` (none stated (research dataset)), scanned 2026-10-30T02:03:28+00:00.

Verdict mode counts only findings that claim a vulnerability; review mode adds security hotspots.

## Verdict mode

**44 of 121 vulnerable files flagged for their CWE (36%); 47% have some security finding**

| CWE | Flagged | Files |
|---|---|---|
| CWE-20 | 0 | 6 |
| CWE-22 | 2 | 4 |
| CWE-78 | 1 | 2 |
| CWE-79 | 3 | 3 |
| CWE-80 | 1 | 1 |
| CWE-89 | 0 | 2 |
| CWE-90 | 2 | 2 |
| CWE-94 | 3 | 3 |
| CWE-95 | 0 | 1 |
| CWE-99 | 0 | 1 |
| CWE-113 | 0 | 2 |
| CWE-116 | 0 | 2 |
| CWE-117 | 0 | 3 |
| CWE-193 | 0 | 1 |
| CWE-200 | 0 | 1 |
| CWE-209 | 0 | 1 |
| CWE-215 | 0 | 1 |
| CWE-250 | 0 | 1 |
| CWE-252 | 0 | 1 |
| CWE-259 | 0 | 2 |
| CWE-269 | 0 | 1 |
| CWE-283 | 0 | 1 |
| CWE-285 | 0 | 1 |
| CWE-295 | 2 | 3 |
| CWE-306 | 0 | 1 |
| CWE-319 | 2 | 2 |
| CWE-321 | 0 | 2 |
| CWE-326 | 2 | 2 |
| CWE-327 | 2 | 4 |
| CWE-329 | 1 | 1 |
| CWE-330 | 1 | 1 |
| CWE-331 | 1 | 1 |
| CWE-339 | 1 | 1 |
| CWE-347 | 3 | 3 |
| CWE-367 | 0 | 1 |
| CWE-377 | 1 | 1 |
| CWE-379 | 1 | 1 |
| CWE-385 | 0 | 1 |
| CWE-400 | 0 | 1 |
| CWE-406 | 0 | 1 |
| CWE-414 | 0 | 1 |
| CWE-425 | 0 | 1 |
| CWE-434 | 0 | 2 |
| CWE-454 | 0 | 1 |
| CWE-462 | 0 | 1 |
| CWE-477 | 0 | 1 |
| CWE-502 | 1 | 4 |
| CWE-521 | 1 | 2 |
| CWE-522 | 0 | 2 |
| CWE-595 | 0 | 1 |
| CWE-601 | 3 | 5 |
| CWE-605 | 0 | 1 |
| CWE-611 | 3 | 6 |
| CWE-641 | 0 | 1 |
| CWE-643 | 2 | 2 |
| CWE-703 | 0 | 3 |
| CWE-730 | 0 | 3 |
| CWE-732 | 0 | 1 |
| CWE-759 | 1 | 1 |
| CWE-760 | 1 | 1 |
| CWE-776 | 0 | 1 |
| CWE-798 | 0 | 2 |
| CWE-827 | 0 | 1 |
| CWE-835 | 0 | 1 |
| CWE-841 | 0 | 1 |
| CWE-918 | 2 | 2 |
| CWE-941 | 0 | 1 |
| CWE-943 | 0 | 1 |
| CWE-1204 | 1 | 1 |

## Review mode

**64 of 121 vulnerable files flagged for their CWE (53%); 70% have some security finding**

| CWE | Flagged | Files |
|---|---|---|
| CWE-20 | 2 | 6 |
| CWE-22 | 3 | 4 |
| CWE-78 | 2 | 2 |
| CWE-79 | 3 | 3 |
| CWE-80 | 1 | 1 |
| CWE-89 | 2 | 2 |
| CWE-90 | 2 | 2 |
| CWE-94 | 3 | 3 |
| CWE-95 | 1 | 1 |
| CWE-99 | 0 | 1 |
| CWE-113 | 0 | 2 |
| CWE-116 | 0 | 2 |
| CWE-117 | 0 | 3 |
| CWE-193 | 0 | 1 |
| CWE-200 | 0 | 1 |
| CWE-209 | 0 | 1 |
| CWE-215 | 1 | 1 |
| CWE-250 | 0 | 1 |
| CWE-252 | 0 | 1 |
| CWE-259 | 2 | 2 |
| CWE-269 | 0 | 1 |
| CWE-283 | 0 | 1 |
| CWE-285 | 0 | 1 |
| CWE-295 | 2 | 3 |
| CWE-306 | 0 | 1 |
| CWE-319 | 2 | 2 |
| CWE-321 | 2 | 2 |
| CWE-326 | 2 | 2 |
| CWE-327 | 3 | 4 |
| CWE-329 | 1 | 1 |
| CWE-330 | 1 | 1 |
| CWE-331 | 1 | 1 |
| CWE-339 | 1 | 1 |
| CWE-347 | 3 | 3 |
| CWE-367 | 0 | 1 |
| CWE-377 | 1 | 1 |
| CWE-379 | 1 | 1 |
| CWE-385 | 0 | 1 |
| CWE-400 | 0 | 1 |
| CWE-406 | 0 | 1 |
| CWE-414 | 0 | 1 |
| CWE-425 | 0 | 1 |
| CWE-434 | 0 | 2 |
| CWE-454 | 0 | 1 |
| CWE-462 | 0 | 1 |
| CWE-477 | 0 | 1 |
| CWE-502 | 4 | 4 |
| CWE-521 | 1 | 2 |
| CWE-522 | 0 | 2 |
| CWE-595 | 0 | 1 |
| CWE-601 | 3 | 5 |
| CWE-605 | 1 | 1 |
| CWE-611 | 3 | 6 |
| CWE-641 | 0 | 1 |
| CWE-643 | 2 | 2 |
| CWE-703 | 0 | 3 |
| CWE-730 | 0 | 3 |
| CWE-732 | 1 | 1 |
| CWE-759 | 1 | 1 |
| CWE-760 | 1 | 1 |
| CWE-776 | 0 | 1 |
| CWE-798 | 2 | 2 |
| CWE-827 | 0 | 1 |
| CWE-835 | 0 | 1 |
| CWE-841 | 0 | 1 |
| CWE-918 | 2 | 2 |
| CWE-941 | 0 | 1 |
| CWE-943 | 0 | 1 |
| CWE-1204 | 1 | 1 |

