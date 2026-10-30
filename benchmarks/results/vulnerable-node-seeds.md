# vulnerable-node-seeds

vulnerable-node's SAST seeds: one known vulnerability per file plus clean controls that must stay quiet. Not held out: its first scan missed the SQL concatenation, NoSQL operator, prototype pollution and deserialization seeds and raised a false alarm on a clean control, which led to the JS guard sanitizer, SQL value-formatting and prototype-pollution rules. Measures detection and false alarms.

Commit `d68f2a3c92` (BSD-3-Clause), scanned 2026-10-30T23:20:10+00:00.

Verdict mode counts only findings that claim a vulnerability; review mode adds security hotspots.

## Verdict mode

**Detection 92% (11 of 12 vulnerable files), false alarms 0% (0 of 2 safe files)**

| CWE | Detected | Missed | False alarms | Correctly quiet |
|---|---|---|---|---|
| CWE-1321 | 1 | 0 | 0 | 0 |
| CWE-1333 | 1 | 0 | 0 | 0 |
| CWE-22 | 1 | 0 | 0 | 0 |
| CWE-327 | 1 | 0 | 0 | 0 |
| CWE-502 | 1 | 0 | 0 | 0 |
| CWE-601 | 1 | 0 | 0 | 0 |
| CWE-79 | 1 | 0 | 0 | 0 |
| CWE-798 | 1 | 0 | 0 | 0 |
| CWE-89 | 1 | 0 | 0 | 0 |
| CWE-918 | 1 | 0 | 0 | 0 |
| CWE-943 | 0 | 1 | 0 | 0 |
| CWE-95 | 1 | 0 | 0 | 0 |
| clean controls | 0 | 0 | 0 | 2 |

## Review mode

**Detection 100% (12 of 12 vulnerable files), false alarms 50% (1 of 2 safe files)**

| CWE | Detected | Missed | False alarms | Correctly quiet |
|---|---|---|---|---|
| CWE-1321 | 1 | 0 | 0 | 0 |
| CWE-1333 | 1 | 0 | 0 | 0 |
| CWE-22 | 1 | 0 | 0 | 0 |
| CWE-327 | 1 | 0 | 0 | 0 |
| CWE-502 | 1 | 0 | 0 | 0 |
| CWE-601 | 1 | 0 | 0 | 0 |
| CWE-79 | 1 | 0 | 0 | 0 |
| CWE-798 | 1 | 0 | 0 | 0 |
| CWE-89 | 1 | 0 | 0 | 0 |
| CWE-918 | 1 | 0 | 0 | 0 |
| CWE-943 | 1 | 0 | 0 | 0 |
| CWE-95 | 1 | 0 | 0 | 0 |
| clean controls | 0 | 0 | 1 | 1 |

