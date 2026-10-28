import hashlib
from collections import Counter


def normalize(text):
    return " ".join(text.split())


def assign_fingerprints(findings, read_line):
    """Fingerprint from rule, file and source text rather than line number, so issues survive edits above them.

    read_line(path, line) returns that line's text (or "" if unavailable). Identical issues on identical lines
    in the same file are told apart by occurrence order.
    """
    seen = Counter()
    fingerprints = {}
    for f in sorted(findings, key=lambda f: (f.path, f.line or 0, f.tool, f.rule)):
        anchor = normalize(read_line(f.path, f.line)) if f.line else normalize(f.message)
        key = (f.tool, f.rule, f.path, anchor)
        seen[key] += 1
        raw = "\0".join([*key, str(seen[key])])
        # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
        fingerprints[id(f)] = hashlib.sha1(raw.encode(), usedforsecurity=False).hexdigest()
    return [fingerprints[id(f)] for f in findings]
