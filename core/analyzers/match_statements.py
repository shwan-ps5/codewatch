"""Rewrite Python `match` statements as `if` blocks for Semgrep.

Semgrep OSS parses `match` but silently skips the rest of the function after one, so findings below it are lost.
In the copy it scans (never run; every line keeps its place) `match x:` becomes `if True:` and each `case p:`
becomes `if x == (p):`, which keeps every case reachable and the data flow through them.
"""
import ast
import re

CASE_RE = re.compile(r"^(\s*)case\b")


def expression(text):
    try:
        ast.parse(text, mode="eval")
    except SyntaxError:
        return False
    return True


def colon_after(line, col):
    """Index of the first ":" at or after col that ends the header (the rest is blank or a comment)."""
    i = line.find(":", col)
    while i != -1:
        if not line[i + 1:].strip() or line[i + 1:].lstrip().startswith("#"):
            return i
        i = line.find(":", i + 1)
    return -1


def case_header(source, lines, case, subject):
    if case.pattern.lineno != case.pattern.end_lineno or (case.guard and case.guard.end_lineno != case.pattern.lineno):
        return None
    pattern = ast.get_source_segment(source, case.pattern)
    if pattern is None or not expression(pattern):
        return None
    row = case.pattern.lineno
    line = lines[row - 1]
    if not (m := CASE_RE.match(line)):
        return None
    end = colon_after(line, len(m.group(0)))
    if end == -1:
        return None
    condition = f"{subject} == ({pattern})"
    if case.guard:
        condition += f" and ({ast.get_source_segment(source, case.guard)})"
    return row, f"{m.group(1)}if {condition}{line[end:]}"


def match_edits(source, lines, node):
    """{row: new line} for one match statement, or {} if any part of it can't be rewritten."""
    subject = ast.get_source_segment(source, node.subject)
    line = lines[node.lineno - 1]
    head = re.match(r"^(\s*)match\b", line)
    if subject is None or node.subject.lineno != node.lineno or node.subject.end_lineno != node.lineno or not head:
        return {}
    end = colon_after(line, len(head.group(0)))
    if end == -1:
        return {}
    edits = {node.lineno: f"{head.group(1)}if True{line[end:]}"}
    for case in node.cases:
        header = case_header(source, lines, case, f"({subject})")
        if header is None:
            return {}
        edits[header[0]] = header[1]
    return edits


def match_as_if(source):
    """The source with match statements rewritten, or None if it has none (or doesn't parse)."""
    if "match" not in source or "case" not in source:
        return None
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    lines = source.splitlines(keepends=True)
    edits = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Match):
            edits.update(match_edits(source, lines, node))
    if not edits:
        return None
    for row, text in edits.items():
        lines[row - 1] = text
    return "".join(lines)
