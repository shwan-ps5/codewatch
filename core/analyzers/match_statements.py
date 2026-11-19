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


def case_line(lines, case):
    """(row, match) of the `case` keyword's line: the pattern's own line or one of the two before it, since
    `case (` can stand alone with the pattern on the next line; None if not found."""
    first = case.pattern.lineno
    while first > 1 and not CASE_RE.match(lines[first - 1]) and lines[first - 1].strip() not in ("", ")"):
        first -= 1
        if case.pattern.lineno - first > 2:
            return None
    m = CASE_RE.match(lines[first - 1])
    return (first, m) if m else None


def header_colon(lines, case):
    """(row, column) of the colon that ends the case header: the first after the pattern (or guard), on a later
    line if a bracket the pattern sits in closes outside the pattern's own span; None if there is none."""
    after = case.guard or case.pattern
    last, end = after.end_lineno, colon_after(lines[after.end_lineno - 1], after.end_col_offset)
    while end == -1 and last < len(lines) and last < case.body[0].lineno - 1:
        last += 1
        end = colon_after(lines[last - 1], 0)
    return None if end == -1 else (last, end)


def header_parses(pattern_text, guarded):
    """The header text between `case` and the colon is a pattern (and ` if ` guard) Python reads as expressions."""
    if guarded:
        guard_start = pattern_text.rfind(" if ")
        if guard_start == -1:
            return False
        pattern_text, guard = pattern_text[:guard_start], pattern_text[guard_start + 4:]
        if not expression(f"({guard})"):
            return False
    return bool(expression(f"({pattern_text})"))


def closed_last_line(tail, end, guarded):
    """The header's last line with the pattern's bracket closed: before the guard's `if`, or before the colon."""
    if not guarded:
        return f"{tail[:end]}){tail[end:]}"
    cut = tail.rfind(" if ", 0, end)
    return None if cut == -1 else f"{tail[:cut]}) and ({tail[cut + 4:end]}){tail[end:]}"


def multiline_case_header(lines, case, subject):
    """{row: new line} for a case whose pattern spans lines (LightRAG GHSA-v9w6-9hq9-33ch:
    `case (\n ".txt"\n | ".md"\n ):`): `case` becomes `if subject == (` on the first line and `)` closes it before
    the colon on the last, so the lines between stay as they are, inside the brackets."""
    start, colon = case_line(lines, case), header_colon(lines, case)
    if start is None or colon is None or colon[0] == start[0]:
        return None
    (first, m), (last, end) = start, colon
    head = lines[first - 1][len(m.group(0)):]
    if not header_parses("".join([head, *lines[first:last - 1], lines[last - 1][:end]]), case.guard is not None):
        return None
    closed = closed_last_line(lines[last - 1], end, case.guard is not None)
    return None if closed is None else {first: f"{m.group(1)}if {subject} == ({head}", last: closed}


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
        if header is not None:
            edits[header[0]] = header[1]
            continue
        multiline = multiline_case_header(lines, case, f"({subject})")
        if not multiline:
            return {}
        edits.update(multiline)
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
