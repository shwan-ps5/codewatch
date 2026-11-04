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


def multiline_case_header(lines, case, subject):
    """{row: new line} for a case whose pattern spans lines (LightRAG GHSA-v9w6-9hq9-33ch:
    `case (\n ".txt"\n | ".md"\n ):`): `case` becomes `if subject == (` on the first line and `)` closes it before
    the colon on the last, so the lines between stay as they are, inside the brackets."""
    # `case (` can stand alone on its line, with the pattern starting on the next.
    first = case.pattern.lineno
    while first > 1 and not CASE_RE.match(lines[first - 1]) and lines[first - 1].strip() not in ("", ")"):
        first -= 1
        if case.pattern.lineno - first > 2:
            return None
    if not (m := CASE_RE.match(lines[first - 1])):
        return None
    # The header ends at the first colon after the pattern (or guard); a bracket the pattern sits in can close on
    # a later line, outside the pattern's own span.
    after = case.guard or case.pattern
    last, end = after.end_lineno, colon_after(lines[after.end_lineno - 1], after.end_col_offset)
    while end == -1 and last < len(lines) and last < case.body[0].lineno - 1:
        last += 1
        end = colon_after(lines[last - 1], 0)
    if end == -1 or last == first:
        return None
    head = lines[first - 1][len(m.group(0)):]
    body = [head, *lines[first:last - 1], lines[last - 1][:end]]
    pattern_text = "".join(body)
    if case.guard:
        guard_start = pattern_text.rfind(" if ")
        if guard_start == -1:
            return None
        pattern_text, guard = pattern_text[:guard_start], pattern_text[guard_start + 4:]
        if not expression(f"({guard})"):
            return None
    if not expression(f"({pattern_text})"):
        return None
    edits = {first: f"{m.group(1)}if {subject} == ({head}"}
    tail = lines[last - 1]
    if case.guard:
        # The guard sits after the pattern on the last line: close the pattern's bracket before its `if`.
        cut = tail.rfind(" if ", 0, end)
        if cut == -1:
            return None
        edits[last] = f"{tail[:cut]}) and ({tail[cut + 4:end]}){tail[end:]}"
    else:
        edits[last] = f"{tail[:end]}){tail[end:]}"
    return edits


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
