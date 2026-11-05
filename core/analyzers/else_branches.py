"""Split `if ... else` so a check's sanitizers don't reach the branch where it failed.

The rules clear a value inside a check that passed: `if ext in ALLOWED: ...` or `if is_safe(url): ...`, written
as `pattern-inside: if <... $X in $ALLOWED ...>: ...`. Semgrep's range for that pattern is the whole `if`
statement, else branch included, so `else: return mark_safe(f"...{ext}...")` (the value that failed the check)
was cleared too. In the copy Semgrep scans (never run; every line and column kept), `else:` becomes `if E:` and
`elif c:` becomes `if   c:`, so each branch is a statement of its own and only the checked one is inside the
check. Taint still flows into both branches, as it would at run time.
"""
import ast
import re

ELSE_RE = re.compile(r"^(\s*)else(\s*):")
ELIF_RE = re.compile(r"^(\s*)elif\b")


def else_rows(tree, lines):
    """(row, kind) of each `else:` / `elif` line that belongs to an if statement."""
    rows = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If) or not node.orelse:
            continue
        first = node.orelse[0]
        if isinstance(first, ast.If) and len(node.orelse) == 1 and ELIF_RE.match(lines[first.lineno - 1]) \
                and len(ELIF_RE.match(lines[first.lineno - 1]).group(1)) == node.col_offset:
            rows.append((first.lineno, "elif"))
            continue
        # The `else:` line is the last one before the else body at the if's own indentation.
        row = first.lineno
        while row > node.lineno:
            m = ELSE_RE.match(lines[row - 1])
            if m and len(m.group(1)) == node.col_offset:
                rows.append((row, "else"))
                break
            row -= 1
    return rows


def split_else(source):
    """The source with if statements' else/elif branches made separate ifs, or None if none (or it doesn't
    parse)."""
    if "else" not in source and "elif" not in source:
        return None
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    lines = source.splitlines(keepends=True)
    rows = else_rows(tree, lines)
    if not rows:
        return None
    for row, kind in rows:
        line = lines[row - 1]
        if kind == "elif":
            lines[row - 1] = ELIF_RE.sub(lambda m: m.group(1) + "if  ", line, count=1)
        else:
            lines[row - 1] = ELSE_RE.sub(lambda m: m.group(1) + "if E" + m.group(2) + ":", line, count=1)
    result = "".join(lines)
    try:
        ast.parse(result)
    except (SyntaxError, ValueError):
        return None
    return None if result == source else result
