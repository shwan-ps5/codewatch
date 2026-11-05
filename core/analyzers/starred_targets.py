"""Unstar starred assignment targets (`[*parts, ext] = x` -> `[parts , ext] = x`) for Semgrep's taint.

Semgrep OSS taints every name an unpacking assigns from tainted data, except a starred one: `head, *rest =
request.path.split("/")` leaves rest clean. Dagster's log download (GHSA-q93c) unpacked the request path that way
before the file response. Without the star the copy still parses and rest is tainted like head. The copy is only
ever scanned, never run, and the name moves left over its star (a space after it), so the line keeps its length and
indentation: blanking the star instead would indent `*parts, ext = ...` at the start of a statement.
"""
import ast


def starred_targets(tree):
    """(line, column, name) of the star of each starred name in an assignment or for-loop target."""
    targets = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets += node.targets
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            targets.append(node.target)
    return [(node.lineno, node.col_offset, node.value.id) for target in targets for node in ast.walk(target)
            if isinstance(node, ast.Starred) and isinstance(node.value, ast.Name)]


def unstar_targets(source):
    """The source with starred targets unstarred, or None if it has none (or doesn't parse)."""
    if "*" not in source:
        return None
    try:
        stars = starred_targets(ast.parse(source))
    except (SyntaxError, ValueError):
        return None
    if not stars:
        return None
    lines = source.splitlines(keepends=True)
    for row, col, name in stars:
        line = lines[row - 1]
        # ast columns count UTF-8 bytes; a line with other characters before the star is left alone.
        if line[col:col + 1 + len(name)] != "*" + name:
            continue
        lines[row - 1] = line[:col] + name + " " + line[col + 1 + len(name):]
    result = "".join(lines)
    return None if result == source else result
