"""Rewrite Python slices as tuple indexes (x[a:b] -> x[a, b]) for Semgrep's taint analysis.

Semgrep OSS stops tracking taint through a slice, so `bar = param[5:]` loses the request data that flowed into
it, while `param[5]` keeps it. Scanning a copy with every slice turned into an index keeps the data flow. The copy
is only ever scanned, never run, and every token stays on its original line, so findings map back unchanged.
"""
import io
import keyword
import tokenize

OPENERS, CLOSERS = "([{", ")]}"
# A "[" after one of these starts a subscript; after anything else (an operator, a keyword, "(") it's a list.
SUBSCRIPTABLE_TOKENS = {tokenize.NAME, tokenize.STRING, tokenize.NUMBER}
FSTRING_END = getattr(tokenize, "FSTRING_END", None)


def is_subscript(prev):
    if prev is None:
        return False
    if prev.type == tokenize.NAME:
        return not keyword.iskeyword(prev.string) or prev.string in ("None", "True", "False")
    if prev.type == tokenize.OP:
        return prev.string in (")", "]")
    return prev.type in SUBSCRIPTABLE_TOKENS or prev.type == FSTRING_END


def slice_edits(source):
    """(row, col, old, new) edits turning each top-level ":" of a subscript into ", ", with None for empty bounds."""
    edits, stack, prev = [], [], None
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type in (tokenize.NL, tokenize.NEWLINE, tokenize.COMMENT, tokenize.INDENT, tokenize.DEDENT):
            continue
        if tok.type == tokenize.OP and tok.string in OPENERS:
            stack.append({"subscript": tok.string == "[" and is_subscript(prev), "colons": [], "lambda": False,
                          "last": tok})
        elif tok.type == tokenize.OP and tok.string in CLOSERS:
            frame = stack.pop() if stack else None
            if frame and frame["subscript"] and frame["colons"] and not frame["lambda"]:
                edits += frame["colons"]
        elif stack:
            frame = stack[-1]
            if tok.type == tokenize.NAME and tok.string == "lambda":
                frame["lambda"] = True
            elif frame["subscript"] and tok.type == tokenize.OP and tok.string == ":":
                empty_before = frame["last"].type == tokenize.OP and frame["last"].string in ("[", ",", ":")
                frame["colons"].append((*tok.start, ":", "None, " if empty_before else ", "))
        if stack:
            stack[-1]["last"] = tok
        prev = tok
    return edits


def index_slices(source):
    """The source with slices rewritten, or None if it has none (or doesn't tokenize)."""
    if "[" not in source or ":" not in source:
        return None
    try:
        edits = slice_edits(source)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return None
    if not edits:
        return None
    lines = source.splitlines(keepends=True)
    for row, col, old, new in sorted(edits, reverse=True):
        line = lines[row - 1]
        if line[col:col + len(old)] != old:
            return None
        lines[row - 1] = line[:col] + new + line[col + len(old):]
    return "".join(lines)
