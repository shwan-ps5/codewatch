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


SKIPPED_TOKENS = (tokenize.NL, tokenize.NEWLINE, tokenize.COMMENT, tokenize.INDENT, tokenize.DEDENT)


def is_op(tok, strings):
    return tok.type == tokenize.OP and tok.string in strings


def open_frame(tok, prev):
    return {"subscript": tok.string == "[" and is_subscript(prev), "colons": [], "lambda": False, "last": tok}


def close_frame(stack):
    """The colon edits of the bracket a closer ends: a subscript's, unless a lambda inside it holds the colons."""
    frame = stack.pop() if stack else None
    return frame["colons"] if frame and frame["subscript"] and frame["colons"] and not frame["lambda"] else []


def inner_token(frame, tok):
    """A token inside brackets: a lambda, or a subscript's top-level colon, which becomes ", " (with None for an
    empty bound before it)."""
    if tok.type == tokenize.NAME and tok.string == "lambda":
        frame["lambda"] = True
    elif frame["subscript"] and is_op(tok, ":"):
        empty_before = is_op(frame["last"], ("[", ",", ":"))
        colon = [*tok.start, ":", "None, " if empty_before else ", "]
        frame["colons"].append(colon)
        frame["pending"] = colon


def slice_edits(source):
    """[row, col, old, new] edits turning each top-level ":" of a subscript into ", ", with None for empty bounds."""
    edits, stack, prev = [], [], None
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type in SKIPPED_TOKENS:
            continue
        if stack and (pending := stack[-1].pop("pending", None)) and is_op(tok, ","):
            # x[:, i] and x[a:, i]: the next comma already separates, so the colon adds no ", " of its own.
            pending[3] = pending[3][:-2]
        if is_op(tok, OPENERS):
            stack.append(open_frame(tok, prev))
        elif is_op(tok, CLOSERS):
            edits += close_frame(stack)
        elif stack:
            inner_token(stack[-1], tok)
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

