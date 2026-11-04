"""A template's inline <script> blocks as JavaScript Semgrep can scan.

Python apps ship much of their front end as scripts inside Jinja and Django templates, which the JavaScript rules
never saw (only .js files are JavaScript to Semgrep). The copy keeps every line where it was: script code stays,
everything else (markup, <script src=...>, non-JavaScript script types) becomes blank, and template tags inside the
code become same-length filler, so a finding's line is the template's line.
"""
import re

SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
# Script types that are JavaScript; anything else (text/template, application/json, x-tmpl-mustache) is data.
JS_TYPES = {"", "text/javascript", "application/javascript", "module", "text/ecmascript", "application/ecmascript"}
TYPE_RE = re.compile(r"""\btype\s*=\s*["']?([^"'\s>]*)""", re.IGNORECASE)
SRC_RE = re.compile(r"\bsrc\s*=", re.IGNORECASE)
# {{ value }} becomes a number (valid JavaScript wherever a value goes, plain text inside a string); {% tag %} and
# {# comment #} become spaces. Newlines inside a tag are kept so lines don't move.
EXPRESSION_RE = re.compile(r"\{\{.*?\}\}", re.DOTALL)
STATEMENT_RE = re.compile(r"\{%.*?%\}|\{#.*?#\}", re.DOTALL)


def _blank(text):
    return re.sub(r"[^\n]", " ", text)


def _filler(match):
    text = match.group(0)
    return "0" + _blank(text[1:])


def inline_scripts(source):
    """The template as JavaScript with only its inline scripts kept, or None if it has none."""
    pieces, last, found = [], 0, False
    for match in SCRIPT_RE.finditer(source):
        attributes, code = match.group(1), match.group(2)
        kind = (m.group(1).lower() if (m := TYPE_RE.search(attributes)) else "")
        start = match.start(2)
        pieces.append(_blank(source[last:start]))
        if SRC_RE.search(attributes) or kind not in JS_TYPES or not code.strip():
            pieces.append(_blank(code))
        else:
            found = True
            code = STATEMENT_RE.sub(lambda m: _blank(m.group(0)), code)
            pieces.append(EXPRESSION_RE.sub(_filler, code))
        last = match.end(2)
    if not found:
        return None
    pieces.append(_blank(source[last:]))
    return "".join(pieces)
