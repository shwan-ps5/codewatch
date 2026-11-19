"""codewatch's own checks: repeated string literals and regexes vulnerable to catastrophic backtracking.

Python files are parsed here with ast; JS/TS parsing and the ReDoS analysis (recheck) run in
tools/codewatch-checks.mjs.
"""
import ast
import json
import re
import shutil
import subprocess
import tempfile
from collections import defaultdict
from html.parser import HTMLParser
from pathlib import Path

from .accessibility import TEMPLATES, blank_template_syntax
from .base import (
    ACCESSIBILITY,
    CODE_SMELL,
    CRITICAL,
    HOTSPOT,
    JS,
    MAJOR,
    MINOR,
    PY,
    TOOLS_DIR,
    VULNERABILITY,
    Analyzer,
    Finding,
    Result,
    is_test_file,
    node_tool,
    python_tree,
)

TOOL = "codewatch"
MIN_LITERAL_LENGTH = 5
RE_MODULES = {"re", "regex"}
MATCH, FULLMATCH = "match", "fullmatch"
BACKTRACKING = "regex-backtracking"
RE_FUNCTIONS = {"compile", MATCH, "search", FULLMATCH, "sub", "subn", "split", "findall", "finditer"}
PY_FLAGS = {"IGNORECASE": "i", "I": "i", "MULTILINE": "m", "M": "m", "DOTALL": "s", "S": "s", "VERBOSE": "x", "X": "x"}

RULES = [
    {
        "code": "data-table-without-headers", "title": "Data table without header cells",
        "languages": ["html"], "type": ACCESSIBILITY, "severity": MAJOR,
        "summary": "A table of data has no <th> cells, so screen readers can't announce which row or column a "
                   "value belongs to. Mark header cells with <th scope=\"col\"> or <th scope=\"row\">.",
        "references": [{"label": "WCAG technique H51: table markup", "url": "https://www.w3.org/WAI/WCAG22/Techniques/html/H51"},
                       {"label": "WCAG 2.2 SC 1.3.1", "url": "https://www.w3.org/WAI/WCAG22/Understanding/info-and-relationships.html"}],
        "cwe": [], "wcag": ["1.3.1"],
    },
    {
        "code": "layout-table-with-headers", "title": "Layout table uses data-table markup",
        "languages": ["html"], "type": ACCESSIBILITY, "severity": MAJOR,
        "summary": "A table marked role=\"presentation\" (layout only) contains <th>, <caption>, <thead> or scope, "
                   "which tells assistive technology two contradictory things. Use CSS layout, or make it a real "
                   "data table.",
        "references": [{"label": "WCAG failure F46", "url": "https://www.w3.org/WAI/WCAG22/Techniques/failures/F46"},
                       {"label": "WCAG 2.2 SC 1.3.1", "url": "https://www.w3.org/WAI/WCAG22/Understanding/info-and-relationships.html"}],
        "cwe": [], "wcag": ["1.3.1"],
    },
    {
        "code": "duplicate-string-literal", "title": "String literal repeated too often",
        "languages": ["python", "javascript"], "type": CODE_SMELL, "severity": MINOR,
        "summary": "The same string literal appears more than the allowed number of times in one file. "
                   "Define it once as a named constant so a change can't miss a copy.",
        "references": [{"label": "The Pragmatic Programmer: DRY", "url": "https://en.wikipedia.org/wiki/Don%27t_repeat_yourself"}],
        "cwe": [1041],
    },
    {
        "code": BACKTRACKING, "title": "Regular expression vulnerable to catastrophic backtracking (ReDoS)",
        "languages": ["python", "javascript"], "type": VULNERABILITY, "severity": MAJOR,
        "summary": "Some inputs make this pattern take exponential or polynomial time, so crafted input can "
                   "stall the process. Remove nested or overlapping quantifiers, anchor the pattern, or bound "
                   "repetition and input length. Exponential backtracking is reported as a vulnerability; "
                   "polynomial, which needs long input, as a security hotspot to review where the pattern reads "
                   "outside text.",
        "references": [
            {"label": "OWASP: Regular expression Denial of Service",
             "url": "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS"},
            {"label": "recheck (ReDoS checker)", "url": "https://makenowjust-labs.github.io/recheck/"},
        ],
        "cwe": [1333],
    },
]


def docstring_nodes(tree):
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                out.add(id(first.value))
    return out


def name_like_parts(node):
    """Sub-nodes holding names or prose rather than data: f-string fragments, annotations, keys, subscripts."""
    if isinstance(node, ast.JoinedStr):
        return node.values
    if isinstance(node, (ast.AnnAssign, ast.arg)) and node.annotation is not None:
        return list(ast.walk(node.annotation))
    if isinstance(node, ast.Dict):
        return [k for k in node.keys if k is not None]
    if isinstance(node, ast.Subscript):
        return list(ast.walk(node.slice))
    return []


def skipped_nodes(tree):
    skip = docstring_nodes(tree)
    for node in ast.walk(tree):
        skip.update(id(part) for part in name_like_parts(node))
    return skip


def python_literals(tree, max_repeats):
    skip = skipped_nodes(tree)
    seen = defaultdict(list)
    for node in ast.walk(tree):
        if (isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip
                and len(node.value.strip()) >= MIN_LITERAL_LENGTH):
            seen[node.value].append(node.lineno)
    return [(value, sorted(lines)) for value, lines in seen.items() if len(lines) > max_repeats]


def python_flags(call):
    flags = ""
    for arg in [*call.args[1:], *(k.value for k in call.keywords if k.arg == "flags")]:
        for node in ast.walk(arg):
            if isinstance(node, ast.Attribute) and node.attr in PY_FLAGS:
                flags += PY_FLAGS[node.attr]
    return flags


INLINE_FLAGS_RE = re.compile(r"\(\?([aiLmsux]+)\)")


def without_verbose_layout(pattern):
    """A verbose pattern (re.X) as the regex it means: whitespace and # comments outside character classes and
    escapes are layout, not text to match."""
    out, in_class, i = [], False, 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\":
            out.append(pattern[i:i + 2])
            i += 2
            continue
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
        elif char.isspace():
            i += 1
            continue
        elif char == "#":
            i = pattern.find("\n", i)
            i = len(pattern) if i < 0 else i
            continue
        out.append(char)
        i += 1
    return "".join(out)


def inline_flags(pattern, flags):
    """A leading (?imsx) group moved into the flags: JavaScript has no inline flags, and a pattern it can't parse
    isn't checked at all (five of codewatch's own regexes went unchecked that way)."""
    found = INLINE_FLAGS_RE.match(pattern)
    if not found:
        return pattern, flags
    letters = found.group(1)
    pattern = pattern[found.end():]
    if "x" in letters:
        pattern = without_verbose_layout(pattern)
    return pattern, flags + "".join(f for f in "ims" if f in letters and f not in flags)


def to_js_syntax(pattern):
    """Python-only regex syntax rewritten to its JavaScript equivalent so recheck can analyse it."""
    pattern = re.sub(r"\(\?P<(\w+)>", r"(?<\1>", pattern)
    pattern = re.sub(r"\(\?P=(\w+)\)", r"\\k<\1>", pattern)
    return pattern.replace(r"\A", "^").replace(r"\Z", "$")


def anchored(pattern, function):
    """re.match/fullmatch only try position 0, so analyse them as anchored rather than as a search."""
    if function in (MATCH, FULLMATCH) and not pattern.startswith("^"):
        pattern = f"^(?:{pattern})"
    if function == FULLMATCH and not pattern.endswith("$"):
        pattern += "$"
    return pattern


ANCHORED_METHODS = (MATCH, FULLMATCH)


def compiled_patterns(tree):
    """{name: re.compile calls assigned to it} in this module."""
    compiled = defaultdict(list)
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and is_re_call(node.value) and node.value.func.attr == "compile"):
            compiled[node.targets[0].id].append(node.value)
    return compiled


def name_uses(tree, names):
    """{name: what each read of it does}: the attribute taken (NAME.match) or None for any other use."""
    attributes = {id(node.value): node.attr for node in ast.walk(tree)
                  if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)}
    uses = defaultdict(list)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in names:
            uses[node.id].append(attributes.get(id(node)))
    return uses


def compiled_uses(tree):
    """{id of a re.compile call: "match" or "fullmatch"} for a pattern assigned once to a name that is only ever
    used as NAME.match(...) or NAME.fullmatch(...) in this module: those try one position, so they are analysed
    anchored, as re.match(...) is. A name used any other way (searched, passed on, put in a list) stays a search."""
    compiled = compiled_patterns(tree)
    uses = name_uses(tree, compiled)
    out = {}
    for name, calls in compiled.items():
        methods = set(uses.get(name, ()))
        if len(calls) == 1 and methods and methods <= set(ANCHORED_METHODS):
            out[id(calls[0])] = MATCH if MATCH in methods else FULLMATCH
    return out


def is_re_call(node):
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in RE_FUNCTIONS
            and isinstance(node.func.value, ast.Name) and node.func.value.id in RE_MODULES and bool(node.args))


def python_regexes(tree, path):
    out = []
    anchored_compiles = compiled_uses(tree)
    for node in ast.walk(tree):
        if not is_re_call(node):
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            flags = python_flags(node)
            pattern = without_verbose_layout(first.value) if "x" in flags else first.value
            pattern, flags = inline_flags(pattern, flags.replace("x", ""))
            out.append({"path": path, "line": node.lineno, "flags": flags, "original": first.value,
                        "pattern": anchored(to_js_syntax(pattern), anchored_compiles.get(id(node), node.func.attr))})
    return out


class TableSemantics(HTMLParser):
    """Collects (line, problem) for tables whose markup contradicts their role."""

    LAYOUT_ROLES = {"presentation", "none"}
    HEADER_TAGS = {"th", "caption", "thead"}
    # A caption names the table but doesn't identify any cell, so it doesn't make a data table accessible.
    CELL_HEADERS = {"th"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack, self.problems = [], []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "table":
            self.stack.append({"line": self.getpos()[0], "layout": attrs.get("role") in self.LAYOUT_ROLES,
                               "headers": False, "cell_headers": False, "cells": False})
        elif self.stack:
            table = self.stack[-1]
            table["headers"] |= tag in self.HEADER_TAGS or "scope" in attrs
            table["cell_headers"] |= tag in self.CELL_HEADERS or "scope" in attrs or "headers" in attrs
            table["cells"] |= tag == "td"

    def handle_endtag(self, tag):
        if tag != "table" or not self.stack:
            return
        table = self.stack.pop()
        if table["layout"] and table["headers"]:
            self.problems.append((table["line"], "layout-table-with-headers"))
        elif not table["layout"] and table["cells"] and not table["cell_headers"]:
            self.problems.append((table["line"], "data-table-without-headers"))


def table_problems(text):
    parser = TableSemantics()
    parser.feed(text)
    parser.close()
    return parser.problems


TABLE_MESSAGES = {
    "data-table-without-headers": "Data table has no header cells (<th>); add them so cells can be identified",
    "layout-table-with-headers": "Layout table (role=presentation) contains <th>/<caption>/<thead>/scope",
}


class CodewatchChecks(Analyzer):
    name = TOOL
    executable = "node"
    extensions = PY | JS | TEMPLATES

    def available(self):
        return shutil.which("node") is not None and node_tool("tsc") is not None

    @staticmethod
    def python_checks(ctx):
        """(repeated-literal findings, regexes to check) from the Python files."""
        findings, regexes = [], []
        for path in ctx.files_with(PY):
            tree = python_tree((ctx.root / path).read_text(errors="replace"))
            if tree is None:
                continue
            if not is_test_file(path):
                findings += [literal_finding(path, value, lines)
                             for value, lines in python_literals(tree, ctx.max_literal_repeats)]
            regexes += [{**r, "tooling": True} if developer_tool(tree, path) else r
                        for r in python_regexes(tree, path)]
        return findings, regexes

    def run(self, ctx):
        result = Result()
        literal_findings, regexes = self.python_checks(ctx)
        result.findings += literal_findings + self.table_findings(ctx)
        node_out = self.run_node(ctx, regexes)
        result.findings += [literal_finding(path, lit["value"], lit["lines"]) for lit in node_out["literals"]
                            if not is_test_file(path := ctx.rel(lit["path"]))]
        result.findings += [regex_finding(ctx.rel(r["path"]), r) for r in node_out["regexes"]]
        return result

    def table_findings(self, ctx):
        findings = []
        for path in ctx.files_with(TEMPLATES):
            text = blank_template_syntax((ctx.root / path).read_text(errors="replace"))
            findings += [Finding(TOOL, code, MAJOR, ACCESSIBILITY, TABLE_MESSAGES[code], path, line)
                         for line, code in table_problems(text)]
        return findings

    def run_node(self, ctx, python_regexes_):
        spec = {"jsFiles": [str(ctx.root / f) for f in ctx.files_with(JS)], "minLength": MIN_LITERAL_LENGTH,
                "maxRepeats": ctx.max_literal_repeats, "pythonRegexes": python_regexes_}
        with tempfile.TemporaryDirectory() as tmp:
            spec_file, out_file = Path(tmp) / "spec.json", Path(tmp) / "out.json"
            spec_file.write_text(json.dumps(spec))
            subprocess.run(["node", str(TOOLS_DIR / "codewatch-checks.mjs"), str(spec_file), str(out_file)],
                           cwd=TOOLS_DIR, capture_output=True, text=True, check=False, timeout=1800)
            return json.loads(out_file.read_text()) if out_file.exists() else {"literals": [], "regexes": []}


def literal_finding(path, value, lines):
    shown = value if len(value) <= 60 else value[:57] + "..."
    return Finding(TOOL, "duplicate-string-literal", MINOR, CODE_SMELL,
                   f'"{shown}" appears {len(lines)} times (lines {", ".join(map(str, lines[:10]))}'
                   f'{"…" if len(lines) > 10 else ""}); define it once as a constant', path, lines[0])


def regex_finding(path, r):
    severity = CRITICAL if r.get("complexity") == "exponential" else MAJOR
    pattern = r.get("original") or r["pattern"]
    message = (f"Regex /{pattern[:80]}/ has {r.get('complexity', 'super-linear')} backtracking "
               f"({r.get('summary') or 'ReDoS'}); e.g. input {r.get('attack', '')[:80]}")
    if r.get("tooling"):
        return Finding(TOOL, BACKTRACKING, MINOR, HOTSPOT,
                       message + ". It is in a developer tool (a script or management command), so it only "
                       "matters if that tool reads text someone else controls", path, r["line"])
    # Polynomial backtracking needs long input to hurt (a request body, an uploaded file), and the check can't
    # tell what the regex reads: a parser's patterns over its own source files were most of a scan's
    # "vulnerabilities" (codewatch on its own code, 2026-11-17). Exponential stays one: a few dozen characters
    # are enough.
    if r.get("complexity") != "exponential":
        return Finding(TOOL, BACKTRACKING, MAJOR, HOTSPOT,
                       message + ". Polynomial backtracking is slow only on long input: it matters where this "
                       "pattern reads text from outside (a request, an upload) without a length limit",
                       path, r["line"])
    return Finding(TOOL, BACKTRACKING, severity, VULNERABILITY, message, path, r["line"])


# A file that builds a web app, even if it also runs itself under `if __name__ == "__main__"` (app.run()).
WEB_APP_RE = re.compile(r"\b(Flask|FastAPI|Starlette|Quart|Sanic|APIRouter|Blueprint)\(|urlpatterns\b|@\w+\.(route|get|post)\(")


def developer_tool(tree, path):
    """A Django management command, or a script run by hand (`if __name__ == "__main__":`) that builds no web
    app: what its regexes read is the developer's own input (a changelog, the repo's files), not a visitor's.
    A slow regex there is a hotspot, not a denial of service anyone outside can trigger."""
    if "/management/commands/" in f"/{path}":
        return True
    main = any(isinstance(n, ast.If) and isinstance(n.test, ast.Compare) and isinstance(n.test.left, ast.Name)
               and n.test.left.id == "__name__" for n in tree.body)
    return main and not WEB_APP_RE.search(ast.unparse(tree))
