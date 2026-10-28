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
from pathlib import Path

from .base import JS, PY, TOOLS_DIR, Analyzer, Finding, Result, is_test_file, node_tool

MIN_LITERAL_LENGTH = 5
RE_MODULES = {"re", "regex"}
RE_FUNCTIONS = {"compile", "match", "search", "fullmatch", "sub", "subn", "split", "findall", "finditer"}
PY_FLAGS = {"IGNORECASE": "i", "I": "i", "MULTILINE": "m", "M": "m", "DOTALL": "s", "S": "s"}

RULES = [
    {
        "code": "duplicate-string-literal", "title": "String literal repeated too often",
        "languages": ["python", "javascript"], "type": "code_smell", "severity": "minor",
        "summary": "The same string literal appears more than the allowed number of times in one file. "
                   "Define it once as a named constant so a change can't miss a copy.",
        "references": [{"label": "The Pragmatic Programmer: DRY", "url": "https://en.wikipedia.org/wiki/Don%27t_repeat_yourself"}],
        "cwe": [1041],
    },
    {
        "code": "regex-backtracking", "title": "Regular expression vulnerable to catastrophic backtracking (ReDoS)",
        "languages": ["python", "javascript"], "type": "vulnerability", "severity": "major",
        "summary": "Some inputs make this pattern take exponential or polynomial time, so crafted input can "
                   "stall the process. Remove nested or overlapping quantifiers, anchor the pattern, or bound "
                   "repetition and input length.",
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


def to_js_syntax(pattern):
    """Python-only regex syntax rewritten to its JavaScript equivalent so recheck can analyse it."""
    pattern = re.sub(r"\(\?P<(\w+)>", r"(?<\1>", pattern)
    pattern = re.sub(r"\(\?P=(\w+)\)", r"\\k<\1>", pattern)
    return pattern.replace(r"\A", "^").replace(r"\Z", "$")


def anchored(pattern, function):
    """re.match/fullmatch only try position 0, so analyse them as anchored rather than as a search."""
    if function in ("match", "fullmatch") and not pattern.startswith("^"):
        pattern = f"^(?:{pattern})"
    if function == "fullmatch" and not pattern.endswith("$"):
        pattern += "$"
    return pattern


def python_regexes(tree, path):
    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in RE_FUNCTIONS and isinstance(node.func.value, ast.Name)
                and node.func.value.id in RE_MODULES and node.args):
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            out.append({"path": path, "line": node.lineno, "flags": python_flags(node), "original": first.value,
                        "pattern": anchored(to_js_syntax(first.value), node.func.attr)})
    return out


class CodewatchChecks(Analyzer):
    name = "codewatch"
    executable = "node"
    extensions = PY | JS

    def available(self):
        return shutil.which("node") is not None and node_tool("tsc") is not None

    def run(self, ctx):
        result = Result()
        regexes = []
        for path in ctx.files_with(PY):
            try:
                tree = ast.parse((ctx.root / path).read_text(errors="replace"))
            except (SyntaxError, ValueError):
                continue
            if not is_test_file(path):
                for value, lines in python_literals(tree, ctx.max_literal_repeats):
                    result.findings.append(literal_finding(path, value, lines))
            regexes += python_regexes(tree, path)
        node_out = self.run_node(ctx, regexes)
        for lit in node_out["literals"]:
            path = ctx.rel(lit["path"])
            if not is_test_file(path):
                result.findings.append(literal_finding(path, lit["value"], lit["lines"]))
        for r in node_out["regexes"]:
            result.findings.append(regex_finding(ctx.rel(r["path"]), r))
        return result

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
    return Finding("codewatch", "duplicate-string-literal", "minor", "code_smell",
                   f'"{shown}" appears {len(lines)} times (lines {", ".join(map(str, lines[:10]))}'
                   f'{"…" if len(lines) > 10 else ""}); define it once as a constant', path, lines[0])


def regex_finding(path, r):
    severity = "critical" if r.get("complexity") == "exponential" else "major"
    pattern = r.get("original") or r["pattern"]
    return Finding("codewatch", "regex-backtracking", severity, "vulnerability",
                   f"Regex /{pattern[:80]}/ has {r.get('complexity', 'super-linear')} backtracking "
                   f"({r.get('summary') or 'ReDoS'}); e.g. input {r.get('attack', '')[:80]}", path, r["line"])
