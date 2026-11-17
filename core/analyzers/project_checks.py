"""Sanitizers learnt from the project's own Python code, which name-based rules can't see.

Refusal checks: a helper that tests a parameter (a regex match, an allowlist) and returns a message when it fails,
`def scan_refusal(project, branch=None): if branch and not BRANCH_RE.match(branch): return "That isn't a branch
name."` (codewatch's own server). A caller that stops when it answers, `if scan_refusal(project, branch): return
None`, or `refusal = scan_refusal(...)` then `if refusal: return ...`, has a checked value after that. The helper's
name says nothing (refusal, problem, error_for), so its body decides: every return is None, a constant or an
f-string (never a parameter, so a truthy answer can only mean "refused"), and at least one returns a message from an
`if` that tests a parameter.

Configured bases: a URL whose scheme and host come from configuration, `base = os.environ.get("CODEWATCH_URL",
...).rstrip("/")` then `f"{base}/api/{path}"`, has only its path from the caller (codewatch's MCP server). Semgrep
can't tie an f-string's first part to the variable assigned (a regex group doesn't unify with a metavariable), so the
names assigned from configuration anywhere in the project are listed here and both the assignment and the f-string's
start are matched against them.
"""
import ast
import re

from .summaries import is_js

SSRF_RULE = "codewatch.python.web.ssrf"


def _param_names(node):
    args = node.args
    return {a.arg for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]}


def _names(node):
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _tests_a_parameter(test, params):
    """`not RE.match(p)`, `not re.fullmatch(..., p)`, `p not in ALLOWED`, or such a test inside and/or."""
    for node in ast.walk(test):
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not) and isinstance(node.operand, ast.Call):
            call = node.operand
            func = call.func.attr if isinstance(call.func, ast.Attribute) else getattr(call.func, "id", "")
            if func in ("match", "fullmatch", "search") and any(_names(a) & params for a in call.args):
                return True
        if isinstance(node, ast.Compare) and any(isinstance(op, ast.NotIn) for op in node.ops) \
                and isinstance(node.left, ast.Name) and node.left.id in params:
            return True
    return False


def _message(value):
    return isinstance(value, ast.JoinedStr) or (isinstance(value, ast.Constant) and bool(value.value))


def _harmless(value):
    return value is None or isinstance(value, (ast.Constant, ast.JoinedStr))


def refusal_helpers(texts):
    """Names of the project's functions that answer with a message when a parameter fails a check."""
    found = set()
    for text in texts:
        if "def " not in text or "return" not in text:
            continue
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            params = _param_names(node) - {"self", "cls"}
            returns = [n for n in ast.walk(node) if isinstance(n, ast.Return)]
            if not params or not returns or not all(_harmless(r.value) for r in returns):
                continue
            if any(isinstance(n, ast.If) and _tests_a_parameter(n.test, params)
                   and any(isinstance(s, ast.Return) and _message(s.value) for s in n.body)
                   for n in ast.walk(node)):
                found.add(node.name)
    return found


def refusal_sanitizers(names):
    regex = "^(.*\\.)?(" + "|".join(sorted(map(re.escape, names))) + ")$"
    check = {"metavariable-regex": {"metavariable": "$CHECK", "regex": regex}}
    direct = [{"pattern-inside": f"if $CHECK(..., $X, ...):\n  ...\n  {end} ...\n...\n"} for end in ("return", "raise")]
    stored = [{"pattern-inside": f"$R = $CHECK(..., $X, ...)\n...\nif $R:\n  ...\n  {end} ...\n...\n"}
              for end in ("return", "raise")]
    return [
        {"patterns": [{"pattern-either": direct}, {"pattern-not-inside": "if $CHECK(..., $X, ...):\n  ...\n"},
                      check, {"pattern": "$X"}]},
        {"patterns": [{"pattern-either": stored}, {"pattern-not-inside": "if $R:\n  ...\n"}, check,
                      {"pattern": "$X"}]},
    ]


CONFIG_VALUE_RE = re.compile(r"^(os\.environ\b|os\.getenv\(|(django\.conf\.)?settings\.\w)")


def configured_names(texts):
    """Variables the project assigns from os.environ, os.getenv() or Django settings (possibly stripped first)."""
    found = set()
    for text in texts:
        if "environ" not in text and "getenv" not in text and "settings." not in text:
            continue
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                    and CONFIG_VALUE_RE.match(ast.unparse(node.value)):
                found.add(node.targets[0].id)
    return found


def configured_base_sanitizer(names):
    alternatives = "|".join(sorted(map(re.escape, names)))
    starts = [f"$BASE = {value}\n...\n" for value in (
        "os.environ.get(...)", "os.environ.get(...).$CLEAN(...)", "os.environ[$KEY]", "os.environ[$KEY].$CLEAN(...)",
        "os.getenv(...)", "os.getenv(...).$CLEAN(...)", "settings.$NAME", "settings.$NAME.$CLEAN(...)")]
    return {"patterns": [
        {"pattern-either": [{"pattern-inside": s} for s in starts]},
        {"metavariable-regex": {"metavariable": "$BASE", "regex": f"^({alternatives})$"}},
        {"pattern": "$URL"},
        {"metavariable-pattern": {"metavariable": "$URL", "patterns": [
            {"pattern": 'f"..."'},
            {"pattern-regex": "^f[\"']\\{\\s*(" + alternatives + ")\\s*\\}/"}]}},
    ]}


def with_project_checks(rules, texts):
    """Python taint rules with the refusal checks' sanitizers, and SSRF's with the configured bases'."""
    texts = list(texts)
    refusals, bases = refusal_helpers(texts), configured_names(texts)
    if not refusals and not bases:
        return rules
    extra = refusal_sanitizers(refusals) if refusals else []
    out = []
    for rule in rules:
        if rule.get("mode") != "taint" or is_js(rule) or "python" not in rule.get("languages", []):
            out.append(rule)
            continue
        added = extra + ([configured_base_sanitizer(bases)] if bases and rule.get("id") == SSRF_RULE else [])
        out.append({**rule, "pattern-sanitizers": [*rule.get("pattern-sanitizers", []), *added]} if added else rule)
    return out
