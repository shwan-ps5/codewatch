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

from .base import python_tree
from .summaries import is_js

SSRF_RULE = "codewatch.python.web.ssrf"


def _param_names(node):
    args = node.args
    return {a.arg for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]}


def _names(node):
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _called_name(call):
    return call.func.attr if isinstance(call.func, ast.Attribute) else getattr(call.func, "id", "")


def _failed_match(node, params):
    """`not RE.match(p)` or `not re.fullmatch(..., p)` on a parameter."""
    if not (isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not) and isinstance(node.operand, ast.Call)):
        return False
    call = node.operand
    return _called_name(call) in ("match", "fullmatch", "search") and any(_names(a) & params for a in call.args)


def _not_allowed(node, params):
    """`p not in ALLOWED` on a parameter."""
    return (isinstance(node, ast.Compare) and any(isinstance(op, ast.NotIn) for op in node.ops)
            and isinstance(node.left, ast.Name) and node.left.id in params)


def _tests_a_parameter(test, params):
    """`not RE.match(p)`, `not re.fullmatch(..., p)`, `p not in ALLOWED`, or such a test inside and/or."""
    return any(_failed_match(node, params) or _not_allowed(node, params) for node in ast.walk(test))


def _message(value):
    return isinstance(value, ast.JoinedStr) or (isinstance(value, ast.Constant) and bool(value.value))


def _harmless(value):
    return value is None or isinstance(value, (ast.Constant, ast.JoinedStr))


def _is_refusal_helper(node):
    """A function whose returns are all harmless, and which returns a message from an if that tests a parameter."""
    params = _param_names(node) - {"self", "cls"}
    returns = [n for n in ast.walk(node) if isinstance(n, ast.Return)]
    if not params or not returns or not all(_harmless(r.value) for r in returns):
        return False
    return any(_refuses(n, params) for n in ast.walk(node))


def _refuses(node, params):
    """`if <test of a parameter>: return "message"`."""
    return (isinstance(node, ast.If) and _tests_a_parameter(node.test, params)
            and any(isinstance(s, ast.Return) and _message(s.value) for s in node.body))


def refusal_helpers(texts):
    """Names of the project's functions that answer with a message when a parameter fails a check."""
    trees = (python_tree(text) for text in texts if "def " in text and "return" in text)
    return {node.name for tree in filter(None, trees) for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_refusal_helper(node)}


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


def _configured_assignment(node):
    """The name `name = os.environ...` (or os.getenv, or Django settings) assigns, or None."""
    if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
            and CONFIG_VALUE_RE.match(ast.unparse(node.value))):
        return node.targets[0].id
    return None


def configured_names(texts):
    """Variables the project assigns from os.environ, os.getenv() or Django settings (possibly stripped first)."""
    trees = (python_tree(text) for text in texts if "environ" in text or "getenv" in text or "settings." in text)
    return {name for tree in filter(None, trees) for node in ast.walk(tree) if (name := _configured_assignment(node))}


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


def is_python_taint(rule):
    return rule.get("mode") == "taint" and not is_js(rule) and "python" in rule.get("languages", [])


def with_project_checks(rules, texts):
    """Python taint rules with the refusal checks' sanitizers, and SSRF's with the configured bases'."""
    texts = list(texts)
    refusals, bases = refusal_helpers(texts), configured_names(texts)
    if not refusals and not bases:
        return rules
    extra = refusal_sanitizers(refusals) if refusals else []
    base_sanitizers = [configured_base_sanitizer(bases)] if bases else []
    out = []
    for rule in rules:
        added = (extra + (base_sanitizers if rule.get("id") == SSRF_RULE else [])) if is_python_taint(rule) else []
        out.append({**rule, "pattern-sanitizers": [*rule.get("pattern-sanitizers", []), *added]} if added else rule)
    return out
