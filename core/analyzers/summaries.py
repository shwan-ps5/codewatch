"""One level of interprocedural taint for codewatch's own Semgrep taint rules.

Semgrep OSS follows data within a function only, so `load_css(request.args["css"])` is missed when the file read
happens inside load_css. Two passes close that gap:

1. Each taint rule runs with the parameters of every named function as its sources. A hit means that parameter
   reaches the rule's sink inside the function (sanitizers still apply): a summary (function, parameter).
2. The rules run again with each summarised call as an extra sink for that argument: `load_css(<arg>)`.

Pass 1 repeats with the summarised calls as sinks too, so a wrapper that hands its parameter to load_css is
summarised as well, up to MAX_DEPTH calls deep.

A call only counts where the function is visible: in the file that defines it, or in a file that imports it or
its module, so same-named functions elsewhere don't connect.
"""
import ast
import copy
import functools
import re
from pathlib import Path

SUMMARY_SUFFIX = ".params"
VIA_SUFFIX = ".via"
VIA_RE = re.compile(r"\[via (\w+)\(\)\]$")
MAX_DEPTH = 3
JS_LANGUAGES = {"javascript", "typescript"}
RECEIVERS = {"self", "cls"}

PYTHON_PARAM_SOURCES = [
    {"patterns": [{"pattern-either": [{"pattern-inside": "def $FUNC(..., $PARAM, ...):\n  ...\n"},
                                      {"pattern-inside": "async def $FUNC(..., $PARAM, ...):\n  ...\n"}]},
                  {"pattern": "$PARAM"},
                  {"metavariable-regex": {"metavariable": "$PARAM", "regex": "^(?!(self|cls)$)\\w+$"}}]},
]
JS_PARAM_SOURCES = [
    {"patterns": [{"pattern-either": [
        {"pattern-inside": "function $FUNC(..., $PARAM, ...) { ... }"},
        {"pattern-inside": "const $FUNC = (..., $PARAM, ...) => { ... }"},
        {"pattern-inside": "const $FUNC = (..., $PARAM, ...) => $BODY"},
        {"pattern-inside": "const $FUNC = function (..., $PARAM, ...) { ... }"},
        {"pattern-inside": "class $CLASS { ... $FUNC(..., $PARAM, ...) { ... } ... }"},
        {"pattern-inside": "$OBJ.$FUNC = (..., $PARAM, ...) => { ... }"},
        {"pattern-inside": "$OBJ.$FUNC = function (..., $PARAM, ...) { ... }"},
    ]}, {"pattern": "$PARAM"}]},
]


def taint_rules(rules):
    """Taint rules that follow data across calls. A rule whose sources aren't request data (a stack trace, a
    file name) sets metadata `interprocedural: false`: a parameter reaching its sink says nothing about them."""
    return [r for r in rules if r.get("mode") == "taint" and r.get("metadata", {}).get("interprocedural", True)]


def is_js(rule):
    return bool(JS_LANGUAGES & set(rule.get("languages", [])))


def summary_rules(rules, summaries=None):
    """Pass 1: every taint rule with function parameters as sources, reporting "function|parameter|callee".

    With summaries, only the summarised rules, and calls to the summarised functions are sinks as well (the callee
    names which one was reached, so parse_summaries can check it is visible)."""
    out = []
    for rule in taint_rules(rules):
        found = (summaries or {}).get(rule["id"])
        if summaries is not None and not found:
            continue
        variant = copy.deepcopy(rule)
        variant["id"] = rule["id"] + SUMMARY_SUFFIX
        variant["message"] = "$FUNC|$PARAM|$VIA_FUNC"
        variant["pattern-sources"] = copy.deepcopy(JS_PARAM_SOURCES if is_js(rule) else PYTHON_PARAM_SOURCES)
        if found:
            variant["pattern-sinks"] = rule["pattern-sinks"] + via_sinks(found, is_js(rule))
        out.append(variant)
    return out


@functools.lru_cache(maxsize=32)
def python_functions(text):
    """{name: [(def node, defined directly in a class)]}, parsed once per file: pass 1 can report thousands of
    hits in one large module."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return {}
    functions = {}
    for parent in ast.walk(tree):
        for node in ast.iter_child_nodes(parent):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.setdefault(node.name, []).append((node, isinstance(parent, ast.ClassDef)))
    return functions


def python_signature(text, func, line):
    """(positional index or None, is_method) of the parameters of the def named func around line."""
    best = None
    for node, in_class in python_functions(text).get(func, ()):
        if node.lineno <= line <= (node.end_lineno or node.lineno) and (best is None or node.lineno > best[0].lineno):
            best = (node, in_class)
    if best is None:
        return None
    node, in_class = best
    positional = [a.arg for a in node.args.posonlyargs + node.args.args]
    method = in_class and bool(positional) and positional[0] in RECEIVERS
    return positional[1:] if method else positional, [a.arg for a in node.args.kwonlyargs], method


JS_HEADER_RES = [
    re.compile(r"function\s*\*?\s*(?P<name>\w+)\s*(<[^>]*>)?\s*\((?P<params>[^)]*)\)"),
    re.compile(r"(?P<name>\w+)\s*=\s*(async\s+)?(function\s*)?\((?P<params>[^)]*)\)"),
    re.compile(r"^\s*(public\s+|private\s+|protected\s+|static\s+|async\s+)*(?P<name>\w+)\s*(<[^>]*>)?\s*\((?P<params>[^)]*)\)[^;]*\{"),
]


def js_param_name(param):
    param = param.strip()
    if not param or param[0] in "{[" or param.startswith("..."):
        return None
    return re.split(r"[?:=\s]", param, maxsplit=1)[0]


def js_signature(text, func, line):
    """Parameters of the nearest header for func at or above line (single-line headers only)."""
    lines = text.splitlines()
    for i in range(min(line, len(lines)) - 1, -1, -1):
        for header in JS_HEADER_RES:
            if (m := header.search(lines[i])) and m.group("name") == func:
                params = [js_param_name(p) for p in m.group("params").split(",")]
                return params, [], False
    return None


def parse_summaries(results, read_text, known=None, hits=None):
    """{rule id: {(function, positional index or None, parameter, is_method, defining path)}} from pass 1.

    known: the summaries the pass used as sinks; a hit on one counts only where that callee is visible.
    hits: collects (rule id, path, line, function, parameter) for each accepted result."""
    summaries = {}
    for check_id, path, line, message in results:
        func, param, callee = [*message.split("|"), "", ""][:3]
        if not func or not param:
            continue
        rule_id = check_id.removesuffix(SUMMARY_SUFFIX)
        if callee and not callee.startswith("$"):
            defining = {s[4] for s in (known or {}).get(rule_id, ()) if s[0] == callee}
            if callee == func or not defining or not visible(path, defining, read_text):
                continue
        text = read_text(path)
        if text is None:
            continue
        signature = (python_signature if path.endswith(".py") else js_signature)(text, func, line)
        if signature is None:
            continue
        positional, keyword_only, method = signature
        if param not in positional and param not in keyword_only:
            continue
        index = positional.index(param) if param in positional else None
        summaries.setdefault(rule_id, set()).add((func, index, param, method, path))
        if hits is not None:
            hits.append((rule_id, path, line, func, param))
    return summaries


NAME_RE = re.compile(r"[A-Za-z_$][\w$]*")
DEFINITION_RE = re.compile(r"(\bdef|\bfunction\s*\*?|\bclass)\s+$")
DEFINITION_REACH = 64
NOT_A_USE_RE = re.compile(r"^\s*(#|//|\*|/\*)|module\.exports|\bexports\.|^\s*export\s*\{|__all__")


def referenced_names(files):
    """Names used somewhere other than their own definition, an export list or a comment: a function whose name
    is never used has no caller in the project, so whatever reaches its parameters comes from outside."""
    used = set()
    for path, text in files:
        js = not path.endswith(".py")
        for line in text.splitlines():
            if NOT_A_USE_RE.search(line):
                continue
            # Positions rather than slices of the line: minified bundles have lines of 100k characters and
            # thousands of names each, and copying the line per name is quadratic.
            for match in NAME_RE.finditer(line):
                start, end = match.span()
                if (DEFINITION_RE.search(line, max(0, start - DEFINITION_REACH), start)
                        or (js and js_definition(line, start, end))):
                    continue
                used.add(match.group())
    return used


JS_ASSIGNED_FUNCTION_RE = re.compile(r"\s*[:=]\s*(async\s+)?(function\b|\([^)]*\)\s*=>|\w+\s*=>)")
JS_MODIFIERS_RE = re.compile(r"\s*((public|private|protected|static|async)\s+)*")
JS_METHOD_HEADER_RE = re.compile(r"\s*\([^)]*\)[^;]*\{\s*$")


def js_definition(line, start, end):
    """line[start:end] is defined here: `name = (...) =>`, `name: function`, or a class method header
    `name(...) {` at the start of the line."""
    if JS_ASSIGNED_FUNCTION_RE.match(line, end):
        return True
    return bool(JS_MODIFIERS_RE.fullmatch(line, 0, start) and JS_METHOD_HEADER_RE.match(line, end))


def call_patterns(index, param, method, js):
    """Semgrep patterns for a call passing $ARG as that parameter; $VIA_FUNC binds the name."""
    before = "".join(f"$A{i}, " for i in range(index)) if index is not None else None
    receivers = ["this"] if js else sorted(RECEIVERS)
    callees = [f"{r}.$VIA_FUNC" for r in receivers] if method else ["$VIA_FUNC", "$MODULE.$VIA_FUNC"]
    patterns = []
    for callee in callees:
        if before is not None:
            patterns.append(f"{callee}({before}$ARG, ...)")
        if not js:
            patterns.append(f"{callee}(..., {param}=$ARG, ...)")
    return patterns


def via_sinks(found, js):
    sinks = []
    for func, index, param, method, _path in sorted(found, key=repr):
        name = {"metavariable-regex": {"metavariable": "$VIA_FUNC", "regex": f"^{re.escape(func)}$"}}
        sinks += [{"patterns": [{"pattern": pattern}, name, {"focus-metavariable": "$ARG"}]}
                  for pattern in call_patterns(index, param, method, js)]
    return sinks


def merge(summaries, more):
    """summaries plus more; None when more adds nothing."""
    merged = {rule: set(found) for rule, found in summaries.items()}
    for rule, found in more.items():
        merged.setdefault(rule, set()).update(found)
    return None if merged == summaries else merged


def via_rules(rules, summaries):
    """Pass 2 rules: each summarised taint rule with calls to its functions as extra sinks."""
    out = []
    for rule in taint_rules(rules):
        found = summaries.get(rule["id"])
        if not found:
            continue
        variant = copy.deepcopy(rule)
        variant["id"] = rule["id"] + VIA_SUFFIX
        variant["pattern-sinks"] = via_sinks(found, is_js(rule))
        variant["message"] = rule["message"].strip() + " [via $VIA_FUNC()]"
        out.append(variant)
    return out


PY_IMPORT_RE = re.compile(r"^\s*(?:from\s+(\.*[\w.]*)\s+import\s+([\w., ()*]+)|import\s+([\w., ]+))", re.MULTILINE)
JS_IMPORT_RE = re.compile(r"""(?:\bfrom\s+|\brequire\s*\(\s*|\bimport\s*\(\s*)['"](\.{1,2}/[^'"]+)['"]""")
JS_EXTENSIONS = ("", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", "/index.js", "/index.ts")


def python_imports(path, text):
    """Repo-relative files a Python module may import, trying every ancestor folder as an import root."""
    folder = Path(path).parent
    roots = [folder, *folder.parents]
    modules = []
    for match in PY_IMPORT_RE.finditer(text):
        source, names, plain = match.groups()
        if plain:
            modules += [n.split(" as ")[0].strip() for n in plain.split(",")]
            continue
        dots = len(source) - len(source.lstrip("."))
        base = source.lstrip(".")
        bare = [n.split(" as ")[0].strip(" ()") for n in names.split(",")]
        if dots:
            anchor = folder.parents[dots - 2] if dots > 1 else folder
            prefix = anchor.joinpath(*base.split(".")) if base else anchor
            modules_here = [prefix, *(prefix / n for n in bare if n)]
            yield from (f"{m}.py" for m in modules_here)
            yield from (f"{m}/__init__.py" for m in modules_here)
            continue
        modules += [base, *(f"{base}.{n}" for n in bare if n and n != "*")]
    for module in modules:
        for root in roots:
            target = root.joinpath(*module.split("."))
            yield f"{target}.py"
            yield f"{target}/__init__.py"


def js_imports(path, text):
    folder = Path(path).parent
    for match in JS_IMPORT_RE.finditer(text):
        target = (folder / match.group(1)).as_posix()
        parts = []
        for part in target.split("/"):
            if part == "..":
                if parts:
                    parts.pop()
            elif part not in ("", "."):
                parts.append(part)
        yield from ("/".join(parts) + ext for ext in JS_EXTENSIONS)


def visible(path, defining_paths, read_text):
    """The call in path can reach one of the summarised definitions of func: it is in the same file, or the file
    imports the module that defines it."""
    if path in defining_paths:
        return True
    text = read_text(path) or ""
    imports = python_imports(path, text) if path.endswith(".py") else js_imports(path, text)
    normalised = {Path(p).as_posix().removeprefix("./") for p in imports}
    return bool(normalised & set(defining_paths))
