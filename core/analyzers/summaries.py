"""One level of interprocedural taint for codewatch's own Semgrep taint rules.

Semgrep OSS follows data within a function only, so `load_css(request.args["css"])` is missed when the file read
happens inside load_css. Two passes close that gap:

1. Each taint rule runs with the parameters of every named function as its sources. A hit means that parameter
   reaches the rule's sink inside the function (sanitizers still apply): a summary (function, parameter).
2. The rules run again with each summarised call as an extra sink for that argument: `load_css(<arg>)`.

A call only counts where the function is visible: in the file that defines it, or in a file that imports it or
its module, so same-named functions elsewhere don't connect.
"""
import ast
import copy
import re
from pathlib import Path

SUMMARY_SUFFIX = ".params"
VIA_SUFFIX = ".via"
VIA_RE = re.compile(r"\[via (\w+)\(\)\]$")
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
    return [r for r in rules if r.get("mode") == "taint"]


def summary_rules(rules):
    """Pass 1: every taint rule with function parameters as sources, reporting "function|parameter"."""
    out = []
    for rule in taint_rules(rules):
        variant = copy.deepcopy(rule)
        variant["id"] = rule["id"] + SUMMARY_SUFFIX
        variant["message"] = "$FUNC|$PARAM"
        js = bool(JS_LANGUAGES & set(rule.get("languages", [])))
        variant["pattern-sources"] = copy.deepcopy(JS_PARAM_SOURCES if js else PYTHON_PARAM_SOURCES)
        out.append(variant)
    return out


def python_signature(text, func, line):
    """(positional index or None, is_method) of the parameters of the def named func around line."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    best = None
    for parent in ast.walk(tree):
        for node in ast.iter_child_nodes(parent):
            if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func
                    and node.lineno <= line <= (node.end_lineno or node.lineno)
                    and (best is None or node.lineno > best[0].lineno)):
                best = (node, isinstance(parent, ast.ClassDef))
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


def parse_summaries(results, read_text):
    """{rule id: {(function, positional index or None, parameter, is_method, defining path)}} from pass 1."""
    summaries = {}
    for rule_id, path, line, message in results:
        func, _, param = message.partition("|")
        if not func or not param:
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
        summaries.setdefault(rule_id.removesuffix(SUMMARY_SUFFIX), set()).add((func, index, param, method, path))
    return summaries


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


def via_rules(rules, summaries):
    """Pass 2 rules: each summarised taint rule with calls to its functions as extra sinks."""
    out = []
    for rule in taint_rules(rules):
        found = summaries.get(rule["id"])
        if not found:
            continue
        js = bool(JS_LANGUAGES & set(rule.get("languages", [])))
        sinks = []
        for func, index, param, method, _path in sorted(found, key=repr):
            name = {"metavariable-regex": {"metavariable": "$VIA_FUNC", "regex": f"^{re.escape(func)}$"}}
            sinks += [{"patterns": [{"pattern": pattern}, name, {"focus-metavariable": "$ARG"}]}
                      for pattern in call_patterns(index, param, method, js)]
        variant = copy.deepcopy(rule)
        variant["id"] = rule["id"] + VIA_SUFFIX
        variant["pattern-sinks"] = sinks
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
