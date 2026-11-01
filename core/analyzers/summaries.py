"""One level of interprocedural taint for codewatch's own Semgrep taint rules.

Semgrep OSS follows data within a function only, so `load_css(request.args["css"])` is missed when the file read
happens inside load_css. Two passes close that gap:

1. Each taint rule runs with the parameters of every named function as its sources. A hit means that parameter
   reaches the rule's sink inside the function (sanitizers still apply): a summary (function, parameter).
2. The rules run again with each summarised call as an extra sink for that argument: `load_css(<arg>)`.

Pass 1 repeats with the summarised calls as sinks too, so a wrapper that hands its parameter to load_css is
summarised as well, up to MAX_DEPTH calls deep.

Data also comes out of helpers: `def get_param(name): return request.args.get(name)`. A third pass runs each
rule with `return` as the sink to find functions that return request data (returners), and the final rules get a
variant whose sources are calls to them. Returners repeat up to MAX_DEPTH like summaries, and a value looked up
by the request data (a model fetched by id, a decoded token) isn't returned request data.

Data also waits in object fields: `self.term = request.GET["q"]` in one method, `os.system("grep " + self.term)`
in another. The returner pass's first scan also runs each rule with stores to `self.x`/`this.x` as the sink, and
the final rules get a variant whose sources are reads of those fields, kept only in the file that stores them.

Semgrep taints whatever a call returns when an argument is tainted. For the project's own Python functions the
same first scan finds which ones can return a parameter (params as sources, `return` as the sink); a function
that can't, isn't summarised and doesn't return request data itself is a sanitizer: the variable its result is
assigned to is clean (`return_url = self.get_return_to(request.POST)`, which returns the value only inside
`if self.is_safe_url(...)`).

A call only counts where the function is visible: in the file that defines it, or in a file that imports it or
its module, so same-named functions elsewhere don't connect.
"""
import ast
import copy
import functools
import json
import re
from pathlib import Path

SUMMARY_SUFFIX = ".params"
VIA_SUFFIX = ".via"
VIA_RE = re.compile(r"\[via (\w+)\(\)\]$")
RETURNS_SUFFIX = ".returns"
FROM_SUFFIX = ".from"
FROM_RE = re.compile(r"\[from (\w+)\(\)\]$")
PASSES_SUFFIX = ".passes"
FIELDS_SUFFIX = ".fields"
FIELD_SUFFIX = ".field"
FIELD_RE = re.compile(r"\[field (\w+)\]$")
# Keyword via-sinks match any summarised function called with any summarised keyword; the message carries the pair
# so a call passing one function's keyword to another (f(name=x) when only g's name is summarised) is dropped.
KEYWORD_MARK = " {keyword $VIA_FUNC $VIA_KW}"
KEYWORD_RE = re.compile(r" \{keyword (\S+) (\S+)\}")
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

# A view returns a response, not data, even when another view returns its result.
ROUTE_DECORATORS = ("route", "get", "post", "put", "patch", "delete", "api_route", "websocket")
# Class-based handlers (Django's View.get, a Nest controller's get) also return responses, and their names are
# everyone's: requests.get(...) isn't a call to one.
HANDLER_NAMES = {*ROUTE_DECORATORS, "head", "options", "dispatch", "handle", "handler", "render", "__call__"}
PYTHON_RETURN_SINKS = [
    {"patterns": [{"pattern-either": [{"pattern-inside": "def $FUNC(...):\n  ...\n"},
                                      {"pattern-inside": "async def $FUNC(...):\n  ...\n"}]},
                  *({"pattern-not-inside": f"@$APP.{d}(...)\n{a}def $FUNC(...):\n  ...\n"}
                    for d in ROUTE_DECORATORS for a in ("", "async ")),
                  {"pattern": "return $VALUE"}, {"focus-metavariable": "$VALUE"}]},
]
JS_RETURN_SINKS = [
    {"patterns": [{"pattern-either": [
        {"pattern-inside": "function $FUNC(...) { ... }"},
        {"pattern-inside": "const $FUNC = (...) => { ... }"},
        {"pattern-inside": "const $FUNC = function (...) { ... }"},
        {"pattern-inside": "$FUNC(...) { ... }"},
        {"pattern-inside": "$OBJ.$FUNC = (...) => { ... }"},
        {"pattern-inside": "$OBJ.$FUNC = function (...) { ... }"},
    ]},
        # A Koa/Express handler (last parameter `next`) returns the response's promise, not data for its caller
        # (outline: `return renderShare(ctx, next)` passing one route on to another).
        {"pattern-not-inside": "function $FUNC(..., next) { ... }"},
        {"pattern-not-inside": "const $FUNC = (..., next) => { ... }"},
        {"pattern-not-inside": "$FUNC(..., next) { ... }"},
        {"pattern": "return $VALUE;"}, {"focus-metavariable": "$VALUE"}]},
]
LOOKUP_RESULT_MARK = "(get|fetch|load|find|lookup)_(?!"
JS_LOOKUP_RESULT_MARK = "(get|fetch|load|find|lookup)(?!("
# What a helper looks up with the request data (a user by token, a row by id) is stored data, not the request's.
LOOKUP_SANITIZER = {"patterns": [
    {"pattern-either": [{"pattern": "$F(...)"}, {"pattern": "await $F(...)"}]},
    {"metavariable-regex": {"metavariable": "$F", "regex": (
        "(?i)(.*\\.(objects|query|session|db|repo|repository|manager|collection|model)\\.\\w+"
        "|(.*\\.)?(get_object_or_404|get_list_or_404|first_or_404|get_or_404|find\\w*|load\\w*|fetch\\w*"
        "|lookup\\w*|decode\\w*|verify\\w*|authenticate\\w*|get_user\\w*|get_current_user\\w*))$")}},
]}


def taint_rules(rules):
    """Taint rules that follow data across calls. A rule whose sources aren't request data (a stack trace, a
    file name) sets metadata `interprocedural: false`: a parameter reaching its sink says nothing about them."""
    return [r for r in rules if r.get("mode") == "taint" and r.get("metadata", {}).get("interprocedural", True)]


def is_js(rule):
    return bool(JS_LANGUAGES & set(rule.get("languages", [])))


def summary_rules(rules, summaries=None, base=True):
    """Pass 1: every taint rule with function parameters as sources, reporting "function|parameter|callee".

    With summaries, only the summarised rules, and calls to the summarised functions are sinks as well (the callee
    names which one was reached, so parse_summaries can check it is visible). Without base, those calls are the
    only sinks: a deeper pass given just the summaries the last one added finds only what they add."""
    out = []
    for rule in taint_rules(rules):
        found = (summaries or {}).get(rule["id"])
        if summaries is not None and not found:
            continue
        variant = copy.deepcopy(rule)
        variant["id"] = rule["id"] + SUMMARY_SUFFIX
        variant["message"] = "$FUNC|$PARAM|$VIA_FUNC|$VIA_KW"
        variant["pattern-sources"] = copy.deepcopy(JS_PARAM_SOURCES if is_js(rule) else PYTHON_PARAM_SOURCES)
        if found:
            variant["pattern-sinks"] = (rule["pattern-sinks"] if base else []) + via_sinks(found, is_js(rule))
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
        func, param, callee, keyword = [*message.split("|"), "", "", ""][:4]
        if not func or not param:
            continue
        rule_id = check_id.removesuffix(SUMMARY_SUFFIX)
        if callee and not callee.startswith("$"):
            if not keyword_summarised(callee, keyword, (known or {}).get(rule_id, ())):
                continue
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


def callees(method, js):
    receivers = ["this"] if js else sorted(RECEIVERS)
    return [f"{r}.$VIA_FUNC" for r in receivers] if method else ["$VIA_FUNC", "$MODULE.$VIA_FUNC"]


def call_patterns(index, method, js):
    """Semgrep patterns for a call passing $ARG at that position; $VIA_FUNC binds the name."""
    if index is None:
        return []
    before = "".join(f"$A{i}, " for i in range(index))
    return [f"{callee}({before}$ARG, ...)" for callee in callees(method, js)]


NAME_BATCH = 400


def name_regexes(names):
    """Anchored alternations of names, NAME_BATCH at a time: Semgrep's regex engine rejects one listing
    a large project's thousands of functions."""
    names = sorted(names)
    return [f"^({'|'.join(map(re.escape, names[i:i + NAME_BATCH]))})$"
            for i in range(0, len(names), NAME_BATCH)]


def via_sinks(found, js):
    """One sink per call shape, naming every function called that way: a sink per function made Semgrep match
    thousands of patterns in a large project. Python keyword arguments get one sink per kind of callee, naming every
    summarised function and keyword (see KEYWORD_MARK)."""
    callers = {}
    for func, index, _param, method, _path in found:
        for pattern in call_patterns(index, method, js):
            callers.setdefault(pattern, set()).add(func)
    sinks = [{"patterns": [{"pattern": pattern},
                           {"metavariable-regex": {"metavariable": "$VIA_FUNC", "regex": regex}},
                           {"focus-metavariable": "$ARG"}]}
             for pattern, funcs in sorted(callers.items()) for regex in name_regexes(funcs)]
    if js:
        return sinks
    for method in (False, True):
        funcs = {f for f, _index, _param, m, _path in found if m == method}
        params = {p for _f, _index, p, m, _path in found if m == method}
        sinks += [{"patterns": [
            {"pattern-either": [{"pattern": f"{c}(..., $VIA_KW=$ARG, ...)"} for c in callees(method, False)]},
            {"metavariable-regex": {"metavariable": "$VIA_FUNC", "regex": func_regex}},
            {"metavariable-regex": {"metavariable": "$VIA_KW", "regex": param_regex}},
            {"focus-metavariable": "$ARG"},
        ]} for func_regex in name_regexes(funcs) for param_regex in name_regexes(params)]
    return sinks


def keyword_summarised(callee, keyword, found):
    """A via-sink's call passes a summarised parameter: always for a positional one or a result from another sink
    ($VIA_KW or $VIA_FUNC unbound), and for a keyword only when that function's summary names it."""
    if not keyword or keyword.startswith("$") or not callee or callee.startswith("$"):
        return True
    return any(s[0] == callee and s[2] == keyword for s in found)


def split_keyword(message):
    """(message without KEYWORD_MARK, callee, keyword) for a final-pass result."""
    match = KEYWORD_RE.search(message)
    if not match:
        return message, "", ""
    return message[:match.start()] + message[match.end():], match.group(1), match.group(2)


def added(before, after):
    """{rule: entries of after that before lacks}, for the rules that gained some."""
    return {rule: new for rule, found in after.items() if (new := found - before.get(rule, set()))}


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
        variant["message"] = rule["message"].strip() + KEYWORD_MARK + " [via $VIA_FUNC()]"
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


def returner_rules(rules, returners=None, base=True):
    """Pass 3: every taint rule with `return` as its sink, reporting the function that returns request data.

    With returners, calls to them are sources too, so a helper that returns another helper's result is found.
    Without base, those calls are the only sources, and rules with no returners are left out."""
    out = []
    for rule in taint_rules(rules):
        found = (returners or {}).get(rule["id"], ())
        if not base and not found:
            continue
        variant = copy.deepcopy(rule)
        variant["id"] = rule["id"] + RETURNS_SUFFIX
        variant["message"] = "$FUNC"
        variant["pattern-sources"] = (rule["pattern-sources"] if base else []) + from_sources(found, is_js(rule))
        variant["pattern-sanitizers"] = [*without_lookup_result(rule), copy.deepcopy(LOOKUP_SANITIZER)]
        variant["pattern-sinks"] = copy.deepcopy(JS_RETURN_SINKS if is_js(rule) else PYTHON_RETURN_SINKS)
        out.append(variant)
    return out


def innermost_python_function(text, line):
    """Name of the innermost def around line."""
    best = None
    for name, nodes in python_functions(text).items():
        for node, _ in nodes:
            if node.lineno <= line <= (node.end_lineno or node.lineno) and (best is None or node.lineno > best[1]):
                best = (name, node.lineno)
    return best and best[0]


def parse_returners(results, read_text):
    """{rule id: {(function, defining path)}} from pass 3. A return inside a nested function also binds the outer
    one, so only the innermost Python function counts."""
    returners = {}
    for check_id, path, line, func in results:
        if not func or func.startswith("$") or func in HANDLER_NAMES:
            continue
        if path.endswith(".py"):
            text = read_text(path)
            if text is None or innermost_python_function(text, line) != func:
                continue
        returners.setdefault(check_id.removesuffix(RETURNS_SUFFIX), set()).add((func, path))
    return returners


def from_sources(found, js):
    """Sources for calls to the returners in found; $RET_FUNC binds the name."""
    names = sorted({func for func, _path in found})
    if not names:
        return []
    receivers = ["this"] if js else sorted(RECEIVERS)
    calls = ["$RET_FUNC(...)", "$MODULE.$RET_FUNC(...)", *(f"{r}.$RET_FUNC(...)" for r in receivers)]
    # Exact: the call's value is the source, not its arguments. Otherwise a call that is also a summarised
    # function's via-sink matches itself (outline: `X.perform(context)`, one class's perform returning request
    # data and another's passing its argument to a query).
    return [{"patterns": [{"pattern-either": [{"pattern": c} for c in calls]},
                          {"metavariable-regex": {"metavariable": "$RET_FUNC", "regex": regex}}], "exact": True}
            for regex in name_regexes(names)]


def from_rules(rules, returners, summaries):
    """Final-pass variants of each rule whose sources are calls to its returners, with the summarised calls as
    sinks too: "[from get_param()]" names the returner so the finding can be checked for visibility."""
    out = []
    for rule in taint_rules(rules):
        found = returners.get(rule["id"])
        if not found:
            continue
        variant = copy.deepcopy(rule)
        variant["id"] = rule["id"] + FROM_SUFFIX
        variant["pattern-sources"] = from_sources(found, is_js(rule))
        variant["pattern-sanitizers"] = without_lookup_result(rule)
        variant["pattern-sinks"] = rule["pattern-sinks"] + via_sinks(summaries.get(rule["id"], ()), is_js(rule))
        variant["message"] = rule["message"].strip() + KEYWORD_MARK + " [from $RET_FUNC()]"
        out.append(variant)
    return out


def without_lookup_result(rule):
    """The rule's sanitizers minus lookup-result (python-web.yml, javascript-taint.yml) and the pass-through
    sanitizer, which would also clean get_cmd() when get_cmd is a returner: what the returner pass found overrides
    the name."""
    return [s for s in rule.get("pattern-sanitizers", [])
            if not any(mark in repr(s) for mark in (LOOKUP_RESULT_MARK, JS_LOOKUP_RESULT_MARK, PASS_THROUGH_MARK))]


# Not $FIELD: the JS request sources bind that name (req.$FIELD).
FIELD_SINKS = {
    False: [{"patterns": [{"pattern": "self.$STORED_FIELD = $VALUE"}, {"focus-metavariable": "$VALUE"}]}],
    True: [{"patterns": [{"pattern": "this.$STORED_FIELD = $VALUE;"}, {"focus-metavariable": "$VALUE"}]}],
}


def field_rules(rules):
    """Every taint rule with stores to a field of self/this as the sink, reporting the field."""
    out = []
    for rule in taint_rules(rules):
        variant = copy.deepcopy(rule)
        variant["id"] = rule["id"] + FIELDS_SUFFIX
        variant["message"] = "$STORED_FIELD"
        variant["pattern-sinks"] = copy.deepcopy(FIELD_SINKS[is_js(rule)])
        out.append(variant)
    return out


def parse_fields(results):
    """{rule id: {(field, path)}} from field_rules results."""
    fields = {}
    for check_id, path, _line, field in results:
        if field and not field.startswith("$"):
            fields.setdefault(check_id.removesuffix(FIELDS_SUFFIX), set()).add((field, path))
    return fields


def field_variants(rules, fields, summaries):
    """Final-pass variants of each rule whose sources are reads of the fields request data was stored in:
    "[field term]" names the field so the finding can be kept to the file that stores it."""
    out = []
    for rule in taint_rules(rules):
        found = fields.get(rule["id"])
        if not found:
            continue
        names = sorted({field for field, _path in found})
        variant = copy.deepcopy(rule)
        variant["id"] = rule["id"] + FIELD_SUFFIX
        variant["pattern-sources"] = [{"patterns": [
            {"pattern": "this.$STORED_FIELD" if is_js(rule) else "self.$STORED_FIELD"},
            {"metavariable-regex": {"metavariable": "$STORED_FIELD", "regex": regex}},
        ]} for regex in name_regexes(names)]
        variant["pattern-sinks"] = rule["pattern-sinks"] + via_sinks(summaries.get(rule["id"], ()), is_js(rule))
        variant["message"] = rule["message"].strip() + KEYWORD_MARK + " [field $STORED_FIELD]"
        out.append(variant)
    return out


PASS_THROUGH_MARK = "$KEEPS_PARAMS"


# What with_pass_through's sanitizer matches: a variable assigned from a call (a superset; a miss only means a
# function is never treated as clean).
ASSIGNED_CALL_RE = re.compile(r"=\s*(?:await\s+)?(?:(?:self|cls)\.)?(\w+)\s*\(")


def assigned_calls(texts):
    """Names of functions whose result some code assigns to a variable."""
    return {name for text in texts for name in ASSIGNED_CALL_RE.findall(text)}


PASS_RULE_OWN_KEYS = {"id", "message", "metadata", "severity", "pattern-sources", "pattern-sinks", "pattern-sanitizers"}


def pass_rules(rules, names):
    """Python taint rules with function parameters as sources and `return` as the sink: which of names can hand a
    parameter back (under the rule's sanitizers). Only the functions whose result is assigned need an answer; every
    function in a large project meant tens of thousands of results for Semgrep to write out."""
    if not names:
        return []
    sinks = [{"patterns": [*sink["patterns"], {"metavariable-regex": {"metavariable": "$FUNC", "regex": regex}}]}
             for sink in PYTHON_RETURN_SINKS for regex in name_regexes(names)]
    # Sources and sinks are the same for every rule, so rules alike in the rest (sanitizers, propagators) give the
    # same answer: one variant per such group (16 Python rules make 11), its message naming the rules it answers for.
    groups = {}
    for rule in taint_rules(rules):
        if is_js(rule):
            continue
        variant = {k: v for k, v in rule.items() if k not in PASS_RULE_OWN_KEYS}
        variant["pattern-sanitizers"] = without_lookup_result(rule)
        groups.setdefault(json.dumps(variant, sort_keys=True), (variant, []))[1].append(rule["id"])
    out = []
    for variant, ids in groups.values():
        out.append({**copy.deepcopy(variant), "id": ids[0] + PASSES_SUFFIX, "severity": "INFO",
                    "message": "$FUNC|" + ",".join(ids),
                    # The source's own function name is bound as $OWNER so the message names the function that returns.
                    "pattern-sources": json.loads(json.dumps(PYTHON_PARAM_SOURCES).replace("$FUNC", "$OWNER")),
                    "pattern-sinks": copy.deepcopy(sinks)})
    return out


def parse_passes(results):
    """{rule id: {function names that can return a parameter}}."""
    passes = {}
    for _check_id, _path, _line, message in results:
        func, _, ids = message.partition("|")
        if func and not func.startswith("$"):
            for rule_id in ids.split(","):
                passes.setdefault(rule_id, set()).add(func)
    return passes


def python_functions_with_params(texts):
    """Names of the project's Python functions that take a parameter other than self/cls."""
    names = set()
    for text in texts:
        for name, nodes in python_functions(text).items():
            for node, _in_class in nodes:
                params = [a.arg for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]
                if node.args.vararg or node.args.kwarg or any(p not in RECEIVERS for p in params):
                    names.add(name)
    return names


def with_pass_through(rules, functions, passes, summaries, returners):
    """Each Python taint rule plus a sanitizer for the result of calls to functions that can't return a
    parameter: not found by pass_rules, not summarised (a call to one is a via-sink) and not a returner."""
    out = []
    for rule in rules:
        if rule not in taint_rules([rule]) or is_js(rule):
            out.append(rule)
            continue
        rule_id = rule["id"]
        clean = sorted(functions - passes.get(rule_id, set())
                       - {func for func, *_ in summaries.get(rule_id, ())}
                       - {func for func, _path in returners.get(rule_id, ())}
                       - HANDLER_NAMES)
        if not clean:
            out.append(rule)
            continue
        calls = [f"{a}{r}{PASS_THROUGH_MARK}(...)" for a in ("", "await ") for r in ("", "self.", "cls.")]
        sanitizers = [{"patterns": [
            {"pattern-either": [{"pattern-inside": f"$RESULT = {c}\n...\n"} for c in calls]},
            {"pattern": "$RESULT"},
            {"metavariable-regex": {"metavariable": PASS_THROUGH_MARK, "regex": regex}},
        ]} for regex in name_regexes(clean)]
        out.append({**rule, "pattern-sanitizers": [*rule.get("pattern-sanitizers", []), *sanitizers]})
    return out
