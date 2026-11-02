"""Give Flask view arguments the type of their URL converter, for Semgrep's taint rules.

A Flask view's arguments come from the URL path: `@app.route("/user/<name>") def user(name)`. Only the default,
`string` and `path` converters pass free text; the others (`int`, `uuid`, `any(a, b)`, and an app's own, usually a
regex) limit the value. A Semgrep pattern can't tie the converter in the route string to the parameter of the same
name, so on the copy Semgrep scans such a parameter gets an annotation (`id: int`, `key: uuid.UUID`, `tag: uuid_str`),
which the request-source rules skip like any typed FastAPI parameter. Only unannotated parameters change, and every
line keeps its number.
"""
import ast
import re

CONVERTER_RE = re.compile(r"<(\w+)(?:\([^)>]*\))?:(\w+)>")
TEXT_CONVERTERS = {"string", "path"}
TYPES = {"uuid": "uuid.UUID"}
ROUTE_DECORATORS = {"route", "get", "post", "put", "patch", "delete"}


def converter_types(node):
    """{parameter: annotation} from the converters other than string and path in a function's route decorators."""
    types = {}
    for decorator in node.decorator_list:
        if (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr in ROUTE_DECORATORS and decorator.args
                and isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str)):
            for converter, name in CONVERTER_RE.findall(decorator.args[0].value):
                if converter not in TEXT_CONVERTERS:
                    types[name] = TYPES.get(converter, converter)
    return types


def type_route_converters(source):
    """The source with converter-typed view parameters annotated, or None if there are none."""
    if "<" not in source or ":" not in source:
        return None
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    edits = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not node.decorator_list:
            continue
        types = converter_types(node)
        edits.extend((arg.lineno, arg.end_col_offset, f": {types[arg.arg]}")
                     for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs
                     if arg.arg in types and arg.annotation is None)
    return annotated(source, edits)


def annotated(source, edits):
    """The source with each (line, column, text) inserted, or None if there are none."""
    if not edits:
        return None
    lines = source.splitlines(keepends=True)
    for row, col, text in sorted(edits, reverse=True):
        # ast columns count UTF-8 bytes.
        raw = lines[row - 1].encode()
        lines[row - 1] = (raw[:col] + text.encode() + raw[col:]).decode()
    return "".join(lines)


# Django routes its URLs in urls.py: path("files/<path:name>", views.serve) or re_path(r"^files/(?P<name>.*)$", serve).
# A view's arguments past the request come from the URL; those whose converter or regex group lets through free
# text (str, path, or a group that allows dots or excludes characters, like .* or [^/]+) are marked on the copy
# Semgrep scans with the annotation URL_TEXT, which the request-source rule matches. <int:pk>, <slug:slug>, [\w-]+
# and \d+ can't carry a path, quotes or markup, and a view the analysis can't see routed stays unmarked.
URL_TEXT = "codewatch_url_text"
DJANGO_ROUTES = {"path", "re_path", "url"}
PATH_PARAMETER_RE = re.compile(r"<(?:(\w+):)?(\w+)>")
TEXT_PATH_CONVERTERS = {"", "str", "path"}
GROUP_RE = re.compile(r"\(\?P<(\w+)>((?:[^()\\]|\\.|\((?:[^()\\]|\\.)*\))*)\)")
TEXT_GROUP_RE = re.compile(r"\.|\[\^|\\[SWD]")


def constant_text(node):
    """A route string: a constant, 'constant'.format(...), an f-string's constant parts or constants added."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return constant_text(node.func.value)
    if isinstance(node, ast.JoinedStr):
        return "".join(part.value for part in node.values if isinstance(part, ast.Constant))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = constant_text(node.left), constant_text(node.right)
        return None if left is None and right is None else (left or "") + (right or "")
    return None


def call_name(node):
    return node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else None


def django_text_parameters(sources):
    """{view function name: {parameter}} for the URL arguments Django's routes pass as free text, from the
    urlpatterns in sources."""
    views = {}
    for source in sources:
        if "urlpatterns" not in source:
            continue
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and call_name(node.func) in DJANGO_ROUTES and len(node.args) >= 2):
                continue
            route, view = constant_text(node.args[0]), call_name(node.args[1])
            if route is None or view is None:
                continue
            if call_name(node.func) == "path":
                names = {name for converter, name in PATH_PARAMETER_RE.findall(route)
                         if converter in TEXT_PATH_CONVERTERS}
            else:
                names = {name for name, group in GROUP_RE.findall(route) if TEXT_GROUP_RE.search(group)}
            if names:
                views.setdefault(view, set()).update(names)
    return views


def mark_url_text(source, views):
    """The source with the free-text URL arguments of the function views in views annotated URL_TEXT, or None."""
    if not views or not any(name in source for name in views):
        return None
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    edits = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name not in views:
            continue
        arguments = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        if not arguments or arguments[0].arg != "request":
            continue
        edits.extend((arg.lineno, arg.end_col_offset, f": {URL_TEXT}")
                     for arg in arguments[1:] if arg.arg in views[node.name] and arg.annotation is None)
    return annotated(source, edits)


SCALAR_RE = re.compile(r"^(typing\.)?(Optional\[)?(int|float|bool|(uuid\.)?UUID|(datetime\.)?(date|datetime|time)|"
                       r"(decimal\.)?Decimal|uuid_str)\]?$|^(int|float|bool) \| None$")


def scalar_parameters(source):
    """{(function, parameter)} for parameters annotated with a type that can't carry text: int, bool, UUID, a date,
    or (after type_route_converters) a Flask converter other than string and path."""
    source = type_route_converters(source) or source
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return set()
    return {(node.name, arg.arg)
            for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs
            if arg.annotation is not None and SCALAR_RE.match(ast.unparse(arg.annotation))}
