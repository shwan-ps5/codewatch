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

from .base import python_tree

CONVERTER_RE = re.compile(r"<(\w+)(?:\([^()<>]*\))?:(\w+)>")
TEXT_CONVERTERS = {"string", "path"}
TYPES = {"uuid": "uuid.UUID"}
# Flask-AppBuilder and Flask-Admin route a view class's methods with @expose("/path/<arg>"), imported bare.
ROUTE_DECORATORS = {"route", "get", "post", "put", "patch", "delete", "expose"}
BARE_ROUTE_DECORATORS = {"expose"}


def route_path(decorator):
    """The path string of a route decorator (@app.route("/x/<int:id>"), @expose("/x")), else None."""
    if not (isinstance(decorator, ast.Call) and decorator.args and call_name(decorator.func) in ROUTE_DECORATORS):
        return None
    if isinstance(decorator.func, ast.Name) and decorator.func.id not in BARE_ROUTE_DECORATORS:
        return None
    path = decorator.args[0]
    return path.value if isinstance(path, ast.Constant) and isinstance(path.value, str) else None


def converter_types(node):
    """{parameter: annotation} from the converters other than string and path in a function's route decorators."""
    return {name: TYPES.get(converter, converter)
            for path in filter(None, map(route_path, node.decorator_list))
            for converter, name in CONVERTER_RE.findall(path) if converter not in TEXT_CONVERTERS}


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
    for row, col, text, *replaced in sorted(edits, reverse=True):
        # ast columns count UTF-8 bytes. An edit may replace that many bytes (a 4-tuple) rather than only insert.
        raw = lines[row - 1].encode()
        lines[row - 1] = (raw[:col] + text.encode() + raw[col + sum(replaced):]).decode()
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
# A group starts at an unescaped "(": `\(?P<` is a literal parenthesis, and starting there read the rest of the route.
GROUP_RE = re.compile(r"(?<!\\)\(\?P<(\w+)>((?:[^()\\]|\\.|\((?:[^()\\]|\\.)*\))*)\)")
TEXT_GROUP_RE = re.compile(r"\.|\[\^|\\[SWD]")


def joined_text(node):
    return "".join(part.value for part in node.values if isinstance(part, ast.Constant) and isinstance(part.value, str))


def added_text(node):
    left, right = constant_text(node.left), constant_text(node.right)
    return None if left is None and right is None else (left or "") + (right or "")


def constant_text(node):
    """A route string: a constant, 'constant'.format(...), an f-string's constant parts or constants added."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return constant_text(node.func.value)
    if isinstance(node, ast.JoinedStr):
        return joined_text(node)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return added_text(node)
    return None


def call_name(node):
    return node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else None


def django_text_parameters(sources):
    """{view function name: {parameter}} for the URL arguments Django's routes pass as free text, from the
    urlpatterns in sources."""
    views = {}
    for tree in filter(None, (python_tree(source) for source in sources if "urlpatterns" in source)):
        for node in ast.walk(tree):
            if found := route_text_parameters(node):
                views.setdefault(found[0], set()).update(found[1])
    return views


def text_names(route, function):
    """The free-text parameters of a route: path() converters that take text, re_path() groups that match it."""
    if function == "path":
        return {name for converter, name in PATH_PARAMETER_RE.findall(route) if converter in TEXT_PATH_CONVERTERS}
    return {name for name, group in GROUP_RE.findall(route) if TEXT_GROUP_RE.search(group)}


def route_text_parameters(node):
    """(view name, {free-text parameters}) for a path()/re_path() call with both, else None."""
    if not (isinstance(node, ast.Call) and call_name(node.func) in DJANGO_ROUTES and len(node.args) >= 2):
        return None
    route, view = constant_text(node.args[0]), call_name(node.args[1])
    names = text_names(route, call_name(node.func)) if route is not None and view is not None else set()
    return (view, names) if names else None


def mark_url_text(source, views):
    """The source with the free-text URL arguments of the function views in views annotated URL_TEXT, or None."""
    if not views or not any(name in source for name in views):
        return None
    tree = python_tree(source)
    if tree is None:
        return None
    return annotated(source, [edit for node in ast.walk(tree)
                              if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in views
                              for edit in url_text_edits(node, views[node.name])])


def url_text_edits(view, names):
    """URL_TEXT annotations for a request view's unannotated parameters among names."""
    arguments = view.args.posonlyargs + view.args.args + view.args.kwonlyargs
    if not arguments or arguments[0].arg != "request":
        return []
    return [(arg.lineno, arg.end_col_offset, f": {URL_TEXT}")
            for arg in arguments[1:] if arg.arg in names and arg.annotation is None]


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


# Django REST framework's routers send /things/<lookup>/ to a ViewSet's detail methods (retrieve, update,
# partial_update, destroy and @action(detail=True) ones) as the keyword argument lookup_url_kwarg, else lookup_field,
# else pk, matched by lookup_value_regex: '[^/.]+' unless the class narrows it. That passes markup and quotes, so the
# argument is marked URL_TEXT like a Django route's free-text argument, unless the class's regex can't carry text
# (\d+, [0-9a-f-]+). CVAT CVE-2024-47064 (retrieve(self, request, pk: str) into an HttpResponseNotFound).
VIEWSET_BASE_RE = re.compile(r"(ViewSet|ViewSetMixin)$")
DETAIL_METHODS = {"retrieve", "update", "partial_update", "destroy"}


def class_constant(cls, name):
    """The string a class body assigns to name, if any."""
    for stmt in cls.body:
        if (isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in stmt.targets)
                and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str)):
            return stmt.value.value
    return None


def viewset_lookup(cls):
    """The URL argument a DRF ViewSet's detail methods receive, or None if it isn't a ViewSet or can't carry text."""
    if not any(VIEWSET_BASE_RE.search(call_name(base) or "") for base in cls.bases):
        return None
    regex = class_constant(cls, "lookup_value_regex")
    if regex is not None and not TEXT_GROUP_RE.search(regex):
        return None
    return class_constant(cls, "lookup_url_kwarg") or class_constant(cls, "lookup_field") or "pk"


def detail_action(method):
    """Whether a ViewSet method takes the object's lookup from the URL: a standard detail method or @action(detail=True)."""
    return method.name in DETAIL_METHODS or any(
        isinstance(d, ast.Call) and call_name(d.func) == "action"
        and any(k.arg == "detail" and isinstance(k.value, ast.Constant) and k.value.value is True for k in d.keywords)
        for d in method.decorator_list)


def lookup_edits(method, lookup):
    """Edits marking a detail method's lookup argument URL_TEXT: an unannotated one, or one annotated str."""
    edits = []
    for arg in (method.args.posonlyargs + method.args.args + method.args.kwonlyargs)[2:]:
        if arg.arg != lookup:
            continue
        if arg.annotation is None:
            edits.append((arg.lineno, arg.end_col_offset, f": {URL_TEXT}"))
        elif isinstance(arg.annotation, ast.Name) and arg.annotation.id == "str" and arg.annotation.lineno == arg.lineno:
            edits.append((arg.lineno, arg.annotation.col_offset, URL_TEXT, len("str")))
    return edits


def mark_viewset_lookups(source):
    """The source with DRF ViewSets' free-text lookup arguments annotated URL_TEXT, or None."""
    if "ViewSet" not in source:
        return None
    tree = python_tree(source)
    if tree is None:
        return None
    edits = [edit for cls in ast.walk(tree) if isinstance(cls, ast.ClassDef) and (lookup := viewset_lookup(cls))
             for method in cls.body
             if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and detail_action(method)
             for edit in lookup_edits(method, lookup)]
    return annotated(source, edits)
