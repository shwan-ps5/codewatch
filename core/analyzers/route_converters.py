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
    if not edits:
        return None
    lines = source.splitlines(keepends=True)
    for row, col, text in sorted(edits, reverse=True):
        # ast columns count UTF-8 bytes.
        raw = lines[row - 1].encode()
        lines[row - 1] = (raw[:col] + text.encode() + raw[col:]).decode()
    return "".join(lines)


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
