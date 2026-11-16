"""Request-body models as taint sources: `def create(item: ItemCreate)` in a FastAPI route.

A route parameter typed with a Pydantic (or SQLModel) class is the parsed request body, and its text fields are
request data: `item.name` in a query is as tainted as `request.args["name"]`. Which classes are models, and which
of their fields hold text, is known only from the project's own class definitions, so the Python files are read
here and each request-source rule gets one more source naming them. Fields typed int, bool, UUID and the like
aren't text; a field name that is text in one model and not in another is left out.

A field typed with another model is followed one level (`data.table.table_name`), and a model with text fields
passed whole to a call (`preview(session, data)`) is request data there, so the callee's summary carries it to a
sink in another file (SQLBot CVE-2026-53556). In that callee the model's other fields are tainted too.
"""
import ast
import re

MODEL_BASES = {"BaseModel", "pydantic.BaseModel", "SQLModel", "sqlmodel.SQLModel"}
TEXT_RE = re.compile(r"^((typing\.)?(Optional|List|Annotated)\[str\b.*|(list|set)\[str\]|str( \| None)?|Any)$")
WRAPPER_RE = re.compile(r"^(?:typing\.)?(?:Optional|List|list|Sequence|set|Set)\[(.*)\]$")
ROUTE_MARK = "$ROUTE"


def model_named(annotation, models):
    """The model an annotation names, through Optional[...], List[...] and `| None`, or None."""
    while True:
        annotation = re.sub(r"\s*\|\s*None$", "", annotation.strip())
        inner = WRAPPER_RE.match(annotation)
        if not inner:
            return annotation if annotation in models else None
        annotation = inner.group(1)


def model_fields(texts):
    """{model class: {text field}}, the field names that are non-text in some model, and {model class: {field:
    model}} for fields typed with another model, from Python sources."""
    classes = {}
    for text in texts:
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                fields = {stmt.target.id: ast.unparse(stmt.annotation) for stmt in node.body
                          if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)}
                classes.setdefault(node.name, ([ast.unparse(b) for b in node.bases], fields))
    models = set()
    while True:
        more = {name for name, (bases, _) in classes.items()
                if name not in models and any(b in MODEL_BASES or b in models for b in bases)}
        if not more:
            break
        models |= more

    def annotations(name, seen=()):
        bases, fields = classes[name]
        inherited = {}
        for base in bases:
            if base in models and base not in seen:
                inherited |= annotations(base, (*seen, name))
        return inherited | fields

    text, other, nested = {}, set(), {}
    for name in models:
        for field, annotation in annotations(name).items():
            if TEXT_RE.match(annotation):
                text.setdefault(name, set()).add(field)
            else:
                other.add(field)
                if inner := model_named(annotation, models):
                    nested.setdefault(name, {})[field] = inner
    return text, other, nested


def route_patterns(models):
    """Inside a route function whose parameter $PARAM is typed with one of these models."""
    route = "@$APP.$ROUTE($PATH, ...)\n{}def $VIEW(..., $PARAM: $MODEL, ...):\n  ...\n"
    return [
        {"pattern-either": [{"pattern-inside": route.format(a)} for a in ("", "async ")]},
        {"metavariable-regex": {"metavariable": "$ROUTE", "regex": "^(route|get|post|put|patch|delete|api_route)$"}},
        {"metavariable-regex": {"metavariable": "$PATH", "regex": "^[rbuf]*['\"]/"}},
        {"metavariable-regex": {"metavariable": "$MODEL", "regex": f"^({alternation(models)})$"}},
    ]


def alternation(names):
    return "|".join(map(re.escape, sorted(names)))


def model_sources(text, other, nested=None):
    """Semgrep taint sources for route parameters typed with these models: their text fields, the text fields of
    their model-typed fields, and the whole model passed to a call. Empty when no model has text."""
    direct = {m: found - other for m, found in text.items() if found - other}
    deep = {}  # model: ({field typed with a model}, {that model's text fields})
    for model, fields in (nested or {}).items():
        subs = {f: direct[inner] for f, inner in fields.items() if inner in direct}
        if subs:
            deep[model] = (set(subs), set().union(*subs.values()))
    sources = []
    if direct:
        sources.append({"patterns": [
            *route_patterns(direct),
            {"pattern": "$PARAM.$FIELD"},
            {"metavariable-regex": {"metavariable": "$FIELD",
                                    "regex": f"^({alternation(set().union(*direct.values()))})$"}},
        ]})
    if deep:
        sources.append({"patterns": [
            *route_patterns(deep),
            {"pattern": "$PARAM.$SUB.$FIELD"},
            {"metavariable-regex": {"metavariable": "$SUB",
                                    "regex": f"^({alternation(set().union(*(s for s, _ in deep.values())))})$"}},
            {"metavariable-regex": {"metavariable": "$FIELD",
                                    "regex": f"^({alternation(set().union(*(f for _, f in deep.values())))})$"}},
        ]})
    if direct or deep:
        sources.append({"patterns": [
            *route_patterns({*direct, *deep}),
            {"pattern-either": [{"pattern": "$CALL(..., $PARAM, ...)"}, {"pattern": "$CALL(..., $KW=$PARAM, ...)"}]},
            {"focus-metavariable": "$PARAM"},
        ]})
    return sources


def with_model_sources(rules, texts):
    """The rules, with the model sources added to every Python taint rule whose sources include route parameters."""
    sources = model_sources(*model_fields(texts))
    if not sources:
        return rules
    return [{**rule, "pattern-sources": [*rule["pattern-sources"], *sources]} if takes_route_sources(rule) else rule
            for rule in rules]


def takes_route_sources(rule):
    return (rule.get("mode") == "taint" and "python" in rule.get("languages", [])
            and ROUTE_MARK in repr(rule.get("pattern-sources")))
