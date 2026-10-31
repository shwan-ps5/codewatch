"""Request-body models as taint sources: `def create(item: ItemCreate)` in a FastAPI route.

A route parameter typed with a Pydantic (or SQLModel) class is the parsed request body, and its text fields are
request data: `item.name` in a query is as tainted as `request.args["name"]`. Which classes are models, and which
of their fields hold text, is known only from the project's own class definitions, so the Python files are read
here and each request-source rule gets one more source naming them. Fields typed int, bool, UUID and the like
aren't text; a field name that is text in one model and not in another is left out.
"""
import ast
import re

MODEL_BASES = {"BaseModel", "pydantic.BaseModel", "SQLModel", "sqlmodel.SQLModel"}
TEXT_RE = re.compile(r"^((typing\.)?(Optional|List|Annotated)\[str\b.*|(list|set)\[str\]|str( \| None)?|Any)$")
ROUTE_MARK = "$ROUTE"


def model_fields(texts):
    """{model class: {text field}} and the field names that are non-text in some model, from Python sources."""
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

    text, other = {}, set()
    for name in models:
        for field, annotation in annotations(name).items():
            if TEXT_RE.match(annotation):
                text.setdefault(name, set()).add(field)
            else:
                other.add(field)
    return text, other


def model_source(text, other):
    """A Semgrep taint source for the text fields of route parameters typed with these models, or None."""
    fields = sorted({f for found in text.values() for f in found} - other)
    models = sorted(m for m, found in text.items() if found - other)
    if not fields or not models:
        return None
    route = ("@$APP.$ROUTE($PATH, ...)\n{}def $VIEW(..., $PARAM: $MODEL, ...):\n  ...\n")
    return {"patterns": [
        {"pattern-either": [{"pattern-inside": route.format(a)} for a in ("", "async ")]},
        {"metavariable-regex": {"metavariable": "$ROUTE", "regex": "^(route|get|post|put|patch|delete|api_route)$"}},
        {"metavariable-regex": {"metavariable": "$PATH", "regex": "^[rbuf]*['\"]/"}},
        {"metavariable-regex": {"metavariable": "$MODEL", "regex": f"^({'|'.join(map(re.escape, models))})$"}},
        {"pattern": "$PARAM.$FIELD"},
        {"metavariable-regex": {"metavariable": "$FIELD", "regex": f"^({'|'.join(map(re.escape, fields))})$"}},
    ]}


def with_model_sources(rules, texts):
    """The rules, with the model source added to every Python taint rule whose sources include route parameters."""
    source = model_source(*model_fields(texts))
    if source is None:
        return rules
    return [{**rule, "pattern-sources": [*rule["pattern-sources"], source]} if takes_route_sources(rule) else rule
            for rule in rules]


def takes_route_sources(rule):
    return (rule.get("mode") == "taint" and "python" in rule.get("languages", [])
            and ROUTE_MARK in repr(rule.get("pattern-sources")))
