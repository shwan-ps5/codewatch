"""Flask-RESTful / Flask-RESTX resources' URL parameters as request sources.

A Resource's handler methods take the URL's variable parts as parameters (`def get(self, rdtype, domain)`), but
the URL is given elsewhere: `api.add_resource(LookupRecordType, "/<rdtype>/<domain>")`. This reads those
registrations with ast and adds, per registered class, a source for the parameters the URL fills with text (no
converter, `string` or `path`): `<int:certificate_id>` is a number. OpenResolve GHSA-h3h4 (a record type and domain
from the path, reflected in error messages).
"""
import ast
import re

from .body_models import takes_route_sources

PARAMETER_RE = re.compile(r"<(?:(\w+)(?:\([^)>]*\))?:)?(\w+)>")
TEXT_CONVERTERS = {"", "string", "path"}
HANDLERS = "get|post|put|patch|delete"


def text_parameters(texts):
    """{resource class name: URL parameters filled with text}, from `$API.add_resource(Class, "/url", ...)`."""
    found = {}
    for text in texts:
        if "add_resource" not in text:
            continue
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "add_resource" and node.args):
                continue
            target = node.args[0]
            name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", None)
            urls = [a.value for a in node.args[1:] if isinstance(a, ast.Constant) and isinstance(a.value, str)]
            params = {param for url in urls for converter, param in PARAMETER_RE.findall(url)
                      if converter in TEXT_CONVERTERS}
            if name and params:
                found.setdefault(name, set()).update(params)
    return found


def resource_source(cls, params):
    names = "|".join(sorted(map(re.escape, params)))
    return {"patterns": [
        {"pattern-inside": f"class {cls}(...):\n  ...\n"},
        {"pattern-inside": "def $HANDLER(self, ..., $PARAM, ...):\n  ...\n"},
        {"metavariable-regex": {"metavariable": "$HANDLER", "regex": f"^({HANDLERS})$"}},
        {"metavariable-regex": {"metavariable": "$PARAM", "regex": f"^({names})$"}},
        {"focus-metavariable": "$PARAM"},
    ]}


def with_resource_sources(rules, texts):
    """The rules, with a source per registered resource on every Python taint rule that takes route parameters."""
    found = text_parameters(texts)
    if not found:
        return rules
    extra = [resource_source(cls, params) for cls, params in sorted(found.items())]
    return [{**rule, "pattern-sources": [*rule["pattern-sources"], *extra]} if takes_route_sources(rule) else rule
            for rule in rules]
