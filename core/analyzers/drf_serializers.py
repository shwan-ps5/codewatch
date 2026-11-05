"""Django REST framework field checks as sanitizers: `validated_data["field"]` in a serializer that defines
`validate_field`.

DRF calls a serializer's `validate_<field>(self, value)` on that field before create() or update() sees it, and
whatever the method returns (or raises) is what lands in `validated_data`. The rules can't tie a key to a method's
name, so this reads the project's serializers with ast and adds, per serializer, a sanitizer for its checked
fields read from any mapping inside the class. firefighter GHSA-fqvv's fix: validate_attachments() rejects
private and non-http URLs, and create() then fetches validated_data["attachments"].
"""
import ast
import re

SERIALIZER_BASE_RE = re.compile(r"Serializer$")
CHECK_PREFIX = "validate_"


def base_name(node):
    """The last name of a base class expression: `serializers.ModelSerializer[JiraTicket]` -> ModelSerializer."""
    if isinstance(node, ast.Subscript):
        node = node.value
    if isinstance(node, ast.Attribute):
        return node.attr
    return getattr(node, "id", "")


def checked_fields(texts):
    """{serializer class name: fields it checks with validate_<field>}, from the project's Python sources."""
    checked = {}
    for text in texts:
        if CHECK_PREFIX not in text or "Serializer" not in text:
            continue
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef) or not any(
                    SERIALIZER_BASE_RE.search(base_name(b)) for b in node.bases):
                continue
            fields = {item.name.removeprefix(CHECK_PREFIX) for item in node.body
                      if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                      and item.name.startswith(CHECK_PREFIX) and len(item.name) > len(CHECK_PREFIX)}
            if fields:
                checked.setdefault(node.name, set()).update(fields)
    return checked


def field_sanitizer(cls, fields):
    keys = "|".join(sorted(map(re.escape, fields)))
    return {"patterns": [
        {"pattern-inside": f"class {cls}(...):\n  ...\n"},
        {"pattern-either": [{"pattern": "$DATA[$KEY]"}, {"pattern": "$DATA.get($KEY, ...)"}]},
        {"metavariable-regex": {"metavariable": "$KEY", "regex": f"^[rbu]*['\"]({keys})['\"]$"}},
    ]}


def with_serializer_checks(rules, texts):
    """The rules, with a sanitizer per serializer's checked fields on every Python taint rule."""
    checked = checked_fields(texts)
    if not checked:
        return rules
    extra = [field_sanitizer(cls, fields) for cls, fields in sorted(checked.items())]
    return [{**rule, "pattern-sanitizers": [*rule.get("pattern-sanitizers", []), *extra]}
            if rule.get("mode") == "taint" and "python" in rule.get("languages", []) else rule
            for rule in rules]
