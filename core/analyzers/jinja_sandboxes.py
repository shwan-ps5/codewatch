"""Jinja sandboxes the project makes in one module and renders with in another.

The template-injection rule leaves `env.from_string(text)` alone where `env = SandboxedEnvironment(...)` is in the
same function. paperless-ngx defines `class JinjaEnvironment(SandboxedEnvironment)`, makes
`_template_environment = JinjaEnvironment(...)` in one module and imports it where users' storage-path templates
are rendered. This reads the project with ast for classes based (through any of the project's classes) on
jinja2's SandboxedEnvironment or ImmutableSandboxedEnvironment, and the names and self fields assigned an instance
of one, and adds a sanitizer for `name.from_string(...)` and `name.get_template(...)` to that rule.
"""
import ast
import re

RULE = "codewatch.python.web.template-injection"
SANDBOXES = {"SandboxedEnvironment", "ImmutableSandboxedEnvironment"}


def base_name(node):
    return node.attr if isinstance(node, ast.Attribute) else getattr(node, "id", "")


def sandbox_names(texts):
    """Names (`env`, `self.env`) assigned an instance of a sandboxed Jinja environment anywhere in texts."""
    trees = []
    for text in texts:
        if "Environment" not in text:
            continue
        try:
            trees.append(ast.parse(text))
        except (SyntaxError, ValueError):
            continue
    bases = {}
    for tree in trees:
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                bases[node.name] = {base_name(b) for b in node.bases}
    sandboxes = set(SANDBOXES)
    changed = True
    while changed:
        changed = False
        for cls, parents in bases.items():
            if cls not in sandboxes and parents & sandboxes:
                sandboxes.add(cls)
                changed = True
    names = set()
    for tree in trees:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) \
                    and base_name(node.value.func) in sandboxes:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
                    elif isinstance(target, ast.Attribute) and getattr(target.value, "id", None) == "self":
                        names.add(f"self.{target.attr}")
    return names


def with_sandbox_sanitizers(rules, texts):
    names = sandbox_names(texts)
    if not names:
        return rules
    regex = "^(" + "|".join(sorted(map(re.escape, names))) + ")$"
    sanitizer = {"patterns": [
        {"pattern-either": [{"pattern": "$ENV.from_string(...)"}, {"pattern": "$ENV.get_template(...)"}]},
        {"metavariable-regex": {"metavariable": "$ENV", "regex": regex}},
    ]}
    return [{**rule, "pattern-sanitizers": [*rule.get("pattern-sanitizers", []), sanitizer]} if rule.get("id") == RULE
            else rule for rule in rules]
