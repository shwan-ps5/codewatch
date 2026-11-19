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

from .base import python_tree

RULE = "codewatch.python.web.template-injection"
SANDBOXES = {"SandboxedEnvironment", "ImmutableSandboxedEnvironment"}


def base_name(node):
    return node.attr if isinstance(node, ast.Attribute) else getattr(node, "id", "")


def sandbox_names(texts):
    """Names (`env`, `self.env`) assigned an instance of a sandboxed Jinja environment anywhere in texts."""
    trees = [tree for tree in (python_tree(text) for text in texts if "Environment" in text) if tree]
    sandboxes = sandbox_classes(trees)
    return {name for tree in trees for node in ast.walk(tree) if creates(node, sandboxes)
            for name in assigned_names(node.targets)}


def creates(node, classes):
    """`x = Cls(...)` for one of classes."""
    return isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and base_name(node.value.func) in classes


def sandbox_classes(trees):
    """The sandboxed environment classes, and the project's classes derived from them at any depth."""
    bases = {node.name: {base_name(b) for b in node.bases}
             for tree in trees for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}
    sandboxes = set(SANDBOXES)
    while more := {cls for cls, parents in bases.items() if cls not in sandboxes and parents & sandboxes}:
        sandboxes |= more
    return sandboxes


def assigned_names(targets):
    """`env` and `self.env` among assignment targets."""
    return [target.id if isinstance(target, ast.Name) else f"self.{target.attr}" for target in targets
            if isinstance(target, ast.Name)
            or (isinstance(target, ast.Attribute) and getattr(target.value, "id", None) == "self")]


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
