"""Rewrite local containers in Python so Semgrep's taint analysis tracks each slot on its own.

Semgrep tracks taint per attribute, but not per constant dict key or list position: after `m["a"] = param;
m["b"] = "x"` a read of m["a"] comes out clean, and once request data is in a list or ConfigParser every slot reads
as tainted. In the copy Semgrep scans (never run; every token stays on its line):

- constant-key reads and writes of a local dict, and ConfigParser set/get with a constant section and option,
  become attributes (m.k_a), which Semgrep tracks one by one;
- a constant-index read of a local list, after appends, inserts and pops that run straight-line from where the
  list was created, becomes the literal that slot must hold.
"""
import ast
import re

SCOPES = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)
CONFIG_PARSERS = {"ConfigParser", "RawConfigParser", "SafeConfigParser"}
BODY_FIELDS = ("body", "orelse", "finalbody")


def scope_nodes(scope):
    """Nodes in a scope, not descending into nested functions, classes or lambdas."""
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (*SCOPES, ast.ClassDef, ast.Lambda)):
            stack.extend(ast.iter_child_nodes(node))


def is_dict_value(node):
    return isinstance(node, ast.Dict) or (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                                          and node.func.id == "dict" and not node.args)


def is_config_parser(node):
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    return (isinstance(func, ast.Name) and func.id in CONFIG_PARSERS) or (
        isinstance(func, ast.Attribute) and func.attr in CONFIG_PARSERS)


def bound_names(nodes):
    """{name: [values assigned to it]}, with None for bindings other than a plain `name = value`."""
    bindings = {}
    for node in nodes:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                for name in stored_names(target):
                    bindings.setdefault(name.id, []).append(node.value if target is name else None)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr, ast.For, ast.AsyncFor,
                               ast.comprehension, ast.withitem, ast.Delete)):
            targets = getattr(node, "targets", None) or [getattr(node, "target", None) or node.optional_vars]
            for name in (n for t in targets if t is not None for n in stored_names(t)):
                bindings.setdefault(name.id, []).append(None)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for n in node.names:
                bindings.setdefault(n, []).append(None)
    return bindings


def stored_names(target):
    """Names a target binds; m in m["k"] = v is only read."""
    return [n for n in ast.walk(target) if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del))]


def only_bound_to(bindings, test):
    return {name for name, values in bindings.items() if all(v is not None and test(v) for v in values)}


def field_name(*keys):
    return "k_" + re.sub(r"\W", "_", "_".join(keys))


def constant_strings(args):
    return all(isinstance(a, ast.Constant) and isinstance(a.value, str) for a in args)


def one_line(node):
    return getattr(node, "lineno", None) is not None and node.lineno == node.end_lineno


def method_call(node, names, method):
    """The call `name.method(...)` on one of names, or None."""
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == method
            and isinstance(node.func.value, ast.Name) and node.func.value.id in names):
        return node
    return None


def slot_edits(source, nodes, dicts, parsers):
    edits = []
    for node in nodes:
        if not one_line(node):
            continue
        if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id in dicts
                and constant_strings([node.slice])):
            edits.append(replace(node, f"{node.value.id}.{field_name(node.slice.value)}"))
        elif (call := method_call(node, dicts, "get")) and len(call.args) == 1 and constant_strings(call.args):
            edits.append(replace(call, f"{call.func.value.id}.{field_name(call.args[0].value)}"))
        elif (call := method_call(node, parsers, "get")) and len(call.args) == 2 and constant_strings(call.args):
            edits.append(replace(call, f"{call.func.value.id}.{field_name(*(a.value for a in call.args))}"))
        elif (isinstance(node, ast.Expr) and (call := method_call(node.value, parsers, "set"))
              and len(call.args) == 3 and constant_strings(call.args[:2])):
            value = ast.get_source_segment(source, call.args[2])
            target = f"{call.func.value.id}.{field_name(call.args[0].value, call.args[1].value)}"
            edits.append(replace(call, f"{target} = {value}"))
    return edits


def statement_lists(nodes):
    for node in nodes:
        for field in BODY_FIELDS:
            body = getattr(node, field, None)
            if isinstance(body, list) and body and isinstance(body[0], ast.stmt):
                yield body
        if isinstance(node, ast.ExceptHandler):
            yield node.body


def constant_index_reads(stmt, name):
    """Constant-index loads of `name` in a simple statement, or None if it uses the list any other way."""
    if isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try, ast.Match,
                         *SCOPES, ast.ClassDef)):
        return None
    reads, inside = [], set()
    for node in ast.walk(stmt):
        if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == name
                and isinstance(node.ctx, ast.Load) and isinstance(node.slice, ast.Constant)
                and type(node.slice.value) is int):
            reads.append(node)
            inside.add(id(node.value))
    uses = [n for n in ast.walk(stmt) if isinstance(n, ast.Name) and n.id == name]
    return reads if all(id(n) in inside for n in uses) else None


def mutate(slots, stmt, name):
    """Apply a list method call statement to the simulated slots; False if it isn't one we can follow."""
    call = method_call(stmt.value, {name}, stmt.value.func.attr) if (
        isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)
        and isinstance(stmt.value.func, ast.Attribute)) else None
    if call is None or call.keywords:
        return False
    args, method = call.args, call.func.attr
    indexes = [a.value for a in args[:1] if isinstance(a, ast.Constant) and type(a.value) is int]
    try:
        if method == "append" and len(args) == 1:
            slots.append(args[0])
        elif method == "insert" and len(args) == 2 and indexes:
            slots.insert(indexes[0], args[1])
        elif method == "pop" and not args and slots:
            slots.pop()
        elif method == "pop" and len(args) == 1 and indexes:
            slots.pop(indexes[0])
        elif method == "reverse" and not args:
            slots.reverse()
        elif method == "extend" and len(args) == 1 and isinstance(args[0], (ast.List, ast.Tuple)):
            slots.extend(args[0].elts)
        else:
            return False
    except IndexError:
        return False
    return True


def list_edits(source, nodes):
    edits = []
    for body in statement_lists(nodes):
        for start, stmt in enumerate(body):
            if not (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name)
                    and isinstance(stmt.value, ast.List)
                    and not any(isinstance(e, ast.Starred) for e in stmt.value.elts)):
                continue
            name, slots = stmt.targets[0].id, list(stmt.value.elts)
            for later in body[start + 1:]:
                if not any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(later)):
                    continue
                if mutate(slots, later, name):
                    continue
                reads = constant_index_reads(later, name)
                if reads is None:
                    break
                for read in reads:
                    try:
                        slot = slots[read.slice.value]
                    except IndexError:
                        continue
                    if isinstance(slot, ast.Constant) and one_line(read) and one_line(slot):
                        edits.append(replace(read, ast.get_source_segment(source, slot)))
    return edits


def replace(node, text):
    return node.lineno, node.col_offset, node.end_col_offset, text


def container_edits(source):
    tree = ast.parse(source)
    edits = []
    for scope in [n for n in ast.walk(tree) if isinstance(n, SCOPES)]:
        nodes = list(scope_nodes(scope))
        bindings = bound_names(nodes)
        dicts, parsers = only_bound_to(bindings, is_dict_value), only_bound_to(bindings, is_config_parser)
        edits += slot_edits(source, nodes, dicts, parsers)
        edits += list_edits(source, nodes)
    return edits


def track_slots(source):
    """The source with container slots rewritten (see the module docstring), or None if nothing changes."""
    if "[" not in source and "ConfigParser" not in source:
        return None
    try:
        edits = container_edits(source)
    except (SyntaxError, ValueError):
        return None
    if not edits:
        return None
    lines = source.splitlines(keepends=True)
    applied = {}
    # Reverse order keeps earlier columns valid; an edit nested in one already made is dropped.
    for row, start, end, new in sorted(set(edits), key=lambda e: (e[0], e[1], -e[2]), reverse=True):
        if any(start < s_end and s_start < end for s_start, s_end in applied.get(row, [])):
            continue
        raw = lines[row - 1].encode()
        lines[row - 1] = (raw[:start] + new.encode() + raw[end:]).decode()
        applied.setdefault(row, []).append((start, end))
    return "".join(lines)
