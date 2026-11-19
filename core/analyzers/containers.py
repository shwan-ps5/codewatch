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


OTHER_BINDINGS = (ast.AnnAssign, ast.AugAssign, ast.NamedExpr, ast.For, ast.AsyncFor, ast.comprehension, ast.withitem,
                  ast.Delete)


def assign_bindings(node):
    return [(name.id, node.value if target is name else None)
            for target in node.targets for name in stored_names(target)]


def other_bindings(node):
    targets = getattr(node, "targets", None) or [getattr(node, "target", None) or node.optional_vars]
    return [(name.id, None) for target in targets if target is not None for name in stored_names(target)]


def node_bindings(node):
    """(name, value) for each name a node binds, value None for anything but a plain `name = value`."""
    if isinstance(node, ast.Assign):
        return assign_bindings(node)
    if isinstance(node, OTHER_BINDINGS):
        return other_bindings(node)
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return [(n, None) for n in node.names]
    return []


def bound_names(nodes):
    """{name: [values assigned to it]}, with None for bindings other than a plain `name = value`."""
    bindings = {}
    for node in nodes:
        for name, value in node_bindings(node):
            bindings.setdefault(name, []).append(value)
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


def dict_subscript_edit(node, dicts):
    if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id in dicts
            and constant_strings([node.slice])):
        return replace(node, f"{node.value.id}.{field_name(node.slice.value)}")
    return None


def dict_get_edit(node, dicts):
    if (call := method_call(node, dicts, "get")) and len(call.args) == 1 and constant_strings(call.args):
        return replace(call, f"{call.func.value.id}.{field_name(call.args[0].value)}")
    return None


def parser_get_edit(node, parsers):
    if (call := method_call(node, parsers, "get")) and len(call.args) == 2 and constant_strings(call.args):
        return replace(call, f"{call.func.value.id}.{field_name(*(a.value for a in call.args))}")
    return None


def parser_set_edit(source, node, parsers):
    if not isinstance(node, ast.Expr):
        return None
    call = method_call(node.value, parsers, "set")
    if not call or len(call.args) != 3 or not constant_strings(call.args[:2]):
        return None
    value = ast.get_source_segment(source, call.args[2])
    return replace(call, f"{call.func.value.id}.{field_name(call.args[0].value, call.args[1].value)} = {value}")


def slot_edit(source, node, dicts, parsers):
    """The rewrite of one constant-key dict or ConfigParser access, or None."""
    return (dict_subscript_edit(node, dicts) or dict_get_edit(node, dicts) or parser_get_edit(node, parsers)
            or parser_set_edit(source, node, parsers))


def slot_edits(source, nodes, dicts, parsers):
    return [edit for node in nodes if one_line(node) and (edit := slot_edit(source, node, dicts, parsers))]


def statement_lists(nodes):
    for node in nodes:
        for field in BODY_FIELDS:
            body = getattr(node, field, None)
            if isinstance(body, list) and body and isinstance(body[0], ast.stmt):
                yield body
        if isinstance(node, ast.ExceptHandler):
            yield node.body


COMPOUND = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try, ast.Match, *SCOPES, ast.ClassDef)


def is_slot_read(node, name):
    """`name[3]`: a load of a constant int index."""
    return (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == name
            and isinstance(node.ctx, ast.Load) and isinstance(node.slice, ast.Constant)
            and type(node.slice.value) is int)


def constant_index_reads(stmt, name):
    """Constant-index loads of `name` in a simple statement, or None if it uses the list any other way."""
    if isinstance(stmt, COMPOUND):
        return None
    reads = [node for node in ast.walk(stmt) if is_slot_read(node, name)]
    inside = {id(node.value) for node in reads}
    uses = [n for n in ast.walk(stmt) if isinstance(n, ast.Name) and n.id == name]
    return reads if all(id(n) in inside for n in uses) else None


def int_indexes(args):
    return [a.value for a in args[:1] if isinstance(a, ast.Constant) and type(a.value) is int]


def append_slot(slots, args):
    if len(args) != 1:
        return False
    slots.append(args[0])
    return True


def insert_slot(slots, args):
    if len(args) != 2 or not int_indexes(args):
        return False
    slots.insert(int_indexes(args)[0], args[1])
    return True


def pop_slot(slots, args):
    if not args and slots:
        slots.pop()
        return True
    if len(args) == 1 and int_indexes(args):
        slots.pop(int_indexes(args)[0])
        return True
    return False


def reverse_slots(slots, args):
    if args:
        return False
    slots.reverse()
    return True


def extend_slots(slots, args):
    if len(args) != 1 or not isinstance(args[0], (ast.List, ast.Tuple)):
        return False
    slots.extend(args[0].elts)
    return True


LIST_METHODS = {"append": append_slot, "insert": insert_slot, "pop": pop_slot, "reverse": reverse_slots,
                "extend": extend_slots}


def list_method_call(stmt, name):
    """`name.method(...)` as a whole statement, or None."""
    if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)
            and isinstance(stmt.value.func, ast.Attribute)):
        return None
    return method_call(stmt.value, {name}, stmt.value.func.attr)


def mutate(slots, stmt, name):
    """Apply a list method call statement to the simulated slots; False if it isn't one we can follow."""
    call = list_method_call(stmt, name)
    if call is None or call.keywords or call.func.attr not in LIST_METHODS:
        return False
    try:
        return LIST_METHODS[call.func.attr](slots, call.args)
    except IndexError:
        return False


def list_literal(stmt):
    """(name, [its slots]) for `name = [a, b]` without starred items, else None."""
    if (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name)
            and isinstance(stmt.value, ast.List) and not any(isinstance(e, ast.Starred) for e in stmt.value.elts)):
        return stmt.targets[0].id, list(stmt.value.elts)
    return None


def read_edits(source, reads, slots):
    """Each read replaced by the literal its slot holds, where both are on one line."""
    edits = []
    for read in reads:
        index = read.slice.value
        slot = slots[index] if -len(slots) <= index < len(slots) else None
        if isinstance(slot, ast.Constant) and one_line(read) and one_line(slot):
            edits.append(replace(read, ast.get_source_segment(source, slot)))
    return edits


def followed_list_edits(source, later_statements, name, slots):
    """Edits for a list's constant-index reads, following its mutations until a use that can't be followed."""
    edits = []
    for later in later_statements:
        if not any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(later)) or mutate(slots, later, name):
            continue
        reads = constant_index_reads(later, name)
        if reads is None:
            break
        edits += read_edits(source, reads, slots)
    return edits


def list_edits(source, nodes):
    edits = []
    for body in statement_lists(nodes):
        for start, stmt in enumerate(body):
            if found := list_literal(stmt):
                edits += followed_list_edits(source, body[start + 1:], *found)
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
