"""Blank out branches whose condition is decided by constants, for Semgrep's taint analysis.

`num = 106` then `bar = "fixed" if 7 * 18 + num > 200 else param` never uses `param`, but Semgrep follows both
branches. On the copy Semgrep scans, a branch that can't run is replaced: a dead `if`/`else`/`case` body becomes
`pass` lines, a dead ternary arm becomes `None`. Only conditions built from literals and names assigned exactly
once from a literal are evaluated; anything else is left alone. Every line keeps its number.
"""
import ast
import contextlib
import operator

BINOPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.FloorDiv: operator.floordiv,
          ast.Mod: operator.mod}
COMPARES = {ast.Lt: operator.lt, ast.Gt: operator.gt, ast.LtE: operator.le, ast.GtE: operator.ge,
            ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.In: lambda a, b: a in b,
            ast.NotIn: lambda a, b: a not in b}
MAX_INT = 10 ** 12
MAX_STR = 1000


class Unknown(Exception):
    pass


def evaluate(node, env):
    """The value of a constant expression, or Unknown."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, str, bool)):
        value = node.value
    elif isinstance(node, ast.Name) and node.id in env:
        value = env[node.id]
    elif isinstance(node, ast.BinOp) and type(node.op) in BINOPS:
        left, right = evaluate(node.left, env), evaluate(node.right, env)
        if not (isinstance(left, int) and isinstance(right, int)) or (
                isinstance(node.op, (ast.FloorDiv, ast.Mod)) and right == 0):
            raise Unknown
        value = BINOPS[type(node.op)](left, right)
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.Not)):
        operand = evaluate(node.operand, env)
        value = (not operand) if isinstance(node.op, ast.Not) else -operand
    elif isinstance(node, ast.BoolOp):
        values = [evaluate(v, env) for v in node.values]
        value = all(values) if isinstance(node.op, ast.And) else any(values)
    elif isinstance(node, ast.Compare) and all(type(op) in COMPARES for op in node.ops):
        left, value = evaluate(node.left, env), True
        for op, comparator in zip(node.ops, node.comparators, strict=True):
            right = evaluate(comparator, env)
            try:
                value = value and COMPARES[type(op)](left, right)
            except TypeError as exc:
                raise Unknown from exc
            left = right
    elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
        base, index = evaluate(node.value, env), node.slice.value
        if not (isinstance(base, str) and isinstance(index, int) and -len(base) <= index < len(base)):
            raise Unknown
        value = base[index]
    else:
        raise Unknown
    if (isinstance(value, int) and abs(value) > MAX_INT) or (isinstance(value, str) and len(value) > MAX_STR):
        raise Unknown
    return value


def constants(scope):
    """Names assigned exactly once in a function (or module), from a literal or another such constant."""
    stores, literal = {}, {}
    for node in ast.walk(scope):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            stores[node.id] = stores.get(node.id, 0) + 1
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                stores[name] = 2
        if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)):
            literal.setdefault(node.targets[0].id, []).append(node.value)
    env = {}
    for name, values in literal.items():
        if stores.get(name) == 1 and len(values) == 1:
            with contextlib.suppress(Unknown):
                env[name] = evaluate(values[0], env)
    return env


def scopes(tree):
    yield tree, [n for n in tree.body if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node, node.body


def nodes_in(body):
    """Every node in a scope's statements, without entering nested functions (they have their own constants)."""
    stack = list(body)
    while stack:
        node = stack.pop()
        yield node
        stack += [c for c in ast.iter_child_nodes(node)
                  if not isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda))]


def decide(test, env):
    try:
        return bool(evaluate(test, env))
    except Unknown:
        return None


def case_matches(pattern, subject):
    """True/False when a literal case pattern can be compared with the subject, None otherwise."""
    if isinstance(pattern, ast.MatchAs) and pattern.pattern is None:
        return True
    if isinstance(pattern, ast.MatchValue) and isinstance(pattern.value, ast.Constant):
        return pattern.value.value == subject
    if isinstance(pattern, ast.MatchOr):
        results = [case_matches(p, subject) for p in pattern.patterns]
        return None if None in results else any(results)
    return None


def dead_code(tree):
    """(dead statement blocks, dead expressions) for branches decided by constants."""
    blocks, exprs = [], []
    for scope, body in scopes(tree):
        env = constants(scope) if scope is not tree else constants(ast.Module(body=body, type_ignores=[]))
        if not env:
            continue
        for node in nodes_in(body):
            if isinstance(node, (ast.If, ast.While)) and (taken := decide(node.test, env)) is not None:
                dead = node.orelse if taken else node.body
                if dead and not (isinstance(node, ast.While) and taken):
                    blocks.append(dead)
            elif isinstance(node, ast.IfExp) and (taken := decide(node.test, env)) is not None:
                exprs.append(node.orelse if taken else node.body)
            elif isinstance(node, ast.Match):
                blocks += dead_cases(node, env)
    return blocks, exprs


def dead_cases(node, env):
    try:
        subject = evaluate(node.subject, env)
    except Unknown:
        return []
    results = [None if case.guard else case_matches(case.pattern, subject) for case in node.cases]
    if None in results or True not in results:
        return []
    live = results.index(True)
    return [case.body for i, case in enumerate(node.cases) if i != live]


def blank_dead_branches(source):
    """The source with constant-decided dead branches blanked, or None if there are none."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    blocks, exprs = dead_code(tree)
    if not blocks and not exprs:
        return None
    lines = source.splitlines(keepends=True)
    blank = {}
    for block in blocks:
        first = lines[block[0].lineno - 1]
        indent = first[:len(first) - len(first.lstrip())]
        for row in range(block[0].lineno, max(s.end_lineno or s.lineno for s in block) + 1):
            blank[row] = indent
    for expr in sorted(exprs, key=lambda e: (e.lineno, e.col_offset), reverse=True):
        if expr.lineno != expr.end_lineno or expr.lineno in blank:
            continue
        line = lines[expr.lineno - 1]
        start, end = col_to_index(line, expr.col_offset), col_to_index(line, expr.end_col_offset)
        lines[expr.lineno - 1] = line[:start] + "None" + line[end:]
    for row, indent in blank.items():
        ending = "\n" if lines[row - 1].endswith("\n") else ""
        lines[row - 1] = f"{indent}pass{ending}"
    return "".join(lines)


def col_to_index(line, col):
    """ast columns count UTF-8 bytes; string slicing counts characters."""
    return len(line.encode()[:col].decode(errors="ignore"))
