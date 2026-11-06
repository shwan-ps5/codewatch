"""Django model fields the project fills from request data, read back as XSS sources (stored XSS).

A request value saved in one view and printed by another isn't a flow Semgrep can follow: the database is between
them. Making every database read a source would flag every page; matching fields by name alone is too coarse
(PLAN.md step 43: calibre-web writes `shelf.name` from requests, which says nothing about `author.name`). So this
works per model. It reads the project with ast for:

- each model's text fields: CharField, TextField, file and similar fields without `choices=` (a number, a date, a
  foreign key or a fixed choice can't carry markup);
- the fields of each model the project writes from request data: `Model.objects.create(field=...)` or
  `Model(field=...)` with a value taken from the request, `obj.field = ...` on an object made or looked up from
  that model, and the fields of a ModelForm or DRF ModelSerializer for it (both save what the client sent);

and adds, to the XSS rule only, a source for reads of those fields where the model is known: `obj.field` in the
methods of a ModelAdmin registered for the model, `self.field` in the model's own methods, and `x.field` after
`x = Model.objects...(...)` or `x = get_object_or_404(Model, ...)`. A field the project never writes from a
request stays out, so its unescaped output is left to the hotspot rules.
"""
import ast
import re

RULE = "codewatch.python.web.xss"
TEXT_FIELDS = {"CharField", "TextField", "EmailField", "URLField", "SlugField", "FileField", "ImageField",
               "FilePathField", "JSONField", "GenericIPAddressField"}
MODEL_BASE_RE = re.compile(r"Model$")
FORM_BASE_RE = re.compile(r"^(ModelForm|ModelSerializer|HyperlinkedModelSerializer)$")
REQUEST_NAMES = {"request", "req"}
# A file field's .url is the storage's URL for the stored name, percent-encoded (Django's filepath_to_uri), so it
# can't break out of an HTML attribute: mark_safe(f'<img src="{self.image.url}">').
FILE_FIELDS = {"FileField", "ImageField"}


def last_name(node):
    """`models.Model` -> Model, `forms.ModelForm[X]` -> ModelForm, `Foo` -> Foo."""
    if isinstance(node, ast.Subscript):
        node = node.value
    if isinstance(node, ast.Attribute):
        return node.attr
    return getattr(node, "id", "")


def text_fields(cls, kinds=TEXT_FIELDS):
    """Names of a model class's text fields (or fields of the given kinds) without fixed choices."""
    found = set()
    for item in cls.body:
        if not (isinstance(item, ast.Assign) and len(item.targets) == 1 and isinstance(item.targets[0], ast.Name)
                and isinstance(item.value, ast.Call)):
            continue
        if last_name(item.value.func) in kinds and not any(k.arg == "choices" for k in item.value.keywords):
            found.add(item.targets[0].id)
    return found


def is_signed_in_user(node):
    """request.user / self.request.user: the account the server signed in, not what the client sent."""
    return (isinstance(node, ast.Attribute) and node.attr == "user"
            and (getattr(node.value, "id", "") in REQUEST_NAMES
                 or (isinstance(node.value, ast.Attribute) and node.value.attr == "request")))


def mentions(node, names, returners=frozenset()):
    """Whether node reads the request (request.x, self.request.x), one of names, or calls a project function
    that hands request data back (returners) with request data."""
    if is_signed_in_user(node):
        return False
    if isinstance(node, ast.Name):
        return node.id in REQUEST_NAMES or node.id in names
    if isinstance(node, ast.Attribute) and node.attr == "request" and getattr(node.value, "id", "") == "self":
        return True
    if isinstance(node, ast.Call) and last_name(node.func) in returners and any(
            mentions(a, names, returners) for a in [*node.args, *(k.value for k in node.keywords)]):
        return True
    return any(mentions(child, names, returners) for child in ast.iter_child_nodes(node))


def model_of(call, models):
    """The model a call makes or looks up: Model(...), Model.objects.x(...)..., get_object_or_404(Model, ...)."""
    if not isinstance(call, ast.Call):
        return None
    func = call.func
    if isinstance(func, ast.Name) and func.id in models:
        return func.id
    if last_name(func) in ("get_object_or_404", "get_list_or_404") and call.args:
        return last_name(call.args[0]) if last_name(call.args[0]) in models else None
    node = func
    while isinstance(node, (ast.Attribute, ast.Call)):
        node = node.func if isinstance(node, ast.Call) else node.value
        if isinstance(node, ast.Attribute) and node.attr == "objects" and last_name(node.value) in models:
            return last_name(node.value)
    return None


def function_flow(func, models, seeded=(), returners=frozenset()):
    """What a function does with request data: ({(model, field)} it fills, {name: tainted argument positions and
    keywords} for the project functions it calls, whether it returns request data). seeded: its parameters that
    callers fill with request data."""
    tainted, objects, writes, calls = set(seeded), {}, set(), {}
    for node in ast.walk(func):
        if isinstance(node, ast.For) and mentions(node.iter, tainted, returners):
            tainted.update(n.id for n in ast.walk(node.target) if isinstance(n, ast.Name))
    # Assignments in source order, so a value read from the request earlier taints what it's copied into.
    for node in sorted((n for n in ast.walk(func) if isinstance(n, (ast.Assign, ast.AnnAssign, ast.Expr))),
                       key=lambda n: (n.lineno, n.col_offset)):
        value = node.value
        targets = node.targets if isinstance(node, ast.Assign) else [getattr(node, "target", None)]
        if value is None:
            continue
        for call in (n for n in ast.walk(value) if isinstance(n, ast.Call)):
            if (model := model_of(call, models)) is not None:
                writes.update((model, k.arg) for k in call.keywords
                              if k.arg and mentions(k.value, tainted, returners))
        for target in filter(None, targets):
            if isinstance(target, ast.Name):
                if (model := model_of(value, models)) is not None:
                    objects[target.id] = model
                elif mentions(value, tainted, returners):
                    tainted.add(target.id)
            elif isinstance(target, ast.Tuple):
                if mentions(value, tainted, returners):
                    tainted.update(n.id for n in ast.walk(target) if isinstance(n, ast.Name))
            elif (isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
                    and target.value.id in objects and mentions(value, tainted, returners)):
                writes.add((objects[target.value.id], target.attr))
    for call in (n for n in ast.walk(func) if isinstance(n, ast.Call)):
        hit = {i for i, a in enumerate(call.args) if mentions(a, tainted, returners)}
        hit |= {k.arg for k in call.keywords if k.arg and mentions(k.value, tainted, returners)}
        if hit:
            calls.setdefault(last_name(call.func), set()).update(hit)
    returns = any(isinstance(n, ast.Return) and n.value is not None and mentions(n.value, tainted, returners)
                  for n in ast.walk(func))
    return writes, calls, returns


def parameters(func):
    """{position or name: parameter name}, positions counted as a caller passes them (self/cls skipped)."""
    names = [a.arg for a in [*func.args.posonlyargs, *func.args.args]]
    if names and names[0] in ("self", "cls"):
        names = names[1:]
    out = dict(enumerate(names))
    out.update({n: n for n in names + [a.arg for a in func.args.kwonlyargs]})
    return out


def project_writes(functions, models):
    """{(model, field)} the project fills from request data, following request data into the parameters of the
    project's functions and back out of their returns. Only names defined once in the project are followed, so
    two save() methods don't mix."""
    by_name = {}
    for func in functions:
        by_name.setdefault(func.name, []).append(func)
    unique = {name: funcs[0] for name, funcs in by_name.items() if len(funcs) == 1}
    seeded, returners = {}, set()
    for _ in range(6):
        changed, writes = False, set()
        for func in functions:
            found, calls, returns = function_flow(func, models, seeded.get(id(func), ()), frozenset(returners))
            writes |= found
            if returns and func.name in unique and func.name not in returners:
                returners.add(func.name)
                changed = True
            for name, hit in calls.items():
                if name not in unique:
                    continue
                callee = unique[name]
                params = parameters(callee)
                new = {params[h] for h in hit if h in params} - seeded.get(id(callee), set())
                if new:
                    seeded.setdefault(id(callee), set()).update(new)
                    changed = True
        if not changed:
            break
    return writes


def form_fields(cls, models):
    """{(model, field)} a ModelForm or ModelSerializer saves: its Meta.fields ('__all__' is every field)."""
    meta = next((i for i in cls.body if isinstance(i, ast.ClassDef) and i.name == "Meta"), None)
    if meta is None:
        return set()
    values = {t.id: i.value for i in meta.body if isinstance(i, ast.Assign) for t in i.targets
              if isinstance(t, ast.Name)}
    model = last_name(values.get("model")) if "model" in values else None
    if model not in models:
        return set()
    fields = values.get("fields")
    if isinstance(fields, ast.Constant) and fields.value == "__all__":
        names = set(models[model])
    elif isinstance(fields, (ast.List, ast.Tuple)):
        names = {e.value for e in fields.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    else:
        return set()
    excluded = values.get("exclude")
    if isinstance(excluded, (ast.List, ast.Tuple)):
        names -= {e.value for e in excluded.elts if isinstance(e, ast.Constant)}
    return {(model, name) for name in names}


def admin_models(tree, models):
    """{admin class name: model} from @admin.register(Model) and admin.site.register(Model, AdminClass)."""
    found = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and last_name(dec.func) == "register":
                    for arg in dec.args:
                        if last_name(arg) in models:
                            found[node.name] = last_name(arg)
        elif (isinstance(node, ast.Call) and last_name(node.func) == "register" and len(node.args) >= 2
                and last_name(node.args[0]) in models):
            found[last_name(node.args[1])] = last_name(node.args[0])
    return found


def parse_all(texts):
    trees = []
    for text in texts:
        try:
            trees.append(ast.parse(text))
        except (SyntaxError, ValueError):
            continue
    return trees


def stored_fields(texts):
    """({model: request-written text fields}, {admin class: model}, {model: its file fields}) for the project's
    Python sources."""
    trees = parse_all(texts)
    models, files = {}, {}
    for tree in trees:
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and any(MODEL_BASE_RE.search(last_name(b)) for b in node.bases) \
                    and not any(FORM_BASE_RE.search(last_name(b)) for b in node.bases):
                models.setdefault(node.name, set()).update(text_fields(node))
                files.setdefault(node.name, set()).update(text_fields(node, FILE_FIELDS))
    models = {m: f for m, f in models.items() if f}
    if not models:
        return {}, {}, {}
    writes, admins, functions = set(), {}, []
    for tree in trees:
        admins.update(admin_models(tree, models))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append(node)
            elif isinstance(node, ast.ClassDef) and any(FORM_BASE_RE.search(last_name(b)) for b in node.bases):
                writes |= form_fields(node, models)
    writes |= project_writes(functions, models)
    stored = {}
    for model, field in writes:
        if field in models.get(model, ()):
            stored.setdefault(model, set()).add(field)
    return (stored, {a: m for a, m in admins.items() if m in stored},
            {m: f & stored[m] for m, f in files.items() if m in stored and f & stored[m]})


def field_regex(fields):
    return "^(" + "|".join(sorted(map(re.escape, fields))) + ")$"


def sources(stored, admins):
    out = []
    for admin, model in sorted(admins.items()):
        out.append({"patterns": [
            {"pattern-inside": f"class {admin}(...):\n  ...\n"},
            {"pattern-inside": "def $F(self, $OBJ, ...):\n  ...\n"},
            {"pattern": "$OBJ.$FIELD"},
            {"metavariable-regex": {"metavariable": "$FIELD", "regex": field_regex(stored[model])}},
        ]})
    for model, fields in sorted(stored.items()):
        out.append({"patterns": [
            {"pattern-inside": f"class {model}(...):\n  ...\n"},
            {"pattern": "self.$FIELD"},
            {"metavariable-regex": {"metavariable": "$FIELD", "regex": field_regex(fields)}},
        ]})
        out.append({"patterns": [
            {"pattern-either": [
                {"pattern-inside": f"$X = {model}.objects.$Q(...)\n...\n"},
                {"pattern-inside": f"$X = {model}.objects.$Q(...).$R(...)\n...\n"},
                {"pattern-inside": f"$X = get_object_or_404({model}, ...)\n...\n"},
                {"pattern-inside": f"for $X in {model}.objects.$Q(...):\n  ...\n"},
                {"pattern-inside": f"for $X in {model}.objects.$Q(...).$R(...):\n  ...\n"},
            ]},
            {"pattern": "$X.$FIELD"},
            {"metavariable-regex": {"metavariable": "$FIELD", "regex": field_regex(fields)}},
        ]})
    return out


def with_stored_sources(rules, texts):
    """The rules, with sources for request-written model fields on the Python XSS rule."""
    stored, admins, files = stored_fields(texts)
    if not stored:
        return rules
    extra = sources(stored, admins)
    names = set().union(*files.values()) if files else set()
    url = [{"patterns": [{"pattern": "$X.$FIELD.url"},
                         {"metavariable-regex": {"metavariable": "$FIELD", "regex": field_regex(names)}}]}] if names else []
    return [{**rule, "pattern-sources": [*rule["pattern-sources"], *extra],
             "pattern-sanitizers": [*rule.get("pattern-sanitizers", []), *url]} if rule.get("id") == RULE else rule
            for rule in rules]
