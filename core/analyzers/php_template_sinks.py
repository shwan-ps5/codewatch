"""PHP template variables printed unescaped, as sinks for a copy of the PHP XSS rule (codewatch.php.web.template.xss).

Twig, Blade and Latte escape what a template prints, except where it says not to: Twig's `{{ x|raw }}` and
`{% autoescape false %}` (or an Environment made with 'autoescape' => false, as OpenCart does), Blade's `{!! $x !!}`,
Latte's `{$x|noescape}`. Smarty escapes nothing unless the project turns escape_html on, so a `{$x}` without an
escaping modifier is raw. A plain PHP view (CakePHP's .ctp and templates/, CodeIgniter's and Laravel's non-Blade
views, any .phtml) prints `<?= $x ?>` raw unless the expression escapes it (h(), htmlspecialchars(), e(), esc_html()...).

The argument that sets such a variable is a sink: in a call naming the template (Twig's render/renderView/display,
Laravel's view()/View::make() and ->with(), CodeIgniter's load->view(), Latte's render, CakePHP's element()), or,
where the call doesn't name one (Smarty's assign(), CakePHP's $this->set(), Nette's $template->x = ...), by the
variable's name alone, against the templates of that kind. The finding's message names the template (or the
variable), so a fix made in the template can be matched to it (core/benchmark.py).
"""
import re
from pathlib import PurePosixPath

TEMPLATE_RULE = "codewatch.php.web.template.xss"
XSS_RULE = "codewatch.php.web.xss"
# Files read as templates: by extension, and PHP views by folder.
PHP_VIEW_DIR_RE = re.compile(r"(^|/)(views?|View|templates?|Template|Elements?|element|layouts?|Layout)/")
PHP_VIEW_SUFFIXES = (".php", ".ctp", ".phtml")
VAR_RE = re.compile(r"\$([A-Za-z_]\w*)")

# Twig: {{ name...|raw }} and everything under {% autoescape false %}.
# The name ends where the filters start, so the two parts can't trade characters; a block's contents can't hold another
# opener, so a file of unclosed tags is read once rather than once per tag.
TWIG_PRINT_RE = re.compile(r"\{\{-?\s*([A-Za-z_]\w*)(?!\w)([^{}]*?)-?\}\}")
TWIG_AUTOESCAPE_OFF_RE = re.compile(
    r"\{%-?\s*autoescape\s+false\s*-?%\}((?:(?!\{%-?\s*autoescape\b)[\s\S])*?)\{%-?\s*endautoescape\s*-?%\}")
TWIG_FOR_RE = re.compile(r"\{%-?\s*for\s+(\w+)(?:\s*,\s*\w+)?\s+in\s+([A-Za-z_]\w*)")
TWIG_KEYWORDS = {"loop", "app", "_self", "_context", "true", "false", "null", "not", "attribute", "include", "block",
                 "parent", "range", "constant", "dump", "source", "path", "url", "asset", "csrf_token", "form"}
TWIG_SAFE_FILTER_RE = re.compile(r"\|\s*(e|escape|striptags|length|abs|round|number_format|date|json_encode|"
                                 r"url_encode|trans|default\(\s*['\"][^'\"]*['\"]\s*\)\s*\|\s*e)\b")
TWIG_OFF_RE = re.compile(r"['\"]autoescape['\"]\s*=>\s*false")
# Blade: {!! $name ... !!}.
BLADE_RAW_RE = re.compile(r"\{!!((?:[^!{]|!(?!!\})|\{(?!!!))*)!!\}")
# Latte: {$name|noescape} and the old {!$name}.
LATTE_RAW_RE = re.compile(r"\{(?:!\s*(\$\w+)(?!\w)[^{}]*|(\$\w+)(?!\w)(?:[^{}|]|\|(?!\s*noescape))*\|\s*noescape[^{}]*)\}")
# Smarty: {$name|modifier...}, raw unless a modifier escapes or the project escapes by default.
SMARTY_PRINT_RE = re.compile(r"\{\$(\w+)(?!\w)([^{}]*)\}")
SMARTY_SAFE_RE = re.compile(r"\|\s*(escape|strip_tags|intval|floatval|count|date_format|string_format|"
                            r"number_format|urlencode|json_encode)\b|\bnofilter\b")
SMARTY_ESCAPE_ON_RE = re.compile(r"escape_html\s*=\s*true|setEscapeHtml\s*\(\s*true")
# A plain PHP view's printed expressions: <?= ... ?>, and echo/print statements anywhere in its PHP.
SHORT_ECHO_RE = re.compile(r"<\?=((?:[^?<]|\?(?!>)|<(?!\?=))*)\?>")
ECHO_RE = re.compile(r"\b(?:echo|print)\b")
PHP_FOREACH_RE = re.compile(r"foreach\s*\(\s*\$(\w+)\s+as\s+(?:\$\w+\s*=>\s*)?\$(\w+)")
# Calls whose result can't carry markup: escapers and encoders, numbers, booleans and counts.
ESCAPING_CALL_RE = re.compile(
    r"(?i)^(h|e|htmlspecialchars|htmlentities|esc_\w+|(?=\w*escape)\w+|strip_tags|intval|floatval|boolval|"
    r"count|sizeof|number_format|json_encode|urlencode|rawurlencode|date|strlen|mb_strlen|md5|sha1|base64_encode|"
    r"purify|wp_kses\w*|sanitize_\w+|filter_var|empty|isset|is_\w+|in_array|array_key_exists|\$this->.*)$")
CAST_RE = re.compile(r"\(\s*(int|integer|float|double|bool|boolean)\s*\)\s*$")
NAME_RE = re.compile(r"(?<![\w\\])(\$this(?:->\w+)+|[A-Za-z_\\][\w\\]*(?:::\w+)?)\s*$")


def string_end(text, i):
    """Index of the quote closing the string that opens at i (past the end if it is unclosed); backslashes escape."""
    quote, i = text[i], i + 1
    while i < len(text) and text[i] != quote:
        i += 2 if text[i] == "\\" else 1
    return i


def escaping_frame(expression, i):
    """Whether the bracket at i opens an escaping call (or a $this-> helper, which escapes by default)."""
    name = NAME_RE.search(expression[:i])
    return bool(name and ESCAPING_CALL_RE.match(name.group(1).replace(" ", "")))


def printed_in_string(expression, i, end, frames):
    """The variables a double-quoted string interpolates, when nothing around it escapes."""
    if expression[i] != '"' or any(frames):
        return set()
    return {v for v in VAR_RE.findall(expression[i + 1:end]) if v != "this"}


def printed_variable(expression, i, frames):
    """(the variable at i if it prints unescaped, else None; where scanning resumes)."""
    m = re.match(r"\$(\w+)", expression[i:])
    if not m:
        return None, i + 1
    name = m.group(1)
    printed = name != "this" and not any(frames) and not CAST_RE.search(expression[:i])
    return (name if printed else None), i + len(m.group(0))


def printed_variables(expression):
    """The variables an expression prints unescaped: each $name not inside an escaping call (or a $this-> helper,
    which escapes by default), nor cast to a number. Double-quoted strings print the variables they interpolate."""
    found, frames, i = set(), [], 0
    while i < len(expression):
        c = expression[i]
        if c in "'\"":
            end = string_end(expression, i)
            found |= printed_in_string(expression, i, end, frames)
            i = end + 1
            continue
        if c == "$":
            name, i = printed_variable(expression, i, frames)
            found |= {name} if name else set()
            continue
        if c == "(":
            frames.append(escaping_frame(expression, i))
        elif c == ")" and frames:
            frames.pop()
        i += 1
    return found


def statement_end(text, start):
    """Where the PHP statement beginning at start ends: its ; or ?> outside strings and brackets."""
    depth, i, n = 0, start, len(text)
    while i < n:
        c = text[i]
        if c in "'\"":
            i = string_end(text, i)
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth <= 0 and (c == ";" or text.startswith("?>", i)):
            return i
        i += 1
    return n


def printed_expressions(text):
    return ([m.group(1) for m in SHORT_ECHO_RE.finditer(text)]
            + [text[m.end():statement_end(text, m.end())] for m in ECHO_RE.finditer(text)])


TWIG, BLADE, LATTE, SMARTY, PHP = "twig", "blade", "latte", "smarty", "php"
KIND_SUFFIXES = ((".twig", TWIG), (".blade.php", BLADE), (".latte", LATTE))


def is_php_view(lower, path, text):
    """A .ctp or .phtml file, or a .php file in a view folder that leaves PHP mode and defines no class."""
    if lower.endswith((".ctp", ".phtml")):
        return True
    return (lower.endswith(".php") and bool(PHP_VIEW_DIR_RE.search(path)) and "?>" in text
            and not re.search(r"^[ \t]*(?:abstract\s+|final\s+)?class\s", text, re.MULTILINE))


def kind(path, text):
    """The template kind of a file: twig, blade, latte, smarty, php (a plain PHP view), or None."""
    lower = path.lower()
    if found := next((k for suffix, k in KIND_SUFFIXES if lower.endswith(suffix)), None):
        return found
    if lower.endswith(".tpl"):
        # OpenCart 2's and others' .tpl files are plain PHP.
        return PHP if ("<?php" in text or "<?=" in text) else SMARTY
    return PHP if is_php_view(lower, path, text) else None


def names(path, kind_):
    """The names a call can give this template: every tail of its path, with and without the extension, and for
    Blade and plain PHP views the dotted form (`admin.users.show`)."""
    stem = path
    for suffix in (".blade.php", ".html.twig", ".twig", ".latte", ".tpl", ".ctp", ".phtml", ".php"):
        if stem.lower().endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    parts = PurePosixPath(path).parts
    stem_parts = PurePosixPath(stem).parts
    found = set()
    for i in range(len(parts)):
        found.add("/".join(parts[i:]))
        found.add("/".join(stem_parts[i:]))
        if kind_ in (BLADE, PHP):
            found.add(".".join(stem_parts[i:]))
    return {n for n in found if n}


def followed(name, loops):
    """A loop variable traced back to the list it walks."""
    seen = set()
    while name in loops and name not in seen:
        seen.add(name)
        name = loops[name]
    return name


def twig_raw(text, all_raw):
    loops = dict(TWIG_FOR_RE.findall(text))
    printed = [(n, f) for n, f in TWIG_PRINT_RE.findall(text) if all_raw or re.search(r"\|\s*raw\b", f)]
    for block in TWIG_AUTOESCAPE_OFF_RE.findall(text):
        printed += TWIG_PRINT_RE.findall(block)
    raw = set()
    for name, filters in printed:
        before_raw = re.split(r"\|\s*raw\b", filters)[0]
        if TWIG_SAFE_FILTER_RE.search(before_raw):
            continue
        if (traced := followed(name, loops)) not in TWIG_KEYWORDS:
            raw.add(traced)
    return raw


def php_raw(text):
    """Variables a PHP view prints unescaped. One the view assigns itself is its own, not what the controller
    passed (MISP's populate_event_from_template.ctp rebuilds $fileArray, escaped, before printing it)."""
    loops = {item: items for items, item in PHP_FOREACH_RE.findall(text)}
    own = set(re.findall(r"\$(\w+)\s*(?:\[[^\][]*\]\s*)*=(?!=|>)", text))
    raw = set()
    for expression in printed_expressions(text):
        raw.update(followed(name, loops) for name in printed_variables(expression))
    return {name for name in raw if name not in own}


def smarty_raw(text, escapes_by_default):
    return {name for name, rest in SMARTY_PRINT_RE.findall(text)
            if not SMARTY_SAFE_RE.search(rest) and (not escapes_by_default or "nofilter" in rest)}


RAW_VARIABLES = {
    TWIG: lambda text, settings: twig_raw(text, settings["twig_off"]),
    BLADE: lambda text, _settings: {v for expression in BLADE_RAW_RE.findall(text)
                                    for v in printed_variables(expression.strip())},
    LATTE: lambda text, _settings: {(a or b).lstrip("$") for a, b in LATTE_RAW_RE.findall(text)},
    SMARTY: lambda text, settings: smarty_raw(text, settings["smarty_escapes"]),
    PHP: lambda text, _settings: php_raw(text),
}


def raw_variables(text, kind_, settings):
    return RAW_VARIABLES[kind_](text, settings) if kind_ in RAW_VARIABLES else set()


def unescaped(templates, php_texts=()):
    """{kind: {variable: {template path}}} for the project's templates."""
    joined = "\n".join(php_texts)
    settings = {"twig_off": bool(TWIG_OFF_RE.search(joined)), "smarty_escapes": bool(SMARTY_ESCAPE_ON_RE.search(joined))}
    found = {}
    for path, text in templates.items():
        kind_ = kind(path, text)
        if kind_ is None:
            continue
        for variable in raw_variables(text, kind_, settings):
            found.setdefault(kind_, {}).setdefault(variable, set()).add(path)
    return found


def alternation(values):
    return "|".join(re.escape(v) for v in sorted(values))


def filled_array(patterns):
    """The same calls given an array filled entry by entry in the function that renders it: `$data['redirect'] =
    ...;` (in an if or not) and then `$this->load->view('common/login', $data)` (OpenCart, CodeIgniter), or `return
    view('x', $data)`."""
    calls = [p.replace(ARRAY, "$DATA") for p in patterns if ARRAY in p]
    return [{"patterns": [{"pattern-inside": f"function $F(...) {{\n  ...\n  {form}\n  ...\n}}"},
                          {"pattern": "$DATA[$KEY] = $VALUE"}]}
            for call in calls for form in (f"<... {call} ...>;", f"return <... {call} ...>;")]


def named_sink(patterns, name_regex, variable):
    return {"patterns": [{"pattern-either": [*({"pattern": p} for p in patterns), *filled_array(patterns)]},
                         {"metavariable-regex": {"metavariable": "$NAME", "regex": f"^['\"]({name_regex})['\"]$"}},
                         {"metavariable-regex": {"metavariable": "$KEY", "regex": f"^['\"]{re.escape(variable)}['\"]$"}},
                         FOCUS_VALUE]}


def unnamed_sink(patterns, variable):
    return {"patterns": [{"pattern-either": [{"pattern": p} for p in patterns]},
                         {"metavariable-regex": {"metavariable": "$KEY", "regex": f"^['\"]{re.escape(variable)}['\"]$"}},
                         FOCUS_VALUE]}


ARRAY = "[..., $KEY => $VALUE, ...]"
FOCUS_VALUE = {"focus-metavariable": "$VALUE"}
# Calls that name the template they render. Every engine's list is the same: the name has to be one of that kind's
# templates, so OpenCart's Twig through $this->load->view() and CodeIgniter's PHP views through view() both match.
NAMED_CALLS = [f"$T->render($NAME, {ARRAY}, ...)", f"$T->renderView($NAME, {ARRAY}, ...)",
               f"$T->display($NAME, {ARRAY}, ...)", f"$T->load($NAME)->render({ARRAY}, ...)",
               f"$T->renderResponse($NAME, {ARRAY}, ...)", f"$T->renderToString($NAME, {ARRAY}, ...)",
               f"$T->fetch($NAME, {ARRAY}, ...)", f"$T->load->view($NAME, {ARRAY}, ...)",
               f"$T->element($NAME, {ARRAY}, ...)", f"$T->partial($NAME, {ARRAY}, ...)",
               f"view($NAME, {ARRAY}, ...)", f"View::make($NAME, {ARRAY}, ...)",
               "view($NAME, ...)->with($KEY, $VALUE)", f"view($NAME, ...)->with({ARRAY})",
               "View::make($NAME, ...)->with($KEY, $VALUE)"]
NAMED = dict.fromkeys((TWIG, BLADE, LATTE, PHP), NAMED_CALLS)
UNNAMED = {
    SMARTY: ["$S->assign($KEY, $VALUE, ...)", f"$S->assign({ARRAY})", "$S->assignByRef($KEY, $VALUE)",
               "$S->assign_by_ref($KEY, $VALUE)"],
    # A CakePHP component's view variables, for whichever view its controller renders. A controller's own
    # $this->set() is matched to its action's view (cake_sinks).
    PHP: ["$this->Controller->set($KEY, $VALUE)", "$this->controller->set($KEY, $VALUE)",
            f"$this->Controller->set({ARRAY})", f"$this->controller->set({ARRAY})"],
    LATTE: ["$this->template->$KEY = $VALUE;", "$template->$KEY = $VALUE;"],
}


def latte_sink(patterns, variable):
    """A Latte property assignment: $KEY binds the bare identifier, not a string."""
    return {"patterns": [{"pattern-either": [{"pattern": p} for p in patterns]},
                         {"metavariable-regex": {"metavariable": "$KEY", "regex": f"^{re.escape(variable)}$"}},
                         FOCUS_VALUE]}


def variable_sinks(kind_, variable, paths):
    """The sinks for one template variable of one kind: calls that name its templates, and calls that don't."""
    sinks = []
    if kind_ in NAMED:
        tails = set().union(*(names(path, kind_) for path in paths))
        sinks.append(named_sink(NAMED[kind_], alternation(tails), variable))
    if kind_ in UNNAMED:
        build = latte_sink if kind_ == LATTE else unnamed_sink
        sinks.append(build(UNNAMED[kind_], variable))
    return sinks


def template_sinks(found):
    return [sink for kind_, variables in sorted(found.items())
            for variable, paths in sorted(variables.items()) for sink in variable_sinks(kind_, variable, paths)]


# CakePHP: a controller action renders View/<Controller>/<action>.ctp (2.x) or templates/<Controller>/<action>.php
# (3.x and later), its name underscored, unless it calls $this->render('other'); a view's elements print too.
CAKE_VIEW_RE = re.compile(r"(?:^|/)(?:View|templates)/(?!Elements?/|element/|Layouts?/|layout/|email/|Emails/)"
                          r"([A-Z]\w*)/(\w+)\.(?:ctp|php)$")
CAKE_ELEMENT_DIR_RE = re.compile(r"(?:^|/)(?:View/Elements|templates/element)/")
CONTROLLER_RE = re.compile(r"\bclass\s+(\w+)Controller\s+extends\s+\w+")
FUNCTION_RE = re.compile(r"\bfunction\s+(\w+)\s*\(")
RENDER_RE = re.compile(r"\$this->render\(\s*['\"]/?([\w/]+)['\"]")
ELEMENT_CALL_RE = re.compile(r"\$this->element\(\s*['\"]([\w/]+)['\"]")


def squashed(name):
    """CakePHP's view file for an action is its name underscored: viewAll -> view_all."""
    return name.replace("_", "").lower()


def cake_element(path):
    """The element name of a CakePHP element file (View/Elements/a/b.ctp -> a/b), or None."""
    found = CAKE_ELEMENT_DIR_RE.search(path)
    name = path[found.end():] if found else ""
    return name[:-4] if name.endswith((".ctp", ".php")) and len(name) > 4 else None


def cake_views(templates):
    """{(controller, squashed view name): variables the view, or an element it includes, prints unescaped}."""
    elements = {name: text for path, text in templates.items() if (name := cake_element(path))}
    views = {}
    for path, text in templates.items():
        if not (m := CAKE_VIEW_RE.search(path)):
            continue
        raw = php_raw(text)
        for name in ELEMENT_CALL_RE.findall(text):
            if name in elements:
                raw |= php_raw(elements[name])
        views.setdefault((m.group(1).lower(), squashed(m.group(2))), set()).update(raw)
    return views


def render_keys(controller, action, body):
    """The (controller, squashed view) pairs an action can render: its own view and each $this->render() target."""
    keys = {(controller.lower(), squashed(action))}
    for name in RENDER_RE.findall(body):
        parts = name.split("/")
        keys.add((parts[-2].lower(), squashed(parts[-1])) if len(parts) > 1 else (controller.lower(), squashed(name)))
    return keys


def controller_actions(controller, text, views):
    """{variable: {actions whose view prints it unescaped}} for one controller's source."""
    starts = [(m.start(), m.group(1)) for m in FUNCTION_RE.finditer(text)]
    ends = [start for start, _ in starts[1:]] + [len(text)]
    actions = {}
    for (start, action), end in zip(starts, ends, strict=True):
        keys = render_keys(controller, action, text[start:end])
        for variable in set().union(*(views.get(key, set()) for key in keys)):
            actions.setdefault(variable, set()).add(action)
    return actions


def cake_sink(controller, variable, actions):
    return {"patterns": [
        {"pattern-inside": "class $CLASS extends $PARENT { ... }"},
        {"metavariable-regex": {"metavariable": "$CLASS", "regex": f"^{re.escape(controller)}Controller$"}},
        {"pattern-inside": "function $ACTION(...) { ... }"},
        {"metavariable-regex": {"metavariable": "$ACTION", "regex": f"^({alternation(actions)})$"}},
        {"pattern-either": [{"pattern": "$this->set($KEY, $VALUE)"}, {"pattern": f"$this->set({ARRAY})"}]},
        {"metavariable-regex": {"metavariable": "$KEY", "regex": f"^['\"]{re.escape(variable)}['\"]$"}},
        FOCUS_VALUE]}


def cake_sinks(templates):
    """A controller's $this->set() of a variable its action's view prints unescaped."""
    views = cake_views(templates)
    if not views:
        return []
    sinks = []
    for path, text in sorted(templates.items()):
        if path.endswith(".php") and (match := CONTROLLER_RE.search(text)):
            actions = controller_actions(match.group(1), text, views)
            sinks += [cake_sink(match.group(1), variable, names_) for variable, names_ in sorted(actions.items())]
    return sinks


MESSAGE = ("Data from the HTTP request is passed to the template variable $KEY, which a template (template $NAME) "
           "prints unescaped (Twig |raw, Blade {!! !!}, Latte |noescape, Smarty without |escape, or a PHP view's "
           "echo), so it's written into the page as HTML. Escape it here or in the template.")
UNNAMED_TEMPLATE = " (template $NAME)"


def tidy_message(message):
    """A call that doesn't name its template (Smarty's assign(), CakePHP's set()) leaves $NAME unfilled."""
    return message.replace(UNNAMED_TEMPLATE, "")


def with_php_template_sinks(rules, templates, php_texts=()):
    """The rules, plus a copy of the PHP XSS rule whose sinks are the arguments that set variables the project's
    templates print unescaped (none when no template does). templates: {path: text} of the candidate files;
    php_texts: the project's PHP, read for Twig's and Smarty's escaping settings."""
    xss = next((rule for rule in rules if rule.get("id") == XSS_RULE), None)
    if xss is None:
        return rules
    sinks = template_sinks(unescaped(templates, php_texts)) + cake_sinks(templates)
    if not sinks:
        return rules
    return [*rules, {
        **xss, "id": TEMPLATE_RULE,
        "message": MESSAGE,
        "pattern-sinks": sinks}]
