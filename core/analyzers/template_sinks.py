"""Template variables written out unescaped, as sinks for a copy of the Python XSS rule.

Jinja and Django escape what a template prints, except where it says not to: `{{ message|safe }}`, or anything inside
`{% autoescape false %}` / `{% autoescape off %}`. A view that passes request data as such a variable writes it into
the page as HTML: Whoogle (GHSA-mxvc-fwgx-j778) rendered render_template('error.html', error_message='Unable to
resolve query: ' + q) into `{{ error_message|safe }}`. The project's templates are read once per scan, and each
variable printed unescaped makes the argument that sets it, in a render_template / render / render_to_string /
TemplateResponse call naming that template, a sink of a copy of the XSS rule
(codewatch.python.web.template.xss). A value escaped or sanitized on the way
(`{{ text|sanitize_html|safe }}`, `{{ data|tojson|safe }}`) isn't one, and neither is a template no view names.

Flask's autoescape is chosen by extension: only .html, .htm, .xml, .xhtml and .svg are escaped, so a .jinja, .jinja2
or .j2 template prints every value raw. Those variables are sinks for Flask's render_template only; Django's Jinja
backend autoescapes them, so its render calls stay safe. Django also has .djhtml templates; they follow Django's
autoescaping and are not in the Flask-raw set.
"""
import re
from pathlib import PurePosixPath

TEMPLATE_EXTENSIONS = {".html", ".htm", ".jinja", ".jinja2", ".j2", ".djhtml"}
# Extensions Flask's select_jinja_autoescape leaves off (Flask 2.2+ also escapes .svg, which is not read here).
FLASK_RAW_EXTENSIONS = {".jinja", ".jinja2", ".j2"}
XSS_RULE = "codewatch.python.web.xss"
# {{ expression|filter|...|safe }}: the expression's first name, and the filters before safe.
SAFE_RE = re.compile(r"\{\{-?\s*([A-Za-z_]\w*)([^{}|]*(?:\|[^{}|]*)*?)\|\s*safe\s*-?\}\}")
PRINT_RE = re.compile(r"\{\{-?\s*([A-Za-z_]\w*)([^{}]*?)-?\}\}")
FOR_RE = re.compile(r"\{%-?\s*for\s+(\w+)(?:\s*,\s*\w+)*\s+in\s+([A-Za-z_]\w*)")
AUTOESCAPE_OFF_RE = re.compile(r"\{%-?\s*autoescape\s+(?:false|off)\s*-?%\}(.*?)\{%-?\s*endautoescape\s*-?%\}", re.DOTALL)
# Filters that leave text that can't carry markup: escaping, sanitizing, JSON, numbers and counts.
ESCAPING_FILTER_RE = re.compile(r"\|\s*(\w*(escape|saniti[sz]e|clean|bleach|json)\w*|e|striptags|int|float|length|count|"
                                r"urlencode|filesizeformat)\b", re.IGNORECASE)
ADMIN_ONLY = ("admins_only", "admin_required", "staff_member_required", "superuser_required")
KEYWORDS = {"loop", "super", "self", "caller", "varargs", "kwargs", "true", "false", "none", "True", "False", "None"}


def template_name(path):
    """The name a view gives a template: its path after the last templates/ folder, or its file name."""
    parts = PurePosixPath(path).parts
    if "templates" in parts:
        index = len(parts) - 1 - parts[::-1].index("templates")
        return "/".join(parts[index + 1:])
    return parts[-1]


def unescaped_variables(text, all_prints=False):
    """The context variables a template prints unescaped: the first name of each {{ ...|safe }} expression and of
    everything printed under autoescape off, with a loop variable traced back to the list it walks. all_prints also
    counts every other {{ ... }} a template prints (Flask's non-autoescaped extensions)."""
    loops = dict(FOR_RE.findall(text))
    printed = [(name, filters) for name, filters in SAFE_RE.findall(text)]
    for block in AUTOESCAPE_OFF_RE.findall(text):
        printed += PRINT_RE.findall(block)
    if all_prints:
        printed += PRINT_RE.findall(text)
    names = set()
    for printed_name, filters in printed:
        if ESCAPING_FILTER_RE.search(filters) or form_field(printed_name, filters.split("|")[0].strip()):
            continue
        name, seen = printed_name, set()
        while name in loops and name not in seen:
            seen.add(name)
            name = loops[name]
        if name not in KEYWORDS:
            names.add(name)
    return names


FORM_RE = re.compile(r"(?i)^(\w+_)?form$")
FORM_DATA = {".data", ".cleaned_data", ".initial"}


def form_field(name, rest):
    """{{ form|safe }} or {{ form.username|safe }}: a Django form or bound field renders its widgets and escapes the
    values in them itself, so |safe changes nothing (pygoat's login.html). Its data (form.cleaned_data.x) doesn't."""
    return bool(FORM_RE.match(name)) and (rest == "" or (re.fullmatch(r"\.\w+", rest) is not None
                                                        and rest not in FORM_DATA))


def unescaped_template_variables(templates):
    """({template name: {variable}} for variables printed with |safe/autoescape off,
    {template name: {variable}} for every variable in a Flask non-autoescaped extension)."""
    found, flask_raw = {}, {}
    for path, text in templates.items():
        names = unescaped_variables(text)
        if names:
            found.setdefault(template_name(path), set()).update(names)
        if PurePosixPath(path).suffix.lower() in FLASK_RAW_EXTENSIONS:
            names = unescaped_variables(text, all_prints=True)
            if names:
                flask_raw.setdefault(template_name(path), set()).update(names)
    return found, flask_raw


def quoted(text):
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


RENDERERS = {"render_template", "flask.render_template", "django.shortcuts.render",
             "django.template.loader.render_to_string", "django.template.response.TemplateResponse"}
TEMPLATE_RULE = "codewatch.python.web.template.xss"


def is_renderer(sanitizer):
    """The XSS rule's sanitizers for render calls (a template escapes what it prints). Semgrep reports no sink inside
    a sanitizer's match, so the rule for unescaped variables leaves them out."""
    return isinstance(sanitizer, dict) and sanitizer.get("pattern", "").removesuffix("(...)") in RENDERERS


def render_patterns(name, variable, django):
    """The render calls that set one template variable to $VALUE. django adds Django's renderers, which autoescape
    their Jinja backend; a Flask raw-extension variable belongs to render_template calls only."""
    template = quoted(name)
    patterns = [
        f"render_template({template}, ..., {variable}=$VALUE, ...)",
        f"flask.render_template({template}, ..., {variable}=$VALUE, ...)",
    ]
    if django:
        key = quoted(variable)
        patterns += [
            f"django.shortcuts.render($REQUEST, {template}, {{..., {key}: $VALUE, ...}}, ...)",
            f"django.template.loader.render_to_string({template}, {{..., {key}: $VALUE, ...}}, ...)",
            f"django.template.response.TemplateResponse($REQUEST, {template}, {{..., {key}: $VALUE, ...}}, ...)",
        ]
    return patterns


def template_sinks(found, flask_raw):
    """Semgrep sink patterns for the arguments that set found's unescaped variables, and for every variable in a
    Flask non-autoescaped template (those only for Flask's render_template calls)."""
    patterns = []
    for name, variables in sorted(found.items()):
        for variable in sorted(variables):
            patterns += render_patterns(name, variable, django=True)
    for name, variables in sorted(flask_raw.items()):
        for variable in sorted(variables):
            patterns += render_patterns(name, variable, django=False)
    patterns = list(dict.fromkeys(patterns))
    if not patterns:
        return None
    # An admin-only view's input is the administrator's own: CTFd's page preview renders the HTML an admin is
    # writing into {{ content|safe }}, as its pages are meant to.
    admin_only = [{"pattern-not-inside": f"@{name}\ndef $VIEW(...):\n  ...\n"} for name in ADMIN_ONLY]
    return {"patterns": [{"pattern-either": [{"pattern": p} for p in patterns]}, *admin_only,
                         {"focus-metavariable": "$VALUE"}]}


def with_template_sinks(rules, templates):
    """The rules, plus a copy of the XSS rule whose sinks are the arguments that set variables the project's
    templates print unescaped (none when no template does)."""
    sink = template_sinks(*unescaped_template_variables(templates))
    xss = next((rule for rule in rules if rule.get("id") == XSS_RULE), None)
    if sink is None or xss is None:
        return rules
    return [*rules, {
        **xss, "id": TEMPLATE_RULE,
        "message": "Data from the HTTP request is passed to a template variable the template prints unescaped "
                   "(|safe, autoescape off, or a Flask .jinja/.jinja2/.j2 template), so it's written into the page "
                   "as HTML. Escape or sanitize it, or drop |safe in the template.",
        "pattern-sanitizers": [s for s in xss.get("pattern-sanitizers", []) if not is_renderer(s)],
        "pattern-sinks": [sink]}]
