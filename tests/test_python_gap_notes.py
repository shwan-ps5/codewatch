"""Python rule gaps found by the gap notes (AGENTS.md section 9; PLAN.md step 128): each test is a note's probe,
cut to its shape, with a safe look-alike."""
import pytest

from core.analyzers.multi_tools import Semgrep
from tests.test_detection import semgrep_vulnerabilities

semgrep = pytest.mark.skipif(not Semgrep().available(), reason="semgrep not installed")


@semgrep
def test_a_failed_membership_or_equality_check_does_not_clear_the_value(tmp_path):
    """nextcloud-mcp-server's note: `if preset_id not in PRESETS: return HTMLResponse(f"Unknown preset: {preset_id}")`.
    The allowlist guard cleared the value everywhere below the `if`, the branch where the check said no included;
    so did `if name != "index.html"`. Still clear: after that branch returned, and in its else."""
    found = semgrep_vulnerabilities(tmp_path, {"app/views.py": (
        "from flask import Flask, abort\n"
        "from markupsafe import Markup\n\n"
        "app = Flask(__name__)\n"
        "PRESETS = ('alpha', 'beta')\n\n\n"
        "@app.route('/a/<preset>')\n"
        "def a(preset):\n"
        "    if preset not in PRESETS:\n"
        "        return Markup(f'<div>Unknown preset: {preset}</div>')\n"
        "    return 'ok'\n\n\n"
        "@app.route('/b/<preset>')\n"
        "def b(preset):\n"
        "    if preset not in PRESETS:\n"
        "        return 'unknown'\n"
        "    return Markup(f'<div>{preset}</div>')\n\n\n"
        "@app.route('/c/<preset>')\n"
        "def c(preset):\n"
        "    if not preset in PRESETS:\n"
        "        abort(404)\n"
        "        return Markup(f'<div>Unknown: {preset}</div>')\n"
        "    else:\n"
        "        return Markup(f'<div>{preset}</div>')\n\n\n"
        "@app.route('/d/<name>')\n"
        "def d(name):\n"
        "    if name != 'index.html':\n"
        "        return Markup(f'<div>No page {name}</div>')\n"
        "    return Markup(f'<div>{name}</div>')\n")})
    assert found == {("app/views.py", 11, "xss"), ("app/views.py", 26, "xss"), ("app/views.py", 34, "xss")}


@semgrep
def test_cloudpickle_loads_is_unsafe_deserialization(tmp_path):
    """fugue's RPC server (GHSA-xv5p-fjw5-vrj6): cloudpickle.loads(base64.b64decode(request.form value)).
    cloudpickle unpickles as pickle does. json.loads of the same value is fine."""
    found = semgrep_vulnerabilities(tmp_path, {"app/rpc.py": (
        "import base64\nimport json\n\n"
        "import cloudpickle\n"
        "from flask import Flask, request\n\n"
        "app = Flask(__name__)\n\n\n"
        "@app.post('/invoke')\n"
        "def invoke():\n"
        "    payload = str(request.form.get('value'))\n"
        "    args = cloudpickle.loads(base64.b64decode(payload.encode('ascii')))\n"
        "    kwargs = json.loads(base64.b64decode(payload))\n"
        "    return str((args, kwargs))\n")})
    assert found == {("app/rpc.py", 13, "unsafe-deserialization")}


@semgrep
def test_django_shortcuts_redirect_through_its_module(tmp_path):
    """Horizon (GHSA-j72v-mpwp-rg79): `from django import shortcuts` then shortcuts.redirect(redirect_to), with
    redirect_to from the request. A fixed target isn't flagged."""
    found = semgrep_vulnerabilities(tmp_path, {"app/views.py": (
        "from django import shortcuts\n"
        "from django.views import View\n\n\n"
        "class LoginView(View):\n"
        "    def post(self, request):\n"
        "        redirect_to = request.POST.get('next', '')\n"
        "        if not redirect_to:\n"
        "            return shortcuts.redirect('/')\n"
        "        return shortcuts.redirect(redirect_to or '/')\n")})
    assert found == {("app/views.py", 10, "open-redirect")}


@semgrep
def test_frappe_request_input_reaches_frappe_db_sql(tmp_path):
    """Frappe (CVE-2026-55823, CVE-2026-55796): frappe.form_dict and the arguments of a @frappe.whitelist() method
    come from the request, and frappe.db.sql runs its string as given, here through a helper that formats a filter
    into SQL. Not: values bound as parameters, int-annotated arguments (Frappe converts them), or a function that
    isn't whitelisted."""
    found = semgrep_vulnerabilities(tmp_path, {"app/api.py": (
        "import frappe\n\n\n"
        "def get_conditions(filters):\n"
        "    return \"and department = '%s'\" % filters['department']\n\n\n"
        "@frappe.whitelist()\n"
        "def report():\n"
        "    filters = frappe.form_dict\n"
        "    query = 'select name from `tabSalary Slip` where docstatus = 1 %s' % get_conditions(filters)\n"
        "    return frappe.db.sql(query, as_dict=1)\n\n\n"
        "@frappe.whitelist(allow_guest=True)\n"
        "def by_name(name, limit: int = 10, doctype: str = 'User'):\n"
        "    a = frappe.db.sql(f\"select * from `tab{doctype}` where name = '{name}'\")\n"
        "    b = frappe.db.sql(f'select * from tabUser limit {limit}')\n"
        "    c = frappe.db.sql('select * from tabUser where name = %s', (name,))\n"
        "    return a, b, c\n\n\n"
        "def not_exposed(name):\n"
        "    return frappe.db.sql(f\"select * from tabUser where name = '{name}'\")\n")})
    assert found == {("app/api.py", 12, "sql-injection"), ("app/api.py", 17, "sql-injection")}


@semgrep
def test_a_frappe_reports_filters_reach_sql_through_get_conditions(tmp_path):
    """HRMS (CVE-2026-55796): a script report's execute(filters) gets the report page's filters, and
    get_conditions(filters) formats them into SQL. A get_* helper otherwise counts as a lookup that returns a stored
    row, not the value; one named for conditions, filters, where or clauses builds the query from it. Not: a module
    that doesn't import frappe, or the filters passed as bound values."""
    report = (
        "def execute(filters=None):\n"
        "    return [], get_data(filters)\n\n\n"
        "def get_conditions(filters):\n"
        "    return \" and department = '%s'\" % filters['department']\n\n\n"
        "def get_data(filters):\n"
        "    conditions = get_conditions(filters)\n"
        "    safe = frappe.db.sql('select name from tabEmployee where department = %(department)s', filters)\n"
        "    return frappe.db.sql('select name from tabEmployee where docstatus = 1 %s' % (conditions)), safe\n")
    found = semgrep_vulnerabilities(tmp_path, {"report/a.py": "import frappe\n\n\n" + report,
                                               "other/b.py": "from app import frappe\n\n\n" + report})
    assert found == {("report/a.py", 5, "sql-injection")}


@semgrep
def test_djangos_same_origin_check_clears_a_redirect_it_replaced(tmp_path):
    """Horizon's fix (GHSA-j72v-mpwp-rg79): `if redirect_to and not same_origin(build_absolute_uri(redirect_to),
    build_absolute_uri()): redirect_to = None`. The value redirected to afterwards is the checked one or None."""
    found = semgrep_vulnerabilities(tmp_path, {"app/views.py": (
        "from django import shortcuts\n"
        "from django.utils.http import same_origin\n"
        "from django.views import View\n\n\n"
        "class Login(View):\n"
        "    def post(self, request):\n"
        "        redirect_to = request.POST.get('next')\n"
        "        if redirect_to and not same_origin(request.build_absolute_uri(redirect_to),\n"
        "                                           request.build_absolute_uri()):\n"
        "            redirect_to = None\n"
        "        return shortcuts.redirect(redirect_to or '/')\n\n\n"
        "class Unchecked(View):\n"
        "    def post(self, request):\n"
        "        redirect_to = request.POST.get('next')\n"
        "        same_origin(request.build_absolute_uri(redirect_to), request.build_absolute_uri())\n"
        "        return shortcuts.redirect(redirect_to or '/')\n")})
    assert found == {("app/views.py", 19, "open-redirect")}


@semgrep
def test_a_path_a_helper_returns_is_a_file_path_when_used(tmp_path):
    """Checkmk 31dfe9231eee: `_file_path()` joins the request's file_id to the upload directory and returns it, and
    `self._file_path().open()` and `.unlink()` use it; also `path = file_path(file_id); path.write_text(...)`.
    Not: the helper after the fix (isalnum() or raise), a fixed uuid name, a helper not named for a path,
    str.replace() on a returned display path, or a query's exists() with a path helper in its filter (label-studio)."""
    found = semgrep_vulnerabilities(tmp_path, {"app/views.py": (
        "import uuid\n"
        "from pathlib import Path\n\n"
        "from flask import Flask, request\n\n"
        "app = Flask(__name__)\n"
        "TMP = Path('/tmp/host-import')\n\n\n"
        "def file_path(file_id):\n"
        "    return TMP / ('%s.csv' % file_id)\n\n\n"
        "@app.post('/import')\n"
        "def upload():\n"
        "    path = file_path(request.form['file_id'])\n"
        "    path.write_text(request.form['csv'])\n"
        "    shown = get_display_path(request.form['file_id']).replace('/', ' > ')\n"
        "    return {'ok': True, 'shown': shown}\n\n\n"
        "def get_display_path(name):\n"
        "    return '/files/' + name\n\n\n"
        "class BulkImport:\n"
        "    _upload_tmp_path = Path('/tmp/upload')\n\n"
        "    def _file_path(self):\n"
        "        file_id = request.args.get('file_id', 'x')\n"
        "        return self._upload_tmp_path / ('%s.csv' % file_id)\n\n"
        "    def _checked_path(self, file_id=None):\n"
        "        if file_id is None:\n"
        "            file_id = request.args.get('file_id')\n"
        "        if not file_id.isalnum():\n"
        "            raise ValueError('file_id')\n"
        "        return self._upload_tmp_path / ('%s.csv' % file_id)\n\n"
        "    def _record(self):\n"
        "        return Record(request.args.get('id'))\n\n"
        "    def read(self):\n"
        "        with self._file_path().open('r') as f:\n"
        "            return f.read()\n\n"
        "    def delete(self):\n"
        "        self._file_path().unlink()\n"
        "        self._record().unlink()\n\n"
        "    def read_checked(self):\n"
        "        return self._checked_path().read_text()\n\n"
        "    def save(self):\n"
        "        self._checked_path(uuid.uuid4().hex).write_text('x')\n\n"
        "    def known(self):\n"
        "        return Storage.objects.filter(path=normalize_path(request.args['p'])).exists()\n\n\n"
        "def normalize_path(p):\n"
        "    return p.strip('/')\n")})
    assert found == {("app/views.py", 17, "path-traversal"), ("app/views.py", 44, "path-traversal"),
                     ("app/views.py", 48, "path-traversal")}


@semgrep
def test_compile_alone_runs_nothing_but_exec_of_what_it_built_does(tmp_path):
    """Langflow GHSA-v798's note: validate_code() parsed the request's code, compiled each function definition and
    exec'd it; the fix only compiles, to report syntax errors. compile() was a sink itself, so the route stayed
    flagged after the fix. Found: exec() of a code object compiled from the request, in a helper and inline. Not
    found: compile() alone."""
    found = semgrep_vulnerabilities(tmp_path, {
        "app/api.py": (
            "from fastapi import APIRouter\n"
            "from pydantic import BaseModel\n\n"
            "from app.checks import check_code, run_code\n\n"
            "router = APIRouter()\n\n\n"
            "class Code(BaseModel):\n"
            "    code: str\n\n\n"
            "@router.post('/run')\n"
            "async def run(code: Code):\n"
            "    return run_code(code.code)\n\n\n"
            "@router.post('/check')\n"
            "async def check(code: Code):\n"
            "    return check_code(code.code)\n\n\n"
            "@router.post('/inline')\n"
            "async def inline(code: Code):\n"
            "    exec(compile(code.code, '<string>', 'exec'), {})\n"
            "    return {}\n\n\n"
            "@router.post('/syntax')\n"
            "async def syntax(code: Code):\n"
            "    compile(code.code, '<string>', 'exec')\n"
            "    return {}\n"),
        "app/checks.py": (
            "import ast\n\n\n"
            "def run_code(code):\n"
            "    tree = ast.parse(code)\n"
            "    for node in tree.body:\n"
            "        if isinstance(node, ast.FunctionDef):\n"
            "            code_obj = compile(ast.Module(body=[node], type_ignores=[]), '<string>', 'exec')\n"
            "            exec(code_obj, {})\n"
            "    return {}\n\n\n"
            "def check_code(code):\n"
            "    errors = []\n"
            "    tree = ast.parse(code)\n"
            "    for node in tree.body:\n"
            "        if isinstance(node, ast.FunctionDef):\n"
            "            try:\n"
            "                compile(ast.Module(body=[node], type_ignores=[]), '<string>', 'exec')\n"
            "            except SyntaxError as e:\n"
            "                errors.append(str(e))\n"
            "    return errors\n")})
    assert found == {("app/api.py", 15, "code-injection"), ("app/api.py", 25, "code-injection")}


@semgrep
def test_a_containment_helper_that_said_yes_clears_the_path(tmp_path):
    """swingmusic GHSA-pj88's and archivy 2565a9ab11d1's notes: a helper named for containment
    (is_path_within_root_dirs, is_relative_to) checks the path, and the view or the file helper returns when it says
    no, or uses the path only where it says yes. Still found: no check, the branch where it said no, a check an
    `and` can skip, and a helper named for permission rather than containment."""
    found = semgrep_vulnerabilities(tmp_path, {
        "app/views.py": (
            "from pathlib import Path\n\n"
            "from flask import Flask, request\n\n"
            "from app.store import create_dir, delete_dir, is_path_within_root_dirs\n\n"
            "app = Flask(__name__)\n\n\n"
            "def check_access(path):\n"
            "    return True\n\n\n"
            "@app.post('/list')\n"
            "def list_dir():\n"
            "    resolved = Path(request.json['folder']).resolve()\n"
            "    if not is_path_within_root_dirs(str(resolved)):\n"
            "        return {'error': 'denied'}, 403\n"
            "    return {'dirs': [d.name for d in resolved.iterdir()]}\n\n\n"
            "@app.post('/unchecked')\n"
            "def unchecked():\n"
            "    resolved = Path(request.json['folder']).resolve()\n"
            "    return {'dirs': [d.name for d in resolved.iterdir()]}\n\n\n"
            "@app.post('/no-branch')\n"
            "def no_branch():\n"
            "    resolved = Path(request.json['folder']).resolve()\n"
            "    if not is_path_within_root_dirs(resolved):\n"
            "        resolved.unlink()\n"
            "        return {}, 403\n"
            "    return {}\n\n\n"
            "@app.post('/skippable')\n"
            "def skippable():\n"
            "    resolved = Path(request.json['folder']).resolve()\n"
            "    if request.json.get('strict') and not is_path_within_root_dirs(resolved):\n"
            "        return {}, 403\n"
            "    return {'dirs': [d.name for d in resolved.iterdir()]}\n\n\n"
            "@app.post('/permission')\n"
            "def permission():\n"
            "    resolved = Path(request.json['folder']).resolve()\n"
            "    if not check_access(resolved):\n"
            "        return {}, 403\n"
            "    return {'dirs': [d.name for d in resolved.iterdir()]}\n\n\n"
            "@app.post('/folders')\n"
            "def create_folder():\n"
            "    if not create_dir(request.json.get('path', '')):\n"
            "        return {}, 400\n"
            "    return {}\n\n\n"
            "@app.delete('/folders')\n"
            "def delete_folder():\n"
            "    return {'ok': delete_dir(request.json.get('path', ''))}\n"),
        "app/store.py": (
            "from pathlib import Path\n"
            "from shutil import rmtree\n\n"
            "ROOT = Path('/srv/data')\n\n\n"
            "def is_path_within_root_dirs(path):\n"
            "    resolved = Path(path).resolve()\n"
            "    return resolved == ROOT or ROOT in resolved.parents\n\n\n"
            "def is_relative_to(sub_path, parent):\n"
            "    try:\n"
            "        sub_path.resolve().relative_to(parent)\n"
            "        return True\n"
            "    except ValueError:\n"
            "        return False\n\n\n"
            "def create_dir(name):\n"
            "    new_path = ROOT / name.strip('/')\n"
            "    if is_relative_to(new_path, ROOT):\n"
            "        new_path.mkdir(parents=True, exist_ok=True)\n"
            "        return True\n"
            "    return False\n\n\n"
            "def delete_dir(name):\n"
            "    target = ROOT / name\n"
            "    if not is_relative_to(target, ROOT) or target == ROOT:\n"
            "        return False\n"
            "    rmtree(target)\n"
            "    return True\n")})
    assert found == {("app/views.py", 25, "path-traversal"), ("app/views.py", 32, "path-traversal"),
                     ("app/views.py", 42, "path-traversal"), ("app/views.py", 50, "path-traversal")}


@semgrep
def test_a_resolved_path_checked_against_its_base_is_clear(tmp_path):
    """Agent Zero GHSA-8j45's note: the fix's _resolve_allowed_image_path() resolves the path, makes relative_to()
    against the base directory raise for one outside it, and returns it; the view sends what it returns. Also the
    check written as `BASE not in resolved.parents`. Still found: a helper that resolves without checking, and
    relative_to() on a path that wasn't resolved ("a/../../x" passes it)."""
    found = semgrep_vulnerabilities(tmp_path, {
        "app/api.py": (
            "from pathlib import Path\n\n"
            "from fastapi import FastAPI, HTTPException\n"
            "from fastapi.responses import FileResponse\n\n"
            "from app.paths import lexical_only, resolve_allowed, resolve_unchecked\n\n"
            "app = FastAPI()\n"
            "BASE = Path('/srv/agent')\n\n\n"
            "@app.get('/image')\n"
            "def image(path: str = ''):\n"
            "    try:\n"
            "        local = resolve_allowed(path)\n"
            "    except ValueError:\n"
            "        raise HTTPException(status_code=403)\n"
            "    return FileResponse(local)\n\n\n"
            "@app.get('/unchecked')\n"
            "def unchecked(path: str = ''):\n"
            "    return FileResponse(resolve_unchecked(path))\n\n\n"
            "@app.get('/lexical')\n"
            "def lexical(path: str = ''):\n"
            "    return FileResponse(lexical_only(path))\n\n\n"
            "@app.get('/parents')\n"
            "def parents(path: str = ''):\n"
            "    target = (BASE / path).resolve()\n"
            "    if BASE.resolve() not in target.parents:\n"
            "        raise HTTPException(status_code=403)\n"
            "    return FileResponse(target)\n"),
        "app/paths.py": (
            "from pathlib import Path\n\n"
            "BASE = Path('/srv/agent')\n\n\n"
            "def resolve_allowed(path: str) -> str:\n"
            "    candidate = BASE / path\n"
            "    resolved = candidate.resolve(strict=False)\n"
            "    try:\n"
            "        resolved.relative_to(BASE)\n"
            "    except ValueError as exc:\n"
            "        raise ValueError('outside') from exc\n"
            "    return str(resolved)\n\n\n"
            "def resolve_unchecked(path: str) -> str:\n"
            "    return str((BASE / path).resolve())\n\n\n"
            "def lexical_only(path: str) -> str:\n"
            "    candidate = BASE / path\n"
            "    try:\n"
            "        candidate.relative_to(BASE)\n"
            "    except ValueError:\n"
            "        raise\n"
            "    return str(candidate)\n")})
    assert found == {("app/api.py", 23, "path-traversal"), ("app/api.py", 28, "path-traversal")}
