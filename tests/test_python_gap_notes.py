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
