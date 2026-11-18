"""False alarms codewatch raised on its own server and clients (2026-11-17, PLAN.md step 85): each shape with a real
flow beside it that must still be found."""
import pytest

from core.analyzers.multi_tools import Semgrep, form_has_csrf_token
from core.analyzers.project_checks import configured_names, refusal_helpers
from tests.test_detection import semgrep_vulnerabilities

pytestmark = pytest.mark.skipif(not Semgrep().available(), reason="semgrep not installed")

FLASK = "from flask import Flask, request\n\napp = Flask(__name__)\n"


def lines(found, rule):
    return {(path, line) for path, line, r in found if r == rule}


def test_a_module_find_is_not_xpath(tmp_path):
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "from xml.etree import ElementTree\n" + FLASK + "from . import catalog\nimport registry\n\n\n"
        "@app.route('/r/<rule_id>')\n"
        "def rule(rule_id):\n"
        "    catalog.find(rule_id)\n"                                                  # 11
        "    registry.find(rule_id)\n"                                                 # 12
        "    return ElementTree.parse('x.xml').getroot().find(request.args['q'])\n")})   # 13
    assert lines(found, "xpath-injection") == {("app.py", 13)}


def test_a_module_with_its_own_request_function_has_no_web_request(tmp_path):
    """codewatch's CLI client: `def request(url, token)` hides Flask's name in that module."""
    client = ("import json\nimport urllib.request\n\n\n"
              "def request(url, token):\n"
              "    with urllib.request.urlopen(url) as resp:\n"
              "        return json.load(resp)\n\n\n"
              "def save(url, token):\n"
              "    body = request(url + '/config/', token)\n"
              "    open(body['path'], 'w').write('x')\n")                                     # 12
    found = semgrep_vulnerabilities(tmp_path, {"client.py": client, "app.py": (
        FLASK + "\n\n@app.route('/f')\ndef f():\n    return open(request.args['p']).read()\n")})   # 8
    assert lines(found, "path-traversal") == {("app.py", 8)}


def test_a_helper_that_refuses_a_bad_value_guards_its_callers(tmp_path):
    """codewatch's scan_refusal checks a branch name with a regex and returns a message; launch_scan stops when
    it answers, so the branch passed to it is checked. A helper that returns its argument, or never checks a
    parameter, is no guard."""
    jobs = ("import re\nimport subprocess\n\nBRANCH_RE = re.compile(r'^(?!-)[\\w./-]{1,200}$')\n\n\n"
            "def refusal(branch=None):\n"
            "    if branch and not BRANCH_RE.match(branch):\n"
            "        return \"That isn't a branch name.\"\n"
            "    return None\n\n\n"
            "def describe(branch):\n"
            "    if not branch:\n"
            "        return 'none'\n"
            "    return f'branch {branch}'\n\n\n"
            "def launch(branch):\n"
            "    if refusal(branch):\n"
            "        return None\n"
            "    subprocess.run('git fetch origin ' + branch, shell=True)\n\n\n"
            "def launch_unchecked(branch):\n"
            "    if describe(branch):\n"
            "        return None\n"
            "    subprocess.run('git fetch origin ' + branch, shell=True)\n\n\n"
            "def launch_stored(branch):\n"
            "    problem = refusal(branch)\n"
            "    if problem:\n"
            "        raise ValueError(problem)\n"
            "    subprocess.run('git fetch origin ' + branch, shell=True)\n")
    found = semgrep_vulnerabilities(tmp_path, {"jobs.py": jobs, "app.py": (
        FLASK + "from jobs import launch, launch_stored, launch_unchecked\n\n\n"
        "@app.route('/s', methods=['POST'])\n"
        "def s():\n"
        "    launch(request.form['branch'])\n"                                          # 9
        "    launch_stored(request.form['branch'])\n"                                   # 10
        "    launch_unchecked(request.form['branch'])\n"                                # 11
        "    return 'ok'\n")})
    assert lines(found, "command-injection") == {("app.py", 11)}
    assert refusal_helpers([jobs]) == {"refusal"}


def test_a_configured_base_url_fixes_the_host(tmp_path):
    """codewatch's MCP server: the host comes from CODEWATCH_URL and the tool's arguments make the path; its body
    goes in a urllib Request, whose URL is checked where it's built."""
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "import json\nimport os\nimport urllib.request\n" + FLASK + "\n\n"
        "@app.route('/a')\n"
        "def a():\n"
        "    base = os.environ.get('API', 'http://127.0.0.1').rstrip('/')\n"
        "    urllib.request.urlopen(f\"{base}/api/{request.args['p']}\")\n"           # 12
        "    urllib.request.urlopen(f\"{base}{request.args['p']}\")\n"                # 13
        "    urllib.request.urlopen(f\"{request.args['h']}/x/{base}\")\n"             # 14
        "    req = urllib.request.Request(f'{base}/api/', data=json.dumps(request.args).encode())\n"
        "    urllib.request.urlopen(req)\n"                                           # 16
        "    urllib.request.urlopen(urllib.request.Request(request.args['u']))\n"     # 17
        "    return 'ok'\n")})
    assert lines(found, "ssrf") == {("app.py", 13), ("app.py", 14), ("app.py", 17)}
    assert configured_names(["import os\nbase = os.environ['X']\nother = compute()\n"]) == {"base"}


def test_a_row_the_orm_just_created_is_stored_data(tmp_path):
    """codewatch's create_project returns Project.objects.create(**fields) with fields from the request body; the
    row's key, not the body, made the upload path. A helper that hands the request value back still counts."""
    found = semgrep_vulnerabilities(tmp_path, {"views.py": (
        "from django.http import HttpResponse\nfrom .models import Project\n\n\n"
        "def create(fields):\n"
        "    project = Project.objects.create(**fields)\n"
        "    return project\n\n\n"
        "def echo(fields):\n"
        "    return fields\n\n\n"
        "def view(request):\n"
        "    project = create({'name': request.POST['name']})\n"
        "    open(f'/srv/{project.key}/upload', 'wb')\n"                    # 16
        "    same = echo(request.POST['name'])\n"
        "    open(f'/srv/{same}/upload', 'wb')\n"                           # 18
        "    return HttpResponse('ok')\n")})
    assert lines(found, "path-traversal") == {("views.py", 18)}


def test_a_long_form_with_its_csrf_token_has_one():
    """Semgrep's django-no-csrf-token reported codewatch's 15-line settings form, whose token is on its first line:
    the rule's `...` stops after about ten lines. The form's own lines decide."""
    form = ['<form method="post">{% csrf_token %}', *(f"<p>field {i}</p>" for i in range(14)), "</form>"]
    page = ["<h1>Settings</h1>", *form, '<form method="post">', "<p>no token</p>", "</form>"]
    assert form_has_csrf_token(page, 2, 17)
    assert form_has_csrf_token(["<form method=post>{%- csrf_token -%}</form>"], 1, 1)
    assert not form_has_csrf_token(page, 18, 20), "the token of another form doesn't count"
