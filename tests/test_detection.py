"""Detection and noise: merged duplicates, token formats, context filters, the typed and cross-file ESLint passes."""
import json
import shutil

import pytest

from core import benchmark, catalog
from core.analyzers.base import Context, Finding
from core.analyzers.extra import (
    CREDENTIAL_CONTEXT_RE,
    EslintQuality,
    drop_shared_globals,
    known_tokens,
    typed_ts_files,
)
from core.analyzers.multi_tools import Semgrep
from core.analyzers.python_tools import SECRET_USE_RE
from core.client import default_config
from core.duplicates import dedupe


def issue(tool, rule, type_="code_smell", severity="minor"):
    return {"tool": tool, "rule": rule, "severity": severity, "type": type_, "message": "m", "path": "a.py",
            "line": 3, "end_line": None, "fingerprint": f"{tool}{rule}"}


def test_dedupe_merges_repeats_of_one_rule():
    kept = dedupe([issue("eslint", "no-mixed-operators"), issue("eslint", "no-mixed-operators"),
                   issue("eslint", "eqeqeq")])
    assert sorted(i["rule"] for i in kept) == ["eqeqeq", "no-mixed-operators"]
    assert all(i["also_reported_by"] == [] for i in kept)


def test_dedupe_merges_complexity_tools_but_not_unrelated_smells():
    kept = dedupe([issue("radon", "cyclomatic-complexity", severity="major"),
                   issue("complexipy", "cognitive-complexity"),
                   issue("lizard", "cyclomatic-complexity"),
                   issue("ruff", "F401")])
    complexity = next(i for i in kept if i["tool"] == "radon")
    assert sorted(complexity["also_reported_by"]) == ["complexipy:cognitive-complexity", "lizard:cyclomatic-complexity"]
    assert len(kept) == 2


def test_dedupe_keeps_sources_from_an_already_merged_upload():
    first = dedupe([issue("bandit", "B110:try_except_pass", "security_hotspot"),
                    issue("ruff", "S110", "security_hotspot")])
    again = dedupe([dict(i) for i in first])
    assert len(again) == 1 and again[0]["also_reported_by"] == first[0]["also_reported_by"] != []


def test_bandit_lookup_survives_renamed_tests():
    entry = catalog.lookup("bandit", "B324:hashlib")
    assert entry and entry["id"].startswith("bandit/B324")


def test_known_token_formats(tmp_path):
    sonar = "squ_" + "0f" * 20
    github = "ghp_" + "A1" * 18
    (tmp_path / ".mcp.json").write_text(json.dumps({"env": {"SONARQUBE_TOKEN": sonar}}, indent=1))
    (tmp_path / "ci.sh").write_text(f"export GH={github}\necho ghp_short\n")
    (tmp_path / "data.bin").write_bytes(b"\xff\xfe" + sonar.encode())
    ctx = Context(root=tmp_path, files=[".mcp.json", "ci.sh", "data.bin"])
    found = {(f.path, f.line, f.rule) for f in known_tokens(ctx, set())}
    assert found == {(".mcp.json", 3, "SonarQube Token"), ("ci.sh", 1, "GitHub Token")}
    assert known_tokens(ctx, {(".mcp.json", 3), ("ci.sh", 1)}) == [], "lines detect-secrets already reported"


def test_entropy_needs_a_credential_name():
    for line in ('API_KEY = "9f86d081884c7d65"', "'Authorization': 'Bearer ab12'", "client_secret: x"):
        assert CREDENTIAL_CONTEXT_RE.search(line), line
    for line in ('"commit_hash_like": "9f86d081884c"', '"color": "a3b2c1d4e5f6"', "id = 'deadbeefcafe'"):
        assert not CREDENTIAL_CONTEXT_RE.search(line), line


def test_random_is_only_a_weakness_for_secrets():
    for line in ("token = random.random()", "salt = random.randbytes(8)", "iv = random.randbytes(16)"):
        assert SECRET_USE_RE.search(line), line
    for line in ("random.shuffle(players)", "delivery = random.randint(1, 3)", "x = random.choice(words)"):
        assert not SECRET_USE_RE.search(line), line


def test_no_undef_ignores_globals_other_scripts_define_or_the_host_injects(tmp_path):
    (tmp_path / "ws.js").write_text("class QuizWS {}\nwindow.helper = () => 1;\n")
    for name in ("a.js", "b.js", "c.js"):
        (tmp_path / name).write_text("native.go();\n")
    ctx = Context(root=tmp_path, files=["ws.js", "a.js", "b.js", "c.js"])

    def undef(name, path):
        return Finding("eslint", "no-undef", "major", "bug", f"'{name}' is not defined.", path, 1)

    kept = drop_shared_globals(ctx, [undef("QuizWS", "a.js"), undef("helper", "b.js"), undef("native", "a.js"),
                                     undef("native", "b.js"), undef("native", "c.js"), undef("typo", "c.js")])
    assert [f.message for f in kept] == ["'typo' is not defined."]


def test_typed_pass_only_covers_files_under_a_tsconfig():
    files = ["web/tsconfig.json", "web/src/app.ts", "web/src/ui/x.tsx", "scripts/tool.ts", "web/main.js"]
    assert typed_ts_files(Context(root=".", files=files)) == ["web/src/app.ts", "web/src/ui/x.tsx"]
    assert typed_ts_files(Context(root=".", files=["tsconfig.json", "a.ts"])) == ["a.ts"]


@pytest.mark.skipif(not EslintQuality().available(), reason="ESLint not installed")
def test_eslint_catches_precedence_reduce_and_floating_promises(tmp_path):
    (tmp_path / "tsconfig.json").write_text('{"compilerOptions": {"strict": true, "target": "es2022"}}')
    (tmp_path / "mix.ts").write_text(
        "export const pan = (p: number[], i: number) => (p[i] ?? 32 - 32) / 32;\n"
        "export const sum = (xs: number[]) => xs.reduce((a, b) => a + b);\n"
        "export const ok = (a: number, b: number, c: number) => a + b * c;\n"
        "async function load(): Promise<void> {}\n"
        "export function start() { load(); }\n"
    )
    (tmp_path / "obj.js").write_text("export const pick = (o, k) => o[k];\n")
    ctx = Context(root=tmp_path, files=["tsconfig.json", "mix.ts", "obj.js"])
    found = {(f.path, f.line, f.rule) for f in EslintQuality().run(ctx).findings}
    assert ("mix.ts", 1, "no-mixed-operators") in found
    assert ("mix.ts", 2, "no-restricted-syntax") in found
    assert ("mix.ts", 5, "@typescript-eslint/no-floating-promises") in found
    assert not any(line == 3 for _, line, _ in found), "plain arithmetic precedence is fine"
    assert not any(rule == "security/detect-object-injection" for *_, rule in found)


def test_guard_that_rejects_a_character_sanitizes(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    (tmp_path / "app.py").write_text(
        "from flask import request\nimport elementpath\n\n\n"
        "def guarded(root):\n"
        "    name = request.args.get('n')\n"
        "    if \"'\" in name:\n"
        "        return 'bad'\n"
        "    return elementpath.select(root, f\"/u[@n='{name}']\")\n\n\n"
        "def open_query(root):\n"
        "    name = request.args.get('n')\n"
        "    return elementpath.select(root, f\"/u[@n='{name}']\")\n"
    )
    ctx = Context(root=tmp_path, files=["app.py"], semgrep_config="", custom_rules=catalog.custom_semgrep_rules())
    hits = [f.line for f in Semgrep().run(ctx).findings if f.rule.endswith("xpath-injection")]
    assert hits == [14]


def test_first_scan_of_a_new_project_runs_the_built_in_rules():
    assert "codewatch.python.web.sql-injection" in default_config("main").custom_rules


def test_cwe_folder_suite_scoring(tmp_path):
    for cwe, name in (("CWE-089", "a.py"), ("CWE-089", "b.py"), ("CWE-022", "c.py")):
        (tmp_path / "cases" / cwe).mkdir(parents=True, exist_ok=True)
        (tmp_path / "cases" / cwe / name).write_text("x = 1\n")
    suite = {"test_dir": "cases"}
    hit = {"tool": "codewatch", "rule": "codewatch.python.web.sql-injection", "type": "vulnerability",
           "path": "cases/CWE-089/a.py", "line": 1}
    wrong_cwe = {**hit, "path": "cases/CWE-022/c.py"}
    result = benchmark.score_cwe_folders(tmp_path, suite, [hit, wrong_cwe])
    assert result["verdict"]["overall"] == {"found": 1, "total": 3, "recall": 0.333, "any_security": 0.667}
    assert result["verdict"]["categories"]["CWE-89"] == {"found": 1, "total": 2}


def test_seed_suite_scores_clean_controls_as_false_alarms(tmp_path):
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    for name in ("sqli.js", "xss.js", "clean-a.js", "clean-b.js"):
        (seeds / name).write_text("x = 1\n")
    (tmp_path / "truth.yaml").write_text("seeds:\n  - {file: sqli.js, cwe: CWE-89}\n  - {file: xss.js, cwe: CWE-79}\n")
    suite = {"test_dir": "seeds", "ground_truth": "truth.yaml", "clean_glob": "clean-*.js"}
    sqli = {"tool": "codewatch", "rule": "codewatch.js.sql-injection", "type": "vulnerability",
            "path": "seeds/sqli.js", "line": 1}
    result = benchmark.score_seeds(tmp_path, suite, [sqli, {**sqli, "path": "seeds/clean-a.js"}])
    assert {k: result["verdict"]["overall"][k] for k in ("tp", "fn", "fp", "tn")} == {"tp": 1, "fn": 1, "fp": 1, "tn": 1}
    assert result["verdict"]["categories"]["clean controls"] == {"tp": 0, "fn": 0, "fp": 1, "tn": 1}


@pytest.mark.skipif(shutil.which("cppcheck") is None, reason="cppcheck not installed")
def test_unused_struct_members_are_only_reported_outside_headers(tmp_path):
    from core.analyzers.multi_tools import Cppcheck

    body = "struct Packet { int id; int unused; };\nint read(struct Packet *p) { return p->id; }\n"
    (tmp_path / "abi.h").write_text(body)
    (tmp_path / "local.c").write_text(body)
    ctx = Context(root=tmp_path, files=["abi.h", "local.c"])
    paths = {f.path for f in Cppcheck().run(ctx).findings if f.rule == "unusedStructMember"}
    assert paths == {"local.c"}


def test_bandit_keeps_random_only_where_it_makes_secrets(tmp_path):
    from core.analyzers.python_tools import Bandit

    if not Bandit().available():
        pytest.skip("bandit not installed")
    (tmp_path / "app.py").write_text(
        "import random\nimport subprocess\nimport tempfile\n\n\n"
        "def deal(deck):\n    random.shuffle(deck)\n    return random.choice(deck)\n\n\n"
        "def new_session_id():\n    \"\"\"Unpredictable id for the login cookie.\"\"\"\n"
        "    return random.getrandbits(64)\n\n\n"
        "def run(args):\n    subprocess.run(['ls', *args], check=True)\n    return tempfile.mktemp()\n"
    )
    found = {(f.rule.split(":")[0], f.line) for f in Bandit().run(Context(root=tmp_path, files=["app.py"])).findings}
    assert ("B311", 13) in found and ("B306", 18) in found
    assert not {r for r, _ in found} & {"B404", "B603", "B607"}
    assert not {line for r, line in found if r == "B311"} & {7, 8}


def test_dead_constant_branches_are_blanked_keeping_lines_and_indentation():
    import ast

    from core.analyzers.constant_branches import blank_dead_branches

    source = ("def f(param):\n\tnum = 86\n\tif (7 * 42) - num > 200:\n\t\tbar = 'safe'\n\telse:\n\t\tbar = param\n"
              "\tother = 'x' if num > 50 else param\n\tpossible = 'ABC'\n\tmatch possible[1]:\n"
              "\t\tcase 'A':\n\t\t\tbar = param\n\t\tcase 'B':\n\t\t\tbar = 'bob'\n\treturn bar, other\n")
    out = blank_dead_branches(source)
    ast.parse(out)
    assert out.count("\n") == source.count("\n")
    assert "bar = param" not in out and "else param" not in out and "\t\tbar = 'safe'" in out
    assert blank_dead_branches("def f(p):\n    n = 1\n    n = p\n    return 'a' if n > 0 else p\n") is None


def test_slices_become_indexes_without_moving_lines():
    import ast

    from core.analyzers.slices import index_slices

    assert index_slices("y = x[2:]\nz = s[len('a'):len(s) - 5]\nw = f'{v:>10}'\n") == (
        "y = x[2, ]\nz = s[len('a'), len(s) - 5]\nw = f'{v:>10}'\n")
    for source in ("a = x[:5]\n", "a = x[::2]\n", "a = b[c[1:]:]\n", "f = sorted(x, key=lambda t: t[1:])\n"):
        ast.parse(index_slices(source))
    assert index_slices("d = {k: v for k, v in x}\nt = x[lambda a: a]\n") is None


def test_crypto_and_tls_misuse_rules(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    (tmp_path / "bad.py").write_text(
        "import ssl, os, ftplib, tempfile, hashlib, jwt, requests\n"
        "from Crypto.Cipher import AES, DES\n\n\n"
        "def f(key, data, token, password):\n"
        "    ctx = ssl.create_default_context()\n"
        "    ctx.verify_mode = ssl.CERT_NONE\n"
        "    requests.get('https://x', verify=False)\n"
        "    iv = b'x' * 16\n"
        "    AES.new(key, AES.MODE_CBC, iv)\n"
        "    AES.new(key, AES.MODE_ECB)\n"
        "    DES.new(key, DES.MODE_CBC, os.urandom(8))\n"
        "    hashlib.pbkdf2_hmac('sha256', password, b'pepper', 100000)\n"
        "    jwt.decode(token, options={'verify_signature': False})\n"
        "    tempfile.mktemp()\n"
        "    ftplib.FTP('host')\n"
        "    return 'postgresql://user:@db.example.com/app'\n"
    )
    (tmp_path / "good.py").write_text(
        "import ssl, os, ftplib, tempfile, hashlib, jwt, requests\n"
        "from Crypto.Cipher import AES\n\n\n"
        "def f(key, data, token, password):\n"
        "    ctx = ssl.create_default_context()\n"
        "    requests.get('https://x', timeout=5)\n"
        "    AES.new(key, AES.MODE_GCM, nonce=os.urandom(12))\n"
        "    hashlib.pbkdf2_hmac('sha256', password, os.urandom(16), 100000)\n"
        "    jwt.decode(token, key, algorithms=['HS256'])\n"
        "    tempfile.mkstemp()\n"
        "    ftplib.FTP_TLS('host')\n"
        "    return 'postgresql://user:secret@db.example.com/app'\n"
    )
    ctx = Context(root=tmp_path, files=["bad.py", "good.py"], semgrep_config="",
                  custom_rules=catalog.custom_semgrep_rules())
    found = {(f.path, f.line, f.rule.rsplit(".", 1)[1]) for f in Semgrep().run(ctx).findings
             if f.rule.startswith("codewatch.python.") and f.type == "vulnerability"}
    assert not {f for f in found if f[0] == "good.py"}
    assert {(line, rule) for _, line, rule in found} >= {
        (7, "tls-verification-disabled"), (8, "tls-verification-disabled"), (10, "static-iv"), (11, "weak-cipher"),
        (12, "weak-cipher"), (13, "constant-salt"), (14, "jwt-not-verified"), (15, "insecure-temp-file"),
        (16, "cleartext-protocol"), (17, "database-url-without-password")}


def test_pip_audit_reads_utf16_requirements_and_survives_unresolvable_manifests(tmp_path, monkeypatch):
    from core.analyzers import dependencies
    from core.analyzers.base import ToolError

    (tmp_path / "requirements.txt").write_bytes("django==5.1.15\n".encode("utf-16"))
    (tmp_path / "requirements-extra.txt").write_text("no-such-package>=1\n")
    assert dependencies.read_manifest(tmp_path / "requirements.txt") == "django==5.1.15\n"

    def fake_exec(self, args, ctx, ok_codes=(0,)):
        if "requirements-extra.txt" in args:
            raise ToolError("No matching distribution")
        return json.dumps({"dependencies": [{"name": "django", "version": "5.1.15",
                                             "vulns": [{"id": "CVE-2026-1", "aliases": [], "fix_versions": ["5.2"]}]}]})

    monkeypatch.setattr(dependencies.PipAudit, "exec", fake_exec)
    monkeypatch.setattr(dependencies, "osv_severity", lambda ids: "major")
    ctx = Context(root=tmp_path, files=["requirements.txt", "requirements-extra.txt"])
    result = dependencies.PipAudit().run(ctx)
    assert [(f.rule, f.path, f.line) for f in result.findings] == [("CVE-2026-1", "requirements.txt", 1)]
    assert result.metrics["dependency_manifests_unresolved"] == 1


def test_javascript_taint_rules(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    (tmp_path / "app.js").write_text(
        "const express = require('express')\nconst child_process = require('child_process')\n"
        "const fs = require('fs')\nconst app = express()\n\n"
        "app.get('/a', (req, res) => {\n"
        "  sequelize.query(`SELECT * FROM t WHERE name = '${req.query.name}'`)\n"
        "  child_process.exec('ls ' + req.body.dir)\n"
        "  fs.readFile('/data/' + req.params.file, () => {})\n"
        "  res.send('<p>' + req.query.q + '</p>')\n"
        "  res.redirect(req.query.next)\n"
        "  eval(req.body.code)\n"
        "  fetch(req.query.url)\n"
        "})\n\n"
        "app.get('/b', async (req, res) => {\n"
        "  sequelize.query('SELECT * FROM t WHERE id = ?', { replacements: [req.query.id] })\n"
        "  child_process.execFile('ls', [req.body.dir])\n"
        "  fs.readFile('/data/' + path.basename(req.params.file), () => {})\n"
        "  res.send({ q: req.query.q })\n"
        "  res.send('<p>' + escapeHtml(req.query.q) + '</p>')\n"
        "  res.redirect('/home')\n"
        "  const id = parseInt(req.query.id)\n"
        "  sequelize.query(`SELECT * FROM t WHERE id = ${id}`)\n"
        "  const page = await fs.promises.readFile('/static/' + path.basename(req.path))\n"
        "  res.send(page)\n"
        "})\n\n"
        "app.get('/c', (req, res) => {\n"
        "  res.setHeader('Content-Type', 'text/event-stream')\n"
        "  res.write(`data: ${req.query.msg}\\n\\n`)\n"
        "})\n"
    )
    ctx = Context(root=tmp_path, files=["app.js"], semgrep_config="", custom_rules=catalog.custom_semgrep_rules())
    found = {(f.line, f.rule.rsplit(".", 1)[1]) for f in Semgrep().run(ctx).findings
             if f.rule.startswith("codewatch.js.")}
    assert found == {(7, "sql-injection"), (7, "sql-value-formatting"), (8, "command-injection"), (9, "path-traversal"), (10, "xss"),
                     (11, "open-redirect"), (12, "code-injection"), (13, "ssrf")}


def test_javascript_crypto_and_config_rules(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    (tmp_path / "bad.js").write_text(
        "const crypto = require('crypto')\nconst jwt = require('jsonwebtoken')\n\n"
        "function makeToken() {\n  return Math.random().toString(36)\n}\n"
        "const agent = new https.Agent({ rejectUnauthorized: false })\n"
        "crypto.createCipheriv('aes-128-ecb', key, null)\n"
        "const iv = Buffer.alloc(16)\ncrypto.createCipheriv('aes-256-cbc', key, iv)\n"
        "jwt.sign(user, 'hunter2')\n"
        "app.use(rateLimit({ keyGenerator: (req) => req.headers['x-forwarded-for'] }))\n"
        "libxml.parseXml(body, { noent: true })\n"
    )
    (tmp_path / "good.js").write_text(
        "const crypto = require('crypto')\n\n"
        "function shuffleDeck(deck) {\n  return deck.sort(() => Math.random() - 0.5)\n}\n"
        "crypto.createCipheriv('aes-256-gcm', key, crypto.randomBytes(12))\n"
        "jwt.sign(user, process.env.JWT_SECRET)\n"
        "app.use(rateLimit({ keyGenerator: (req) => req.ip }))\n"
    )
    ctx = Context(root=tmp_path, files=["bad.js", "good.js"], semgrep_config="",
                  custom_rules=catalog.custom_semgrep_rules())
    found = {(f.path, f.line, f.rule.rsplit(".", 1)[1]) for f in Semgrep().run(ctx).findings
             if f.rule.startswith("codewatch.js.")}
    assert not {f for f in found if f[0] == "good.js"}
    assert {(line, rule) for _, line, rule in found} >= {
        (5, "weak-random-secret"), (7, "tls-verification-disabled"), (8, "weak-cipher"), (10, "static-iv"),
        (11, "hardcoded-jwt-secret"), (12, "rate-limit-spoofable-key"), (13, "xml-external-entities")}


def test_random_passed_as_a_named_argument_is_judged_by_that_name(tmp_path):
    from core.analyzers.python_tools import SECRET_USE_RE, LineCache

    (tmp_path / "bots.py").write_text(
        "import random\n\n\n"
        "def spawn(session_key):\n"
        "    return dict(session_key=session_key, connected=True, rtt_ms=random.uniform(2.0, 20.0))\n\n\n"
        "def new_session_id():\n"
        "    value = str(random.random())[2:]\n"
        "    return value\n"
    )
    source = LineCache(tmp_path)
    assert source.purpose_text("bots.py", 5) == "rtt_ms"
    assert not SECRET_USE_RE.search(source.purpose_text("bots.py", 5))
    assert SECRET_USE_RE.search(source.purpose_text("bots.py", 9)), "a generic name falls back to the function"


def test_container_slots_are_tracked_one_by_one():
    from core.analyzers.containers import track_slots

    source = (
        "def f(param):\n"
        "    m = {}\n"
        "    m['a-1'] = 'x'\n"
        "    m['b'] = param\n"
        "    bar = m['a-1'] + m.get('b')\n"
        "    conf = configparser.ConfigParser()\n"
        "    conf.set('s', 'k', param)\n"
        "    bar = conf.get('s', 'k')\n"
        "    lst = []\n"
        "    lst.append('safe')\n"
        "    lst.append(param)\n"
        "    lst.append('moresafe')\n"
        "    lst.pop(0)\n"
        "    bar = lst[1]\n"
        "    other = lst[0]\n"
        "    request.form['x']\n"
    )
    assert track_slots(source).splitlines() == [
        "def f(param):",
        "    m = {}",
        "    m.k_a_1 = 'x'",
        "    m.k_b = param",
        "    bar = m.k_a_1 + m.k_b",
        "    conf = configparser.ConfigParser()",
        "    conf.k_s_k = param",
        "    bar = conf.k_s_k",
        "    lst = []",
        "    lst.append('safe')",
        "    lst.append(param)",
        "    lst.append('moresafe')",
        "    lst.pop(0)",
        "    bar = 'moresafe'",
        "    other = lst[0]",
        "    request.form['x']",
    ]
    # A dict that is rebound, or a list passed elsewhere before the read, keeps its subscripts.
    assert track_slots("def f(p, g):\n    m = {}\n    m = g()\n    return m['a']\n") is None
    assert track_slots("def f(p, g):\n    l = []\n    l.append('a')\n    g(l)\n    return l[0]\n") is None


def test_match_statements_become_ifs_on_the_same_lines():
    import ast

    from core.analyzers.match_statements import match_as_if

    source = ("def f(x, p):\n"
              "    match x:\n"
              "        case 'A' | 'B':\n"
              "            y = p\n"
              "        case [a, *rest] if a:\n"
              "            y = a\n"
              "        case _:  # default\n"
              "            y = 1\n"
              "    return hashlib.md5(y)\n")
    lines = match_as_if(source).splitlines()
    assert [lines[i] for i in (1, 2, 4, 6)] == [
        "    if True:", "        if (x) == ('A' | 'B'):", "        if (x) == ([a, *rest]) and (a):",
        "        if (x) == (_):  # default"]
    ast.parse(match_as_if(source))
    assert match_as_if("match x:\n    case str() as s:\n        pass\n") is None


def test_dead_ternary_nested_in_functions_is_replaced_once():
    from core.analyzers.constant_branches import blank_dead_branches

    source = "def init(app):\n\tdef v(param):\n\t\tnum = 106\n\t\tbar = 'x' if (7*42) - num > 200 else param\n"
    assert blank_dead_branches(source).splitlines()[3] == "\t\tbar = None if (7*42) - num > 200 else param"


def test_registry_rules_defer_to_codewatch_taint_rules():
    from core.analyzers.multi_tools import cwe_numbers, taint_checked

    rules = [{"id": "a", "mode": "taint", "languages": ["python"], "metadata": {"cwe": ["CWE-22: Path"]}},
             {"id": "b", "languages": ["javascript"], "metadata": {"cwe": "CWE-79: XSS"}}]
    assert taint_checked(rules) == {".py": {22}}
    assert cwe_numbers("CWE-611: XXE") == {611}


def semgrep_vulnerabilities(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    ctx = Context(root=tmp_path, files=list(files), semgrep_config="", custom_rules=catalog.custom_semgrep_rules())
    return {(f.path, f.line, f.rule.rsplit(".", 1)[1]) for f in Semgrep().run(ctx).findings
            if f.type == "vulnerability"}


def test_taint_follows_one_call_into_a_helper(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {
        "app.py": (
            "from pathlib import Path\nfrom flask import Flask, request\n\napp = Flask(__name__)\nBASE = Path('.')\n\n\n"
            "def load(name, mode='r'):\n"
            "    return (BASE / name).read_text()\n\n\n"
            "def load_safe(name):\n"
            "    return (BASE / Path(name).name).read_text()\n\n\n"
            "@app.post('/a')\n"
            "def a():\n"
            "    load(request.form['f'])\n"
            "    load_safe(request.form['f'])\n"
            "    load('fixed.css')\n"
            "    return 'ok'\n"),
        "other.py": "from flask import request\n\n\ndef load(name):\n    return name\n\n\ndef b():\n    load(request.args['x'])\n",
    })
    assert found == {("app.py", 18, "path-traversal")}


def test_taint_follows_helpers_several_calls_deep(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {
        "store.py": "import os\n\n\ndef read(name):\n    return open(os.path.join('/srv', name)).read()\n",
        "service.py": ("from store import read\n\n\n"
                       "def load(kind, name):\n    return read(name)\n\n\n"
                       "def fixed(name):\n    return read('index.html')\n"),
        "views.py": ("from flask import request\nfrom service import load, fixed\n\n\n"
                     "def page():\n"
                     "    fixed(request.args['p'])\n"
                     "    return load('page', request.args['p'])\n"),
        "elsewhere.py": "from flask import request\n\n\ndef load(kind, name):\n    return name\n\n\n"
                        "def other():\n    return load(1, request.args['p'])\n",
    })
    assert found == {("views.py", 7, "path-traversal")}


def test_injection_rules_without_a_request_source(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"db.py": (
        "import tarfile\n\n\n"
        "def f(cur, name, table, uid, n):\n"
        "    cur.execute(\"DELETE FROM users WHERE username = '%s'\" % name)\n"
        "    cur.execute(f\"INSERT INTO t VALUES ('{name}', {n})\")\n"
        "    q = \"SELECT * FROM t WHERE a = '%s'\" % name\n"
        "    cur.execute(q)\n"
        "    cur.execute(f\"SELECT COUNT(*) FROM {table}\")\n"
        "    cur.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))\n"
        "    with tarfile.open(name) as tar:\n"
        "        tar.extractall('/tmp')\n"
        "        tar.extractall('/tmp', filter='data')\n")})
    assert found == {("db.py", 5, "sql-value-formatting"), ("db.py", 6, "sql-value-formatting"),
                     ("db.py", 8, "sql-value-formatting"), ("db.py", 12, "tar-extraction-without-filter")}


def test_xxe_is_a_vulnerability_only_when_request_data_reaches_the_parser(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    source = ("import xml.sax\nimport xml.dom.minidom\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
              "@app.post('/x')\n"
              "def x():\n"
              "    parser = xml.sax.make_parser()\n"
              "    parser.setFeature(xml.sax.handler.feature_external_ges, True)\n"
              "    xml.dom.minidom.parseString(request.get_data(), parser)\n"
              "    xml.dom.minidom.parseString('<a/>', parser)\n"
              "    return 'ok'\n")
    assert semgrep_vulnerabilities(tmp_path, {"x.py": source}) == {("x.py", 12, "xxe")}


def test_pathlib_sinks_need_a_path_and_queryset_exists_is_not_one(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"views.py": (
        "import pathlib\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
        "@app.post('/p')\n"
        "def p():\n"
        "    name = request.form['n']\n"
        "    base = pathlib.Path('/srv')\n"
        "    p = (base / name).resolve()\n"
        "    if p.exists():\n"
        "        pass\n"
        "    q = (base / name).resolve()\n"
        "    if not str(q).startswith(str(base)):\n"
        "        return 'no'\n"
        "    q.read_text()\n"
        "    if Player.objects.filter(nickname=name).exists():\n"
        "        pass\n"
        "    when = datetime.now().replace(day=int(name))\n"
        "    return 'ok'\n")})
    assert found == {("views.py", 12, "path-traversal")}


def test_destructured_express_request_is_a_source(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"files.ts": (
        "import fs from 'fs'\n"
        "export function serve () {\n"
        "  return ({ params }: Request, res: Response) => {\n"
        "    fs.readFileSync('/srv/' + params.file)\n"
        "  }\n"
        "}\n"
        "app.use('/ftp', serveIndex('ftp', { icons: true }))\n")})
    assert found == {("files.ts", 4, "path-traversal"), ("files.ts", 7, "directory-listing")}


def test_javascript_injection_rules_and_guards(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {
        "db.js": (
            "function q(pool, name, table, id) {\n"
            "  pool.query(\"SELECT * FROM users WHERE name = '\" + name + \"'\")\n"
            "  pool.query(`SELECT * FROM orders WHERE id = ${id} AND name = '${name}'`)\n"
            "  pool.query('SELECT * FROM ' + table)\n"
            "  pool.query('SELECT * FROM t WHERE id = $1', [id])\n"
            "}\n"
            "function merge(target, source) {\n"
            "  for (const key of Object.keys(source)) {\n"
            "    if (typeof source[key] === 'object') { merge(target[key], source[key]) } else {\n"
            "      target[key] = source[key]\n"
            "    }\n"
            "  }\n"
            "}\n"
            "function safeMerge(target, source) {\n"
            "  for (const key of Object.keys(source)) {\n"
            "    if (key === '__proto__') continue\n"
            "    if (typeof source[key] === 'object') { safeMerge(target[key], source[key]) } else {\n"
            "      target[key] = source[key]\n"
            "    }\n"
            "  }\n"
            "}\n"),
        "app.js": (
            "const exec = require('child_process').exec\n"
            "const swig = require('swig')\n"
            "swig.setDefaults({ autoescape: false })\n"
            "app.get('/a', (req, res) => {\n"
            "  exec('ping -c 2 ' + req.body.address)\n"
            "  db.collection('t').find({ $where: `this.a > '${req.query.t}'` })\n"
            "  const next = req.query.next\n"
            "  if (!next.startsWith('/') || next.startsWith('//')) {\n"
            "    return res.redirect('/')\n"
            "  }\n"
            "  res.redirect(next)\n"
            "})\n"),
    })
    assert found == {("db.js", 2, "sql-value-formatting"), ("db.js", 3, "sql-value-formatting"),
                     ("db.js", 10, "prototype-pollution-merge"), ("app.js", 3, "template-autoescape-disabled"),
                     ("app.js", 5, "command-injection"), ("app.js", 6, "nosql-injection")}


def test_javascript_summaries_follow_dao_methods_across_files(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {
        "data/dao.js": ("function Dao(db) {\n"
                        "  this.byThreshold = (userId, threshold) => {\n"
                        "    return db.collection('a').find({ $where: `this.stocks > '${threshold}'` })\n"
                        "  }\n"
                        "}\nmodule.exports = Dao\n"),
        "routes/a.js": ("const Dao = require('../data/dao')\n"
                        "const dao = new Dao(db)\n"
                        "app.get('/a', (req, res) => {\n"
                        "  const { threshold } = req.query\n"
                        "  dao.byThreshold(1, threshold)\n"
                        "})\n"),
        "routes/b.js": ("app.get('/b', (req, res) => {\n"
                        "  other.byThreshold(1, req.query.t)\n"
                        "})\n"),
    })
    assert found == {("routes/a.js", 5, "nosql-injection")}


def test_import_resolution_for_summaries():
    from core.analyzers.summaries import visible

    texts = {"good/mod_user.py": "import libuser\n", "routes/a.ts": "import * as security from '../lib/insecurity'\n",
             "pkg/views.py": "from .helpers import load\nfrom pkg.sub import x\n"}
    assert not visible("good/mod_user.py", {"bad/libuser.py"}, texts.get)
    assert visible("good/mod_user.py", {"good/libuser.py"}, texts.get)
    assert visible("routes/a.ts", {"lib/insecurity.ts"}, texts.get)
    assert visible("pkg/views.py", {"pkg/helpers.py"}, texts.get)
    assert visible("pkg/views.py", {"pkg/sub.py"}, texts.get)
    assert not visible("pkg/views.py", {"other/helpers.py"}, texts.get)


def test_weak_hash_is_a_vulnerability_only_where_it_protects_something(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {
        "models.py": ("import hashlib\n\n\n"
                      "def avatar(email):\n"
                      "    return hashlib.md5(email.encode()).hexdigest()\n\n\n"
                      "def store_password(password):\n"
                      "    return hashlib.md5(password.encode()).hexdigest()\n\n\n"
                      "def certificate_matches(cert, known):\n"
                      "    return hashlib.sha1(cert).hexdigest() == known\n"),
    })
    assert found == {("models.py", 9, "weak-hash"), ("models.py", 13, "weak-hash")}


def test_python_autoescape_off_and_hash_chosen_by_constant(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "import hashlib\nimport jinja2\nfrom aiohttp_jinja2 import setup as setup_jinja\n\nALGORITHM = 'sha1'\n\n\n"
        "def init(app):\n"
        "    setup_jinja(app, loader=jinja2.PackageLoader('x', 'templates'), autoescape=False)\n"
        "    sql = jinja2.Environment(autoescape=False)\n"
        "    return sql\n\n\n"
        "def otp(key):\n"
        "    return hashlib.new(ALGORITHM, key).hexdigest()\n")})
    assert found == {("app.py", 9, "template-autoescape-disabled"), ("app.py", 15, "weak-hash")}


def test_request_data_as_url_pattern_log_line_and_location(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {
        "app.py": (
            "import logging\nimport re\n\nimport requests\nfrom flask import Flask, Response, request\n\n"
            "app = Flask(__name__)\nlog = logging.getLogger(__name__)\n\n\n"
            "@app.route('/a')\n"
            "def a():\n"
            "    requests.get(request.args['url'])\n"
            "    requests.get('https://api.example.com/items/' + request.args['id'])\n"
            "    requests.get(f\"https://api.example.com/{request.args['id']}\")\n"
            "    re.search(request.args['p'], 'text')\n"
            "    re.search(re.escape(request.args['p']), 'text')\n"
            "    log.info('name ' + request.args['name'])\n"
            "    log.info('name %r', request.args['name'])\n"
            "    log.info('name %s', repr(request.args['name']))\n"
            "    response = Response('moved', 302)\n"
            "    response.headers['Location'] = request.args['next']\n"
            "    return response\n"),
        "app.js": (
            "app.get('/b', (req, res) => {\n"
            "  const re = new RegExp(req.query.q)\n"
            "  const ok = new RegExp(escapeRegExp(req.query.q))\n"
            "  res.setHeader('Location', req.query.next)\n"
            "  res.end()\n"
            "})\n"),
    })
    assert found == {("app.py", 13, "ssrf"), ("app.py", 16, "regex-injection"), ("app.py", 22, "open-redirect"),
                     ("app.js", 2, "regex-injection"), ("app.js", 4, "open-redirect")}


def test_parameters_of_functions_nothing_calls_are_left_for_review(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    files = {
        "lib.py": ("import pickle\n\n\n"
                   "def load(blob):\n    return pickle.loads(blob)\n\n\n"
                   "def evaluate(expr):\n    return eval(expr)\n\n\n"
                   "def _private(expr):\n    return eval(expr)\n"),
        "main.py": "from lib import evaluate\n\nprint(evaluate('1 + 1'))\n",
        # From GHSA-h6m6-jj8v-94jj (litellm) at its fix: an int can't carry SQL.
        "spend.py": ("async def top(limit: int = Query(default=None), name: str = ''):\n"
                     "    await db.query_raw(f'SELECT * FROM spend LIMIT {limit}')\n"
                     "    await db.query_raw(f'SELECT * FROM spend WHERE name = {name}')\n"),
        "dao.js": ("async function findUser(body) {\n  return db.collection('users').findOne(body)\n}\n"
                   "module.exports = { findUser }\n"),
    }
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    ctx = Context(root=tmp_path, files=list(files), semgrep_config="", custom_rules=catalog.custom_semgrep_rules())
    found = {(f.path, f.line, f.rule.rsplit(".", 1)[1], f.type) for f in Semgrep().run(ctx).findings
             if "nothing in the project calls" in f.message}
    assert found == {("lib.py", 5, "unsafe-deserialization", "security_hotspot"),
                     ("spend.py", 3, "sql-injection", "security_hotspot"),
                     ("dao.js", 2, "nosql-injection", "security_hotspot")}


def test_local_named_request_referrer_redirect_and_log_lines(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    files = {"app.py": (
        "import logging\nimport urllib.request\n\nfrom flask import Flask, redirect, request as flask_request\n\n"
        "app = Flask(__name__)\nlog = logging.getLogger(__name__)\n\n\n"
        "def download(url):\n"
        "    request = urllib.request.Request(url, headers={'User-Agent': 'x'})\n"
        "    return urllib.request.urlopen(request).read()\n\n\n"
        "@app.route('/back')\n"
        "def back():\n"
        "    log.info('back from ' + flask_request.args['from'])\n"
        "    download('https://example.com/a')\n"
        "    return redirect(flask_request.referrer or '/')\n")}
    (tmp_path / "app.py").write_text(files["app.py"])
    ctx = Context(root=tmp_path, files=list(files), semgrep_config="", custom_rules=catalog.custom_semgrep_rules())
    found = {(f.line, f.rule.rsplit(".", 1)[1], f.type) for f in Semgrep().run(ctx).findings}
    assert found == {(17, "log-injection", "security_hotspot")}


def test_ordinary_app_patterns_stay_quiet(tmp_path):
    """From djangoproject.com, bakerydemo and node-express-boilerplate: a path-derived redirect is for review,
    and query strings after a fixed URL, ORM lookups, Django-rendered templates and whole records sent with
    res.send are not vulnerabilities; the unsafe variants next to them still are."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    files = {
        "views.py": (
            "from django.http import HttpResponse\n"
            "from django.shortcuts import redirect, render\n"
            "from wagtail.contrib.routable_page.models import route\n\n"
            "from .models import Document\n\n\n"
            "def redirect_index(request):\n"
            "    return redirect(request.path[:-6])\n\n\n"
            "def search(request):\n"
            "    url = '/search/'\n"
            "    q = request.GET.get('q')\n"
            "    if q:\n"
            "        url += '?q=%s' % q\n"
            "    exact = Document.objects.filter(title=q).first()\n"
            "    if exact is not None:\n"
            "        return redirect(exact)\n"
            "    return redirect(url)\n\n\n"
            "def go(request):\n"
            "    return redirect(request.GET['next'] + '?a=1')\n\n\n"
            "class Blog:\n"
            "    @route(r'^tags/$')\n"
            "    def tags(self, request, tag=None):\n"
            "        return render(request, 'tags.html', {'tag': request.GET.get('tag')})\n\n\n"
            "def echo(request):\n"
            "    return HttpResponse(request.GET['q'])\n"),
        "user.controller.js": (
            "const getUser = async (req, res) => {\n"
            "  const user = await userService.getUserById(req.params.userId);\n"
            "  res.send(user);\n"
            "};\n"
            "const greet = async (req, res) => {\n"
            "  const html = await renderer.render(req.query.tpl);\n"
            "  res.send(html);\n"
            "  res.send(req.query.name);\n"
            "};\n"
            "module.exports = { getUser, greet };\n"),
        "tests/helpers.py": ("import subprocess\n\nfrom flask import request\n\n\n"
                             "def run():\n    subprocess.run(request.args['cmd'], shell=True)\n"),
    }
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    ctx = Context(root=tmp_path, files=list(files), semgrep_config="", custom_rules=catalog.custom_semgrep_rules())
    found = {(f.path, f.line, f.rule.rsplit(".", 1)[1], f.type) for f in Semgrep().run(ctx).findings}
    assert found == {
        ("views.py", 9, "open-redirect-path", "security_hotspot"),
        ("views.py", 24, "open-redirect", "vulnerability"),
        ("views.py", 34, "xss", "vulnerability"),
        ("user.controller.js", 7, "xss", "vulnerability"),
        ("user.controller.js", 8, "xss", "vulnerability"),
        ("tests/helpers.py", 7, "command-injection", "security_hotspot"),
    }


def semgrep_findings(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    ctx = Context(root=tmp_path, files=list(files), semgrep_config="", custom_rules=catalog.custom_semgrep_rules())
    return {(f.path, f.line, f.rule.rsplit(".", 1)[1], f.type) for f in Semgrep().run(ctx).findings
            if "nothing in the project calls" not in f.message}


def test_uploads_stored_under_the_client_name(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "app.py": (
            "import os\n\nfrom fastapi import FastAPI, File, UploadFile\nfrom flask import Flask, request\n"
            "from werkzeug.utils import secure_filename\n\n"
            "app = Flask(__name__)\napi = FastAPI()\nALLOWED = {'png', 'jpg'}\n\n\n"
            "def allowed_file(name):\n    return name.rsplit('.', 1)[1].lower() in ALLOWED\n\n\n"
            "@app.route('/a', methods=['POST'])\n"
            "def a():\n"
            "    f = request.files['file']\n"
            "    f.save(os.path.join('uploads', f.filename))\n"
            "    f.save(os.path.join('uploads', secure_filename(f.filename)))\n"
            "    if f and allowed_file(f.filename):\n"
            "        f.save(os.path.join('uploads', secure_filename(f.filename)))\n"
            "    stem = os.path.splitext(f.filename)[0]\n"
            "    f.save(os.path.join('uploads', secure_filename(stem) + '.png'))\n"
            "    return 'ok'\n\n\n"
            "@api.post('/b')\n"
            "async def b(file: UploadFile = File(...)):\n"
            "    with open(f'uploads/{file.filename}', 'wb') as out:\n"
            "        out.write(await file.read())\n"),
        "upload.js": (
            "const storage = multer.diskStorage({\n"
            "  destination: 'uploads/',\n"
            "  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname),\n"
            "})\n"
            "const named = multer.diskStorage({\n"
            "  filename: (req, file, cb) => cb(null, path.parse(file.originalname).name + '.png'),\n"
            "})\n"
            "app.post('/u', (req, res) => {\n"
            "  const file = req.files.doc\n"
            "  file.mv('/srv/uploads/' + file.name)\n"
            "  req.files.doc.mv('/srv/uploads/' + req.query.name)\n"
            "})\n"),
    })
    assert found == {
        ("app.py", 19, "path-traversal", "vulnerability"),
        ("app.py", 19, "unrestricted-upload", "security_hotspot"),
        ("app.py", 20, "unrestricted-upload", "security_hotspot"),
        ("app.py", 30, "unrestricted-upload", "security_hotspot"),
        ("upload.js", 3, "unrestricted-upload", "security_hotspot"),
        ("upload.js", 10, "unrestricted-upload", "security_hotspot"),
        ("upload.js", 11, "path-traversal", "vulnerability"),
    }


def test_error_details_in_responses(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "app.py": (
            "import traceback\n\nfrom flask import Flask, jsonify\n\napp = Flask(__name__)\n\n\n"
            "@app.route('/a')\n"
            "def a():\n"
            "    try:\n"
            "        run()\n"
            "    except ValueError as e:\n"
            "        return jsonify(error=str(e)), 400\n"
            "    except Exception as e:\n"
            "        if app.debug:\n"
            "            return jsonify(error=traceback.format_exc()), 500\n"
            "        return jsonify(error=str(e), kind=type(e).__name__), 500\n"
            "    return 'ok'\n\n\n"
            "@app.route('/b')\n"
            "def b():\n"
            "    try:\n"
            "        run()\n"
            "    except Exception:\n"
            "        return traceback.format_exc(), 500\n"
            "    return 'ok'\n"),
        "errors.js": (
            "app.use((err, req, res, next) => {\n"
            "  res.status(500).json({ message: err.message, stack: err.stack })\n"
            "})\n"
            "app.use((err, req, res, next) => {\n"
            "  res.status(500).json({ stack: process.env.NODE_ENV === 'development' ? err.stack : undefined })\n"
            "  res.status(500).send({ ...(config.env === 'development' \x26\x26 { stack: err.stack }) })\n"
            "})\n"),
    })
    assert found == {
        ("app.py", 17, "exception-message-in-response", "security_hotspot"),
        ("app.py", 26, "stack-trace-exposure", "vulnerability"),
        ("errors.js", 2, "stack-trace-exposure", "vulnerability"),
    }


def test_whole_request_body_written_to_a_model(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "views.py": (
            "from flask import request\n\nfrom .models import User, db\n\n\n"
            "def create():\n"
            "    user = User(**request.json)\n"
            "    data = request.get_json()\n"
            "    other = User(**data)\n"
            "    picked = User(name=data['name'], email=data['email'])\n"
            "    fields = {'name': request.json['name']}\n"
            "    db.session.add(User(**fields))\n"
            "    return user, other, picked\n"),
        "users.js": (
            "router.post('/users', async (req, res) => {\n"
            "  const user = await User.create(req.body)\n"
            "  const body = req.body\n"
            "  await User.findByIdAndUpdate(req.params.id, body)\n"
            "  await prisma.user.create({ data: { ...req.body } })\n"
            "  await User.create({ name: req.body.name })\n"
            "  res.json(user)\n"
            "})\n"),
    })
    assert found == {
        ("views.py", 7, "mass-assignment", "security_hotspot"),
        ("views.py", 9, "mass-assignment", "security_hotspot"),
        ("users.js", 2, "mass-assignment", "security_hotspot"),
        ("users.js", 4, "mass-assignment", "security_hotspot"),
        ("users.js", 5, "mass-assignment", "security_hotspot"),
    }


def test_template_injection_ldap_and_xpath(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "app.py": (
            "import jinja2\nfrom flask import Flask, render_template_string, request\n"
            "from jinja2.sandbox import SandboxedEnvironment\n\napp = Flask(__name__)\n\n\n"
            "@app.route('/a')\n"
            "def a():\n"
            "    jinja2.Template(request.args['t']).render()\n"
            "    jinja2.Environment().from_string(request.args['t'])\n"
            "    sandbox = SandboxedEnvironment()\n"
            "    sandbox.from_string(request.args['t'])\n"
            "    render_template_string('Hello {{ name }}', name=request.args['name'])\n"
            "    return 'ok'\n"),
        "app.js": (
            "app.get('/t', (req, res) => {\n"
            "  res.send(pug.render(req.query.tpl))\n"
            "  res.send(ejs.render('<p><%= name %></p>', { name: req.query.name }))\n"
            "  res.send(_.template(req.body.t)({}))\n"
            "})\n"
            "app.post('/login', (req, res) => {\n"
            "  client.search('ou=people', { filter: '(uid=' + req.body.user + ')' }, done)\n"
            "  client.search('ou=people', { filter: '(uid=' + escapeLdap(req.body.user) + ')' }, done)\n"
            "  xpath.select(\"//user[name='\" + req.body.user + \"']\", doc)\n"
            "  xpath.select('//user', doc)\n"
            "})\n"),
    })
    assert found == {
        ("app.py", 10, "template-injection", "vulnerability"),
        ("app.py", 11, "template-injection", "vulnerability"),
        ("app.js", 2, "template-injection", "vulnerability"),
        ("app.js", 2, "xss", "vulnerability"),
        ("app.js", 4, "template-injection", "vulnerability"),
        ("app.js", 4, "xss", "vulnerability"),
        ("app.js", 7, "ldap-injection", "vulnerability"),
        ("app.js", 9, "xpath-injection", "vulnerability"),
    }


def test_cors_reflecting_any_origin_with_credentials(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "api.py": (
            "from fastapi import FastAPI\nfrom fastapi.middleware.cors import CORSMiddleware\n"
            "from flask import Flask\nfrom flask_cors import CORS\n\n"
            "app = Flask(__name__)\nCORS(app, supports_credentials=True)\n"
            "CORS(app, supports_credentials=True, origins=['https://app.example.com'])\nCORS(app)\n"
            "api = FastAPI()\n"
            "api.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n"
            "api.add_middleware(CORSMiddleware, allow_origins=['*'])\n"
            "api.add_middleware(CORSMiddleware, allow_origins=['https://app.example.com'], allow_credentials=True)\n"),
        "settings.py": "CORS_ALLOW_ALL_ORIGINS = True\nCORS_ALLOW_CREDENTIALS = True\n",
        "other_settings.py": "CORS_ALLOW_ALL_ORIGINS = True\n",
        "server.js": (
            "app.use(cors({ origin: true, credentials: true }))\n"
            "app.use(cors({ origin: ['https://app.example.com'], credentials: true }))\n"
            "app.use(cors())\n"
            "app.use((req, res, next) => {\n"
            "  res.setHeader('Access-Control-Allow-Origin', req.headers.origin)\n"
            "  res.setHeader('Access-Control-Allow-Credentials', 'true')\n"
            "  next()\n"
            "})\n"
            "app.use((req, res, next) => {\n"
            "  if (allowed.includes(req.headers.origin)) {\n"
            "    res.setHeader('Access-Control-Allow-Origin', req.headers.origin)\n"
            "  }\n"
            "  res.setHeader('Access-Control-Allow-Credentials', 'true')\n"
            "  next()\n"
            "})\n"),
    })
    assert found == {
        ("api.py", 7, "cors-any-origin-with-credentials", "vulnerability"),
        ("api.py", 11, "cors-any-origin-with-credentials", "vulnerability"),
        ("settings.py", 1, "cors-any-origin-with-credentials", "vulnerability"),
        ("server.js", 1, "cors-any-origin-with-credentials", "vulnerability"),
        ("server.js", 5, "cors-any-origin-with-credentials", "vulnerability"),
    }


def test_signature_timing_cookies_and_secrets_in_logs(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "hooks.py": (
            "import hashlib\nimport hmac\n\n\n"
            "def verify(key, body, signature):\n"
            "    expected = hmac.new(key, body, hashlib.sha256).hexdigest()\n"
            "    if expected != signature:\n"
            "        return False\n"
            "    if len(expected) == len(signature):\n"
            "        pass\n"
            "    return hmac.compare_digest(expected, signature)\n\n\n"
            "def quick(key, body, sig):\n"
            "    return hmac.new(key, body, hashlib.sha256).hexdigest() == sig\n"),
        "hooks.js": (
            "function verify(secret, body, sig) {\n"
            "  const mac = crypto.createHmac('sha256', secret).update(body).digest('hex')\n"
            "  if (mac === sig) return true\n"
            "  return crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(sig))\n"
            "}\n"
            "app.post('/login', (req, res) => {\n"
            "  res.cookie('session', token, { httpOnly: true })\n"
            "  res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' })\n"
            "  res.cookie('theme', 'dark')\n"
            "  res.cookie('refresh_token', token, { secure: process.env.NODE_ENV === 'production' })\n"
            "  res.cookie('session', '', { maxAge: 0 })\n"
            "  console.log('login', req.body.password)\n"
            "  logger.info(`token is ${accessToken}`)\n"
            "  console.log('token refreshed')\n"
            "})\n"
            "app.use(session({ secret: s, cookie: { httpOnly: false } }))\n"),
    })
    assert found == {
        ("hooks.py", 7, "timing-unsafe-signature-check", "vulnerability"),
        ("hooks.py", 15, "timing-unsafe-signature-check", "vulnerability"),
        ("hooks.js", 3, "timing-unsafe-signature-check", "vulnerability"),
        ("hooks.js", 7, "cookie-without-secure", "vulnerability"),
        ("hooks.js", 12, "secret-in-log", "security_hotspot"),
        ("hooks.js", 13, "secret-in-log", "security_hotspot"),
        ("hooks.js", 16, "session-cookie-flags", "security_hotspot"),
    }


def test_changing_routes_without_the_auth_other_routes_use(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "routes.js": (
            "router.get('/users', auth, list)\n"
            "router.post('/users', auth, validate(schema), create)\n"
            "router.delete('/users/:id', remove)\n"
            "router.patch('/users/:id', validate(schema), update)\n"
            "router.post('/login', validate(schema), login)\n"
            "router.get('/feed', feed)\n"),
        "open.js": "router.post('/comments', create)\nrouter.delete('/comments/:id', remove)\n",
        "views.py": (
            "from flask import Blueprint\nfrom flask_login import login_required\n\nbp = Blueprint('a', __name__)\n\n\n"
            "@bp.route('/notes', methods=['POST'])\n"
            "@login_required\n"
            "def create():\n    return 'ok'\n\n\n"
            "@bp.route('/notes/<int:id>', methods=['DELETE'])\n"
            "def delete(id):\n    return 'ok'\n\n\n"
            "@bp.route('/login', methods=['POST'])\n"
            "def login():\n    return 'ok'\n\n\n"
            "@bp.route('/notes')\n"
            "def index():\n    return 'ok'\n"),
        "upload.js": "const a = multer({ dest: 'uploads/' })\nconst b = multer({ dest: 'uploads/', limits: { fileSize: 1e6 } })\n",
        "cookies.py": (
            "SESSION_COOKIE_HTTPONLY = False\nSESSION_COOKIE_SAMESITE = 'None'\nCSRF_COOKIE_SAMESITE = 'Lax'\n\n\n"
            "def view(resp):\n"
            "    resp.set_cookie('sid', 'x', secure=True, httponly=False)\n"
            "    resp.set_cookie('sid', 'x', secure=True, httponly=True, samesite='Lax')\n"),
    })
    assert found == {
        ("routes.js", 3, "route-without-auth", "security_hotspot"),
        ("routes.js", 4, "route-without-auth", "security_hotspot"),
        ("views.py", 14, "route-without-login", "security_hotspot"),
        ("upload.js", 1, "upload-without-limits", "security_hotspot"),
        ("cookies.py", 1, "cookie-protection-off", "security_hotspot"),
        ("cookies.py", 2, "cookie-protection-off", "security_hotspot"),
        ("cookies.py", 7, "cookie-protection-off", "security_hotspot"),
    }


def test_signup_routes_and_filtered_uploads_stay_quiet(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "routes.js": "router.get('/users/me', auth, me)\nrouter.post('/users', register)\nrouter.post('/api/users', register)\n",
        "upload.js": (
            "const upload = multer({\n"
            "  fileFilter: (req, file, cb) => cb(null, /\\.(png|jpe?g)$/i.test(file.originalname)),\n"
            "  storage: multer.diskStorage({ filename: (req, file, cb) => cb(null, Date.now() + file.originalname) }),\n"
            "  limits: { fileSize: 1e6 },\n"
            "})\n"),
        "users.py": (
            "from flask import Blueprint\n\nbp = Blueprint('a', __name__)\n\n\n"
            "@bp.route('/users/<int:id>', methods=['GET'])\n@token_auth.login_required\ndef get_user(id):\n    return 'ok'\n\n\n"
            "@bp.route('/users', methods=['POST'])\ndef create_user():\n    return 'ok'\n"),
    })
    assert found == set()


def test_lockfile_parsers_cover_npm_yarn_and_pnpm_formats():
    from core.analyzers import dependencies as deps

    npm_v3 = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"lodash": "^4"}},
        "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/a/node_modules/@scope/b": {"version": "1.0.0", "dev": True},
        "node_modules/aliased": {"name": "real-name", "version": "2.0.0"},
        "packages/local": {"version": "0.0.1"},
        "node_modules/local": {"link": True, "resolved": "packages/local"}}})
    npm_v1 = json.dumps({"lockfileVersion": 1, "dependencies": {
        "express": {"version": "4.0.0", "dependencies": {"qs": {"version": "0.6.0"}}},
        "local": {"version": "file:../local"}}})
    assert deps.package_lock_packages(npm_v3) == {("lodash", "4.17.20"): False, ("@scope/b", "1.0.0"): True,
                                                  ("real-name", "2.0.0"): False}
    assert set(deps.package_lock_packages(npm_v1)) == {("express", "4.0.0"), ("qs", "0.6.0")}
    yarn_v1 = ('# yarn lockfile v1\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.2.0"\n'
               '  resolved "https://x"\n\nlodash@^4.17.0:\n  version "4.17.20"\n')
    berry = ('__metadata:\n  version: 6\n\n"lodash@npm:^4.17.0":\n  version: 4.17.21\n\n'
             '"app@workspace:.":\n  version: 0.0.0-use.local\n')
    assert set(deps.yarn_lock_packages(yarn_v1)) == {("@babel/core", "7.2.0"), ("lodash", "4.17.20")}
    assert set(deps.yarn_lock_packages(berry)) == {("lodash", "4.17.21")}
    pnpm_v5 = "lockfileVersion: 5.4\npackages:\n  /lodash/4.17.20:\n    resolution: {}\n  /@scope/b/1.0.0_react@18.0.0:\n    resolution: {}\n"
    pnpm_v9 = "lockfileVersion: '9.0'\npackages:\n  lodash@4.17.21:\n    resolution: {}\n  '@scope/b@1.0.0(react@18.0.0)':\n    resolution: {}\n"
    pnpm_v5 = pnpm_v5.replace("/lodash/4.17.20:\n    resolution: {}", "/lodash/4.17.20:\n    resolution: {}\n    dev: true")
    assert deps.pnpm_lock_packages(pnpm_v5) == {("lodash", "4.17.20"): True, ("@scope/b", "1.0.0"): False}
    assert set(deps.pnpm_lock_packages(pnpm_v9)) == {("lodash", "4.17.21"), ("@scope/b", "1.0.0")}


def test_osv_lockfiles_reports_advisories_for_pinned_versions(tmp_path, monkeypatch):
    from core.analyzers import dependencies as deps

    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {}, "node_modules/lodash": {"version": "4.17.20"}, "node_modules/ok": {"version": "1.0.0"},
        "node_modules/build/node_modules/lodash": {"version": "4.17.19", "dev": True}}}, indent=2))
    (tmp_path / "yarn.lock").write_text("broken: [\n")

    def fake_post(url, body):
        return {"results": [{"vulns": [{"id": "GHSA-1"}]} if q["package"]["name"] == "lodash" else {}
                            for q in body["queries"]]}

    monkeypatch.setattr(deps, "osv_post", fake_post)
    monkeypatch.setattr(deps, "osv_get", lambda vid: {
        "id": vid, "aliases": ["CVE-2026-9"], "summary": "Prototype pollution", "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"name": "lodash", "ecosystem": "npm"},
                      "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]})
    ctx = Context(root=tmp_path, files=["package-lock.json", "yarn.lock"])
    analyzer = deps.OsvLockfiles()
    assert analyzer.applies(ctx)
    result = analyzer.run(ctx)
    assert [(f.tool, f.rule, f.severity, f.type, f.path, f.line) for f in result.findings] == [
        ("osv", "CVE-2026-9", "critical", "security_hotspot", "package-lock.json", 5),
        ("osv", "CVE-2026-9", "critical", "vulnerability", "package-lock.json", 5)]
    assert "(development only)" in result.findings[0].message
    assert "lodash 4.17.20: CVE-2026-9 — fixed in 4.17.21. Prototype pollution" in result.findings[1].message
    assert result.metrics["vulnerable_dependencies"] == 2


def test_dependency_counts_from_both_audits_add_up(monkeypatch, tmp_path):
    from core import collect
    from core.analyzers.base import Result

    class Fake:
        def __init__(self, name, critical):
            self.name, self.critical = name, critical

        def applies(self, ctx):
            return True

        def available(self):
            return True

        def run(self, ctx):
            result = Result()
            result.metrics = {"dependency_critical_vulnerabilities": self.critical, "other": self.critical}
            return result

    monkeypatch.setattr(collect, "ANALYZERS", [Fake("pip-audit", 2), Fake("osv", 3)])
    combined, _ = collect.run_analyzers(collect.ScanConfig(), Context(root=tmp_path, files=[]), lambda m: None)
    assert combined.metrics == {"dependency_critical_vulnerabilities": 5, "other": 3}


def test_focus_narrows_only_the_per_file_pass(tmp_path):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    files = {
        "helpers.py": "import subprocess\n\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n",
        "views.py": ("from flask import Flask, request\n\nfrom helpers import run\n\napp = Flask(__name__)\n\n\n"
                     "@app.route('/a')\ndef a():\n    run(request.args['cmd'])\n    return 'ok'\n"),
        "other.py": ("import subprocess\n\nfrom flask import request\n\n\n"
                     "def b():\n    subprocess.run(request.args['cmd'], shell=True)\n"),
    }
    for name, text in files.items():
        (tmp_path / name).write_text(text)

    def found(focus):
        ctx = Context(root=tmp_path, files=list(files), semgrep_config="", custom_rules=catalog.custom_semgrep_rules(),
                      focus=focus)
        return {(f.path, f.line, f.rule.rsplit(".", 1)[1], f.type) for f in Semgrep().run(ctx).findings}

    everything = found(None)
    assert ("views.py", 10, "command-injection", "vulnerability") in everything
    assert found(["views.py"]) == {f for f in everything if f[0] == "views.py"}
    assert found([]) == set()


def test_redirect_checks_from_cve_fix_pairs(tmp_path):
    """From GHSA-9x43-5qcq-h79q (Grappelli): url_has_allowed_host_and_scheme called with url= is a check too.
    From GHSA-v279-v2xm-whq9 (oils-js): an HTTPS upgrade to the request's own Host and path isn't an open redirect,
    but the path alone, or after a host from the query, still is."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "views.py": (
            "from django.http import Http404\n"
            "from django.shortcuts import redirect\n"
            "from django.utils.http import url_has_allowed_host_and_scheme\n\n\n"
            "def switch_user(request):\n"
            "    redirect_url = request.GET.get('redirect', None)\n"
            "    if redirect_url is None or not url_has_allowed_host_and_scheme(\n"
            "            url=redirect_url, allowed_hosts={request.get_host()}, require_https=request.is_secure()):\n"
            "        raise Http404()\n"
            "    return redirect(redirect_url)\n\n\n"
            "def old(request):\n"
            "    redirect_url = request.GET.get('redirect', None)\n"
            "    return redirect(redirect_url)\n"),
        "web.js": (
            "function toHttps(req, res) {\n"
            "  res.writeHead(302, {'Location': 'https://' + req.headers.host.split(':')[0] + ':8443' + req.url});\n"
            "  res.end();\n"
            "}\n"
            "function back(req, res) {\n"
            "  res.redirect(req.url);\n"
            "  res.redirect('https://' + req.query.host + req.url);\n"
            "}\n"),
    })
    assert found == {
        ("views.py", 16, "open-redirect", "vulnerability"),
        ("web.js", 6, "open-redirect", "vulnerability"),
        ("web.js", 7, "open-redirect", "vulnerability"),
    }


def test_route_converters_become_annotations():
    from core.analyzers.route_converters import type_route_converters
    source = ("@bp.route('/u/<path:name>/<int:n>/<uuid:key>')\n@login_required\ndef view(name, n, key: str, x='é'):\n"
              "    pass\n\n\n@app.get('/a/<int:n>')\nasync def a(n=1):\n    pass\n")
    assert type_route_converters(source) == source.replace("name, n, key", "name, n: int, key").replace(
        "a(n=1)", "a(n: int=1)")
    assert type_route_converters("def f(n):\n    return '<int:n>'\n") is None
    # GHSA-8whx-v8qq-pq64 (changedetection.io): the fix swaps <string:tag_uuid> for an app's own uuid_str converter.
    assert type_route_converters("@rss.route('/tag/<uuid_str:tag>/<any(a, b):page>/<string:s>')\n"
                                 "def feed(tag, page, s):\n    pass\n").splitlines()[1] == (
        "def feed(tag: uuid_str, page: any, s):")


def test_route_parameters_and_raw_sql_sinks(tmp_path):
    """From GHSA-f2mf-q878-gh58 (Parsl) and GHSA-h6m6-jj8v-94jj (litellm): Flask route parameters and FastAPI text
    parameters are request data, reaching pandas.read_sql_query or Prisma's query_raw; numeric, UUID and Depends()
    parameters aren't."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "app.py": (
            "import uuid\nfrom typing import Optional\n\nimport fastapi\nimport pandas as pd\n"
            "from fastapi import APIRouter, Depends, Query\nfrom flask import Blueprint, Flask\n\n"
            "app = Flask(__name__)\nbp = Blueprint('main', __name__)\nrouter = APIRouter()\n\n\n"
            "@app.route('/workflow/<workflow_id>/dag')\n"
            "def dag(workflow_id):\n"
            "    return pd.read_sql_query(\"SELECT * FROM task WHERE run_id='%s'\" % workflow_id, db.engine)\n\n\n"
            "@bp.route('/u/<path:name>/<int:n>')\n"
            "@login_required\n"
            "def mixed(name, n):\n"
            "    cursor.execute('SELECT %s' % n)\n"
            "    cursor.execute(\"SELECT '%s'\" % name)\n"
            "    pd.read_sql_query('SELECT * FROM t WHERE n = :n', db.engine, params={'n': name})\n\n\n"
            "@router.get('/spend')\n"
            "async def spend(api_key: str = fastapi.Query(default=None), limit: int = Query(10)):\n"
            "    await prisma_client.db.query_raw(query=\"SELECT * FROM t WHERE k = '\" + api_key + \"'\")\n"
            "    await prisma_client.db.query_raw('SELECT * FROM t LIMIT %d' % limit)\n"
            "    await prisma_client.db.query_raw('SELECT * FROM t WHERE k = $1', api_key)\n\n\n"
            "@router.get('/items/{id}')\n"
            "def items(id: uuid.UUID, q: Optional[str] = None, session=Depends(get_db)):\n"
            "    session.execute(\"SELECT * FROM items WHERE id = '%s'\" % id)\n"
            "    session.execute(\"SELECT * FROM items WHERE q = '%s'\" % q)\n\n\n"
            "def helper(workflow_id):\n"
            "    cursor.execute(workflow_id)\n"),
    })
    assert {f for f in found if f[2] == "sql-injection"} == {
        ("app.py", 16, "sql-injection", "vulnerability"),
        ("app.py", 23, "sql-injection", "vulnerability"),
        ("app.py", 29, "sql-injection", "vulnerability"),
        ("app.py", 37, "sql-injection", "vulnerability"),
    }


def test_route_parameter_xss_and_file_responses(tmp_path):
    """From GHSA-8whx-v8qq-pq64 (changedetection.io): a <string:...> route parameter echoed in a response is XSS, one
    behind the app's own converter isn't; from pygoat: a file response named after the parameter isn't either."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "app.py": (
            "from flask import Flask, send_from_directory\n\napp = Flask(__name__)\n\n\n"
            "@app.route('/tag/<string:tag_uuid>')\n"
            "def tag(tag_uuid):\n"
            "    return f'Tag with UUID {tag_uuid} not found', 404\n\n\n"
            "@app.route('/tag2/<uuid_str:tag_uuid>')\n"
            "def tag2(tag_uuid):\n"
            "    return f'Tag with UUID {tag_uuid} not found', 404\n\n\n"
            "@app.route('/download/<path:filename>')\n"
            "def serve_file(filename):\n"
            "    return send_from_directory('static', filename, as_attachment=True, download_name=filename)\n"),
    })
    assert found == {("app.py", 8, "xss", "vulnerability")}


def test_path_prefix_checks(tmp_path):
    """From GHSA-8wqc-v2q8-vff2 (mockoon): a resolved path checked with startsWith against a base without a trailing
    separator lets a sibling directory sharing the prefix through. For review; base + sep and path.relative() are fine,
    and so is a URL prefix check on the request path. JavaScript only: the OWASP Benchmark for Python labels the same
    check safe in its path traversal cases."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "files.js": (
            "const path = require('path');\n"
            "const { resolve, relative } = require('path');\n"
            '\n'
            'function a(name) {\n'
            '  const base = path.resolve(root);\n'
            '  const target = path.join(base, name);\n'
            "  if (!target.startsWith(base)) throw new Error('outside');\n"
            '}\n'
            'function b(name) {\n'
            '  const base = path.resolve(root) + path.sep;\n'
            '  const target = path.resolve(base, name);\n'
            "  if (!target.startsWith(base)) throw new Error('outside');\n"
            '}\n'
            'function c(name) {\n'
            '  const target = resolve(this.options.dir, name);\n'
            "  if (!target.startsWith(this.options.dir + '/')) throw new Error('outside');\n"
            "  if (!target.startsWith(`${this.options.dir}${path.sep}`)) throw new Error('outside');\n"
            '  const rel = relative(this.options.dir, target);\n'
            "  if (rel.startsWith('..')) throw new Error('outside');\n"
            '}\n'
            'function d(req) {\n'
            '  if (req.path.startsWith(apiBasePath)) return next();\n'
            '  const staticBaseDir = m ? resolve(m[1]) : null;\n'
            "  if (!resolvedPath.startsWith(staticBaseDir)) throw new Error('x');\n"
            '}\n'),
    })
    assert found == {
        ("files.js", 7, "path-prefix-check", "security_hotspot"),
        ("files.js", 24, "path-prefix-check", "security_hotspot"),
    }


def test_filter_links_built_from_the_current_url(tmp_path):
    """A URL object made from the page's own address keeps its origin when only its query or path changes (a false
    alarm in one of the maintainer's own projects); a redirect to what its query holds, or after its href or host is
    replaced, is still flagged."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "nav.js": (
            'function a(filterValue) {\n'
            '  const url = new URL(window.location.href);\n'
            "  url.searchParams.set('difficulty', filterValue);\n"
            '  window.location.href = url.toString();\n'
            '}\n'
            'function b() {\n'
            '  const url = new URL(window.location.href);\n'
            "  window.location.href = url.searchParams.get('next');\n"
            '}\n'
            'function c() {\n'
            '  const url = new URL(location.href);\n'
            "  url.href = url.searchParams.get('next');\n"
            '  window.location.href = url.toString();\n'
            '}\n'
            'function d() {\n'
            '  const url = new URL(document.URL);\n'
            "  url.pathname = '/list';\n"
            '  window.location.href = url.href;\n'
            '}\n')})
    assert found == {("nav.js", 8, "open-redirect", "vulnerability"), ("nav.js", 13, "open-redirect", "vulnerability")}


def test_session_stores_records_looked_up_by_request_values(tmp_path):
    """From GHSA-9x43-5qcq-h79q (Grappelli): a row looked up by a request value is the database's record, so storing
    it in the session doesn't cross a trust boundary; storing the request value itself does."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "views.py": (
            'from django.shortcuts import get_object_or_404\n'
            '\n'
            '\n'
            'def a(request, object_id):\n'
            '    user = User.objects.get(pk=request.GET["id"])\n'
            '    request.session["user"] = {"id": user.id, "name": user.username}\n'
            '\n'
            '\n'
            'def b(request):\n'
            '    team = get_object_or_404(Team, pk=request.POST["team"])\n'
            '    request.session["team"] = team.pk\n'
            '\n'
            '\n'
            'def c(request):\n'
            '    request.session["team"] = request.POST["team"]\n')})
    assert found == {("views.py", 15, "trust-boundary", "vulnerability")}


def test_nestjs_controller_parameters(tmp_path):
    """NestJS @Param/@Query/@Body/@Headers parameters are request data, unless a pipe or a number/boolean/Date type
    converts them; TypeORM's dataSource.query() is a SQL sink. sendFile with a root option stays quiet."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "users.controller.ts": (
            "import { Body, Controller, Get, Param, ParseIntPipe, Query, Res } from '@nestjs/common';\n"
            "import { exec } from 'child_process';\n"
            '\n'
            "@Controller('users')\n"
            'export class UsersController {\n'
            '  constructor(private readonly dataSource: DataSource) {}\n'
            '\n'
            "  @Get(':slug')\n"
            "  async findOne(@Param('slug') slug, @Query('sort') sort: string) {\n"
            "    return this.dataSource.query(`SELECT * FROM users WHERE slug = '${slug}' ORDER BY ${sort}`);\n"
            '  }\n'
            '\n'
            "  @Get('id/:id')\n"
            "  async byId(@Param('id', ParseIntPipe) id: number, @Query('n') n: number) {\n"
            '    return this.dataSource.query(`SELECT * FROM users WHERE id = ${id} LIMIT ${n}`);\n'
            '  }\n'
            '\n'
            '  @Post()\n'
            '  create(@Body() dto: CreateUserDto) {\n'
            "    exec('useradd ' + dto.name);\n"
            "    return this.dataSource.query('SELECT * FROM users WHERE name = $1', [dto.name]);\n"
            '  }\n'
            '\n'
            "  @Get('download/:path')\n"
            "  download(@Param('path') path: string, @Res() res) {\n"
            "    return res.sendFile(path, { root: './files' });\n"
            '  }\n'
            '\n'
            '  helper(name: string) {\n'
            "    exec('ls ' + name);\n"
            '  }\n'
            '}\n')})
    assert {(path, line, rule) for path, line, rule, kind in found if kind == "vulnerability"} == {
        ("users.controller.ts", 10, "sql-injection"),
        ("users.controller.ts", 10, "sql-value-formatting"),
        ("users.controller.ts", 20, "command-injection"),
    }


def test_request_body_models(tmp_path):
    """A FastAPI route parameter typed with a Pydantic or SQLModel class is the request body: its text fields are
    request data, inherited ones too; its int fields, and the same model outside a route, aren't."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "models.py": (
            "from pydantic import BaseModel\n\n\n"
            "class ItemBase(BaseModel):\n"
            "    title: str\n"
            "    limit: int = 10\n\n\n"
            "class ItemCreate(ItemBase):\n"
            "    owner: str | None = None\n"),
        "api.py": (
            "from fastapi import APIRouter\n\nfrom models import ItemCreate\n\nrouter = APIRouter()\n\n\n"
            "@router.post('/items/')\n"
            "async def create(item: ItemCreate):\n"
            "    await db.execute(f\"SELECT * FROM items WHERE title = '{item.title}'\")\n"
            "    await db.execute(f\"SELECT * FROM items LIMIT {item.limit}\")\n"
            "    await db.execute(f\"SELECT * FROM items WHERE owner = '{item.owner}'\")\n\n\n"
            "def save(item: ItemCreate):\n"
            "    db.execute(f\"INSERT INTO items VALUES ('{item.title}')\")\n"),
    })
    assert {(path, line, rule) for path, line, rule, kind in found if rule == "sql-injection"} == {
        ("api.py", 10, "sql-injection"),
        ("api.py", 12, "sql-injection"),
    }


def test_false_alarms_from_the_maintainers_projects(tmp_path):
    """Shapes from the maintainer's own projects that were flagged once route parameters became sources: a function
    nested in a view, a record fetched by the id (get_gif), a video Response, a URL argv element for mpv, a
    secure_filename() path for ffmpeg, md5 for a seed beside a cache_key, and random values put in a dict that isn't
    the session. The real ones beside them stay flagged."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "app.py": (
            'import hashlib\n'
            'import os\n'
            'import random\n'
            'import subprocess\n'
            '\n'
            'import requests\n'
            'from flask import Flask, Response, jsonify, request, session\n'
            'from werkzeug.utils import secure_filename\n'
            '\n'
            'app = Flask(__name__)\n'
            '\n'
            '\n'
            '@app.route("/creator/<username>")\n'
            'def creator(username):\n'
            '    def fetch_all():\n'
            '        return username\n'
            '    return jsonify(fetch_all())\n'
            '\n'
            '\n'
            '@app.route("/thumb/<gif_id>")\n'
            'def thumb(gif_id):\n'
            '    gif = get_gif(gif_id)\n'
            '    requests.get(gif.urls.poster, timeout=10)\n'
            '    requests.get(request.args["url"], timeout=10)\n'
            '    return Response(stream(gif_id), mimetype="video/mp4")\n'
            '\n'
            '\n'
            '@app.route("/page/<name>")\n'
            'def page(name):\n'
            '    return Response(name, mimetype="text/html")\n'
            '\n'
            '\n'
            '@app.route("/play/<video_id>")\n'
            'def play(video_id):\n'
            '    subprocess.Popen(["mpv", f"https://www.youtube.com/watch?v={video_id}"])\n'
            '    os.system(f"curl https://example.com/{video_id}")\n'
            '    upload = secure_filename(request.files["f"].filename)\n'
            '    subprocess.run(["ffmpeg", "-i", os.path.join(UPLOADS, upload)])\n'
            '    return "ok"\n'
            '\n'
            '\n'
            'def round_seed(game):\n'
            '    cache_key = f"round_{game.code}"\n'
            '    game["questions"] = random.choice(QUESTIONS)\n'
            '    return hashlib.md5(cache_key.encode()).hexdigest()\n'
            '\n'
            '\n'
            'def login():\n'
            '    session["token"] = random.random()\n'
            '\n'
            '\n'
            '@app.route("/video/<gif_id>")\n'
            'def video(gif_id):\n'
            '    try:\n'
            '        gif = get_gif(gif_id)\n'
            '    except KeyError:\n'
            '        return "missing"\n'
            '    requests.get(gif.urls.hd, timeout=10)\n'
            '    page = fetch_page(requests.get(request.args["next"], timeout=10).text)\n'
            '    return "ok"\n')})
    # A sink among a lookup's arguments still counts (line 59).
    assert {(line, rule) for path, line, rule, kind in found if kind == "vulnerability"} == {
        (24, "ssrf"), (30, "xss"), (36, "command-injection"), (49, "weak-random-token"), (59, "ssrf"),
    }


def test_request_data_kept_in_fields_and_class_based_views(tmp_path):
    """Plan step 4: request data stored in a field of self/this in one method reaches a sink in another, kept to the
    file that stores it; a field holding a converted value doesn't. Django class-based views read the request from
    self.request and URL captures from self.kwargs."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "views.py": (
            "import os\n"
            "from django.views import View\n\n\n"
            "class Search(View):\n"
            "    def get(self, request):\n"
            "        os.system('grep ' + self.request.GET['q'])\n"
            "        os.system('grep ' + self.kwargs['slug'])\n"
            "        self.term = request.GET['term']\n"
            "        self.count = int(request.GET['n'])\n"
            "        return self.run()\n\n"
            "    def run(self):\n"
            "        os.system('grep ' + self.term)\n"
            "        os.system('head -n %d' % self.count)\n"),
        "other.py": (
            "import os\n\n\n"
            "class Job:\n"
            "    def run(self):\n"
            "        os.system('grep ' + self.term)\n"),
        "search.js": (
            "const { exec } = require('child_process');\n"
            "class Search {\n"
            "  constructor(req) {\n"
            "    this.name = req.query.name;\n"
            "  }\n"
            "  run() {\n"
            "    exec('grep ' + this.name);\n"
            "  }\n"
            "}\n"),
    })
    assert {(path, line) for path, line, rule, kind in found if rule == "command-injection"} == {
        ("views.py", 7), ("views.py", 8), ("views.py", 14), ("search.js", 7),
    }


def test_helpers_that_return_request_data(tmp_path):
    """A call to a function that returns request data is request data where that function is visible; what a helper
    looks up with the request (a user by id) isn't, and neither is a view's response."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "helpers.py": (
            "from flask import request\n\n\n"
            "def get_param(name):\n"
            "    return request.args.get(name)\n\n\n"
            "def get_cmd():\n"
            "    return get_param('cmd')\n\n\n"
            "def current_user():\n"
            "    return User.query.get(request.args['id'])\n"),
        "views.py": (
            "import os\n\nfrom helpers import current_user, get_cmd, get_param\n\n\n"
            "def run():\n"
            "    os.system(get_param('cmd'))\n"
            "    os.system(get_cmd())\n"
            "    os.system('ls ' + current_user().name)\n"),
        "other.py": (
            "import os\n\n\n"
            "def get_param(name):\n"
            "    return name\n\n\n"
            "def run():\n"
            "    os.system(get_param('ls'))\n"),
        # From the OWASP Benchmark for Python: a GET view that returns the POST view's response.
        "pages.py": (
            "from flask import make_response, request\n\n\n"
            "@app.route('/p', methods=['GET'])\n"
            "def page_get():\n"
            "    return page_post()\n\n\n"
            "@app.route('/p', methods=['POST'])\n"
            "def page_post():\n"
            "    name = request.form['name']\n"
            "    response = make_response(('Saved', {'X-Name': name}))\n"
            "    return response\n"),
        # From pygoat: a class-based view's get() isn't what requests.get() calls.
        "challenge.py": (
            "import requests\n\n\n"
            "class Lab(View):\n"
            "    def get(self, request):\n"
            "        return request.GET['name']\n\n\n"
            "def ping():\n"
            "    requests.get(settings.HEALTH_URL, timeout=5)\n"),
        "util.js": (
            "function getName(req) {\n"
            "  return req.query.name;\n"
            "}\n"
            "module.exports = { getName };\n"),
        "app.js": (
            "const { exec } = require('child_process');\n"
            "const { getName } = require('./util');\n"
            "app.get('/a', (req, res) => {\n"
            "  exec('ls ' + getName(req));\n"
            "});\n"),
    })
    assert found == {
        ("views.py", 7, "command-injection", "vulnerability"),
        ("views.py", 8, "command-injection", "vulnerability"),
        ("app.js", 4, "command-injection", "vulnerability"),
    }
