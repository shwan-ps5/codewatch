"""Detection and noise: merged duplicates, token formats, context filters, the typed and cross-file ESLint passes."""
import json
import shutil

import pytest
import yaml

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


def test_match_cases_spanning_lines_become_ifs_too():
    """LightRAG GHSA-v9w6-9hq9-33ch: one `case (\n ".txt"\n | ".md"\n):` left the match unrewritten, and Semgrep
    then lost an upload route's path traversal elsewhere in the file."""
    import ast

    from core.analyzers.match_statements import match_as_if

    source = ("def f(ext, p):\n"
              "    match ext:\n"
              "        case (\n"
              "            '.txt'\n"
              "            | '.md'\n"
              "        ):\n"
              "            y = p\n"
              "        case '.pdf' | (\n"
              "            '.doc'\n"
              "        ) if p:\n"
              "            y = 2\n"
              "    return y\n")
    lines = match_as_if(source).splitlines()
    assert len(lines) == len(source.splitlines())
    assert [lines[i] for i in (2, 5, 7, 9)] == [
        "        if (ext) == ( (", "        )):", "        if (ext) == ( '.pdf' | (", "        )) and (p):"]
    ast.parse(match_as_if(source))


def test_a_registry_finding_in_a_template_script_defers_like_one_in_a_js_file(tmp_path):
    """A registry rule (stood in for here) flags `location.href = '{% url "list" %}?s=' + param` in a template's
    inline script as an open redirect, but the target is a path on the same site. codewatch's own JavaScript
    open-redirect rule judges inline scripts too, so the registry verdict becomes a hotspot as it would in .js."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    (tmp_path / "registry.yml").write_text(yaml.safe_dump({"rules": [{
        "id": "javascript.browser.security.open-redirect.js-open-redirect", "mode": "taint", "severity": "ERROR",
        "languages": ["javascript"], "message": "open redirect",
        "metadata": {"cwe": ["CWE-601: Open Redirect"], "category": "security", "subcategory": ["vuln"]},
        "pattern-sources": [{"pattern": "new URLSearchParams(...).get(...)"}],
        "pattern-sinks": [{"patterns": [{"pattern": "window.location.href = $X"}, {"focus-metavariable": "$X"}]}],
    }]}))
    script = ("const s = new URLSearchParams(window.location.search).get('s');\n"
              "window.location.href = '{% url \"list\" %}?s=' + s;\n")
    (tmp_path / "chart.html").write_text("<p>chart</p>\n<script>\n" + script + "</script>\n")
    (tmp_path / "chart.js").write_text(script.replace('{% url \\"list\\" %}', "/list/"))
    ctx = Context(root=tmp_path, files=["chart.html", "chart.js"], semgrep_config=str(tmp_path / "registry.yml"),
                  custom_rules=catalog.custom_semgrep_rules())
    found = {(f.path, f.type) for f in Semgrep().run(ctx).findings if f.rule.endswith("js-open-redirect")}
    assert found == {("chart.html", "security_hotspot"), ("chart.js", "security_hotspot")}


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


def semgrep_vulnerabilities(tmp_path, files, full_ids=False):
    """{(path, line, rule)} of the vulnerabilities codewatch's rules find in files; rule is the last part of the rule
    id (xss), or the whole id with full_ids (codewatch.python.web.template.xss), where the last part is ambiguous."""
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    ctx = Context(root=tmp_path, files=list(files), semgrep_config="", custom_rules=catalog.custom_semgrep_rules())
    return {(f.path, f.line, f.rule if full_ids else f.rule.rsplit(".", 1)[1]) for f in Semgrep().run(ctx).findings
            if f.type == "vulnerability"}


def test_semgrep_vulnerabilities_keeps_the_full_rule_id_when_asked(tmp_path):
    """Two rules end in .xss: the template rule (codewatch.python.web.template.xss) and the direct one
    (codewatch.python.web.xss). full_ids tells them apart; the default keeps the short name other tests use."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    files = {
        "app/templates/error.html": "<p>{{ error_message|safe }}</p>\n",
        "app/routes.py": (
            "from flask import Flask, render_template, request\n\napp = Flask(__name__)\n\n\n"
            "@app.route('/a')\n"
            "def a():\n"
            "    return render_template('error.html', error_message=request.args['q'])\n\n\n"
            "@app.route('/b')\n"
            "def b():\n"
            "    return request.args['q']\n"),
    }
    assert semgrep_vulnerabilities(tmp_path, files, full_ids=True) == {
        ("app/routes.py", 8, "codewatch.python.web.template.xss"), ("app/routes.py", 13, "codewatch.python.web.xss")}
    assert semgrep_vulnerabilities(tmp_path, files) == {("app/routes.py", 8, "xss"), ("app/routes.py", 13, "xss")}


def test_flask_jinja_templates_are_not_autoescaped(tmp_path):
    """Flask only autoescapes .html/.htm/.xml/.xhtml/.svg; .jinja is raw. The static hotspot reports the raw
    variable, the generated taint rule reports request data passed to it, and |e/.html/Django's render stay quiet."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    files = {
        "app/templates/page.jinja": "<p>{{ name }}</p>\n<p>{{ name|e }}</p>\n",
        "app/templates/page.html": "<p>{{ name }}</p>\n",
        "app/templates/django.jinja": "<p>{{ name }}</p>\n",
        "app/routes.py": (
            "from flask import Flask, render_template, request\n\napp = Flask(__name__)\n\n\n"
            "@app.route('/')\n"
            "def index():\n"
            "    return render_template('page.jinja', name=request.args['name'])\n"),
        "app/django_routes.py": (
            "from django.shortcuts import render\n\n\ndef index(request):\n"
            "    return render(request, 'django.jinja', {'name': request.GET['name']})\n"),
    }
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    ctx = Context(root=tmp_path, files=list(files), semgrep_config="", custom_rules=catalog.custom_semgrep_rules())
    found = {(f.path, f.line, f.rule, f.type) for f in Semgrep().run(ctx).findings}
    assert ("app/templates/page.jinja", 1, "codewatch.templates.not-autoescaped", "security_hotspot") in found
    assert ("app/routes.py", 8, "codewatch.python.web.template.xss", "vulnerability") in found
    assert not any(path == "app/templates/page.jinja" and line == 2 for path, line, *_ in found), "|e escapes it"
    assert not any(path == "app/templates/page.html" for path, *_ in found), ".html is autoescaped"
    assert not any(path == "app/django_routes.py" and rule == "codewatch.python.web.template.xss"
                   and type_ == "vulnerability" for path, _, rule, type_ in found), "Django autoescapes its Jinja"


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


def test_spawn_with_a_shell_joins_its_argument_array(tmp_path):
    """GHSA-79wm-x847-7cvg (claude-code-templates): spawn(cmd, [..., value], { shell: true }) runs value in a shell."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"server.js": (
        "const { spawn } = require('child_process')\n"
        "const cp = require('child_process')\n"
        "app.post('/a', (req, res) => {\n"
        "  const { agentName } = req.body\n"
        "  spawn('npx', ['tool', '--agent', agentName], { cwd: '.', shell: true })\n"
        "  spawn('npx', ['tool', '--agent', agentName], { cwd: '.' })\n"
        "  cp.spawnSync('npx', ['tool', agentName], { shell: true })\n"
        "  if (!/^[A-Za-z0-9._/-]+$/.test(agentName)) return res.status(400).end()\n"
        "  spawn('npx', ['tool', '--agent', agentName], { shell: true })\n"
        "})\n")})
    assert found == {("server.js", 5, "command-injection"), ("server.js", 7, "command-injection")}


def test_sequelize_literal_and_resource_action_params(tmp_path):
    """GHSA-p849-8hwh-84j9 (NocoBase): ctx.action.params is the request's filter, Sequelize.literal() is raw SQL."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"channels.ts": (
        "import { Op, Sequelize } from 'sequelize'\n"
        "export const list = async (ctx) => {\n"
        "  const { filter = {} } = ctx.action?.params ?? {}\n"
        "  const sql = '(SELECT ts FROM messages LIMIT 1)'\n"
        "  const a = Sequelize.literal(`${sql} < ${filter.latest.$lt}`)\n"
        "  const b = Sequelize.where(Sequelize.literal(sql), Op.lt, Number(filter.latest.$lt))\n"
        "  const c = Sequelize.literal(sql)\n"
        "  return [a, b, c]\n"
        "}\n"
        "app.get('/u', (req, res) => {\n"
        "  const { table = 'users' } = req.query\n"
        "  pool.query('SELECT * FROM ' + table)\n"
        "})\n")})
    assert found == {("channels.ts", 5, "sql-injection"), ("channels.ts", 12, "sql-injection")}


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
    # A monorepo's package under another folder (Dagster GHSA-q93c), but not a bare module name anywhere.
    texts["mods/web/server.py"] = "from dagster._core.storage.logs import Manager\n"
    assert visible("mods/web/server.py", {"mods/dagster/dagster/_core/storage/logs.py"}, texts.get)
    assert not visible("mods/web/server.py", {"mods/other/logs.py"}, texts.get)


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
        "def store(password):\n"
        "    return hashlib.new(ALGORITHM, password).hexdigest()\n")})
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
        ("app.py", 30, "path-traversal", "vulnerability"),
        ("app.py", 30, "unrestricted-upload", "security_hotspot"),
        ("upload.js", 3, "unrestricted-upload", "security_hotspot"),
        ("upload.js", 10, "unrestricted-upload", "security_hotspot"),
        ("upload.js", 11, "path-traversal", "vulnerability"),
    }


def test_fastapi_upload_file_names_are_request_data(tmp_path):
    """libre-chat GHSA-3864-rp2m-2qfj (files: List[UploadFile]) and LightRAG GHSA-v9w6-9hq9-33ch: the client's file
    name is joined to a folder and opened for writing. A route parameter typed UploadFile wasn't a source, so only
    the "parameter reaches a sink" hotspot reported it. secure_filename() still clears it, and a function that
    isn't a route stays a hotspot."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "import os\nfrom typing import List\n\nfrom fastapi import APIRouter, File, UploadFile\n"
        "from werkzeug.utils import secure_filename\n\nrouter = APIRouter()\n\n\n"
        "@router.post('/documents')\n"
        "def many(files: List[UploadFile] = File(...)):\n"
        "    for uploaded in files:\n"
        "        if uploaded.filename:\n"
        "            with open(os.path.join('docs', uploaded.filename), 'wb') as out:\n"
        "                out.write(uploaded.file.read())\n\n\n"
        "@router.post('/upload')\n"
        "async def one(file: UploadFile = File(...)):\n"
        "    with open(INPUT_DIR / file.filename, 'wb') as out:\n"
        "        out.write(await file.read())\n"
        "    with open(os.path.join('docs', secure_filename(file.filename)), 'wb') as out:\n"
        "        out.write(await file.read())\n\n\n"
        "def helper(file: UploadFile):\n"
        "    return open(file.filename, 'wb')\n")})
    assert found == {("app.py", 14, "path-traversal"), ("app.py", 20, "path-traversal")}


def test_project_sql_driver_methods_and_a_request_passed_as_req(tmp_path):
    """pgAdmin GHSA-v395-x24j-4r3g: conn.execute_scalar() runs the string it gets, like cursor.execute(). pgAdmin
    GHSA-cr8c-972v-rmp3: the file manager's add(self, req) reads req.form, the request under a short name. A
    parameterised call, an execute_void() on a fixed string and an HTTP client's reply named req stay quiet, and so
    does the Path built only for a relative_to() check (it opens nothing; the open() after it is the sink). That
    check clears the path once the path is normalised first (abspath), as GHSA-cr8c's fix does; the lexical one
    it replaced doesn't."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "import os\nimport pathlib\n\nimport requests\nfrom flask import request\n\n\n"
        "def restore(conn):\n"
        "    name = request.form['value']\n"
        "    conn.execute_scalar(\"SELECT pg_create_restore_point('{0}');\".format(name))\n"
        "    conn.execute_scalar('SELECT pg_create_restore_point(%s);', (name,))\n"
        "    conn.execute_void('SELECT 1')\n\n\n"
        "class FileManager:\n"
        "    def add(self, req=None):\n"
        "        path = req.form.get('currentpath')\n"
        "        try:\n"
        "            pathlib.Path('/data' + path).relative_to('/data')\n"
        "        except ValueError:\n"
        "            return None\n"
        "        with open('/data' + path, 'wb') as f:\n"
        "            f.write(b'')\n\n"
        "    def add_fixed(self, req=None):\n"
        "        path = req.form.get('currentpath')\n"
        "        try:\n"
        "            if SERVER_MODE:\n"
        "                pathlib.Path(os.path.abspath(os.path.join('/data', path))).relative_to('/data')\n"
        "        except ValueError:\n"
        "            return None\n"
        "        with open('/data' + path, 'wb') as f:\n"
        "            f.write(b'')\n\n"
        "    def fetch(self):\n"
        "        req = requests.get('https://api.example.com/x')\n"
        "        with open('/data' + req.json()['name'], 'wb') as f:\n"
        "            f.write(b'')\n")})
    assert found == {("app.py", 10, "sql-injection"), ("app.py", 22, "path-traversal")}


def test_a_named_check_that_replaces_a_redirect_target(tmp_path):
    """pgAdmin GHSA-7r93-vp6c-cw5m's fix: `if nxt is None or not _is_safe_redirect_url(nxt): nxt = url_for(...)`
    leaves nxt safe for the redirect below; a check that only logs doesn't. Flask-Login's login_url() links to the
    app's own login view, whatever goes in its next parameter."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "from flask import Flask, redirect, request, url_for\nfrom flask_login.utils import login_url\n\n"
        "app = Flask(__name__)\n\n\n"
        "@app.route('/v')\n"
        "def validate():\n"
        "    nxt = request.args.get('next', None)\n"
        "    if nxt is None or nxt == url_for('a') or \\\n"
        "            not _is_safe_redirect_url(nxt):\n"
        "        nxt = url_for('index')\n"
        "    if done():\n"
        "        return redirect(nxt)\n"
        "    return redirect(login_url('mfa.validate', next_url=request.args.get('next')))\n\n\n"
        "@app.route('/w')\n"
        "def logged():\n"
        "    nxt = request.args.get('next')\n"
        "    if not is_safe_url(nxt):\n"
        "        log(nxt)\n"
        "    return redirect(nxt)\n")})
    assert found == {("app.py", 23, "open-redirect")}


def test_a_key_presence_check_does_not_clear_the_whole_request(tmp_path):
    """psiturk GHSA-9mq4-9556-6qxq: `if not ('hitId' in request.args and ...): raise` matched the forbidden-
    character guard (`if "'" in name: raise`) with request.args as the checked value, so every request value
    read after it was clean, and mode reached render_template_string() unreported. A real character check on
    a value still clears that value."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "from flask import Flask, render_template_string, request\n\napp = Flask(__name__)\n\n\n"
        "@app.route('/ad')\n"
        "def ad():\n"
        "    if not ('hitId' in request.args and 'assignmentId' in request.args):\n"
        "        raise ValueError('missing')\n"
        "    mode = request.args['mode']\n"
        "    return render_template_string('<p>' + mode + '</p>')\n\n\n"
        "@app.route('/b')\n"
        "def b():\n"
        "    name = request.args['name']\n"
        "    if '{' in name:\n"
        "        raise ValueError('no')\n"
        "    return render_template_string('<p>' + name + '</p>')\n")}, full_ids=True)
    assert {(line, rule.rsplit(".", 1)[1]) for _, line, rule in found} == {(11, "template-injection"), (11, "xss")}


def test_request_values_printed_into_a_link_or_an_event_handler(tmp_path):
    """Formspree GHSA-2wvm-9j4x-757c: <a href="{{ request.args.get('next') }}">. Autoescaping keeps the value
    inside the attribute but doesn't stop a javascript: URL, and in an onclick the escaped quote is decoded back
    before the script runs. A link with a fixed start, a query string value and plain text stay quiet."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"templates/thanks.html": (
        "{% if request.args.get('next') %}\n"
        "  <a href=\"{{ request.args.get('next') }}\" class=\"button\">Back</a>\n"
        "{% endif %}\n"
        "<button onclick=\"go('{{ request.GET.page }}')\">Go</button>\n"
        "<a href=\"/search?q={{ request.args.q }}\">Again</a>\n"
        "<a href=\"{{ url_for('index') }}\">Home</a>\n"
        "<p>{{ request.args.q }}</p>\n")})
    assert {(path, line) for path, line, _ in found} == {("templates/thanks.html", 2), ("templates/thanks.html", 4)}


def test_a_commonpath_containment_check_clears_the_path(tmp_path):
    """SQLBot GHSA-fghj-qqgj-7rxf's fix: the joined path is realpath'd and compared with the base by
    os.path.commonpath, raising when it falls outside. The unchecked join before it stays a finding."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "import os\n\nfrom flask import Flask, request\n\napp = Flask(__name__)\nBASE = '/srv/uploads'\n\n\n"
        "@app.route('/a')\n"
        "def a():\n"
        "    return open(os.path.join(BASE, request.args['f'])).read()\n\n\n"
        "@app.route('/b')\n"
        "def b():\n"
        "    base = os.path.realpath(BASE)\n"
        "    p = os.path.realpath(os.path.join(base, request.args['f']))\n"
        "    if p == base or os.path.commonpath([p, base]) != base:\n"
        "        raise ValueError('outside')\n"
        "    return open(p).read()\n")})
    assert found == {("app.py", 11, "path-traversal")}


def test_inline_scripts_keep_their_lines_and_drop_markup_and_template_tags():
    from core.analyzers.inline_scripts import inline_scripts

    source = ("<p>{{ x }}</p>\n<script src='/a.js'></script>\n<script type='text/template'>{{ y }}</script>\n"
              "<script>\n  var d = {{ items|tojson }};\n  {% if a %}go(d);{% endif %}\n</script>\n")
    lines = inline_scripts(source).split("\n")
    assert len(lines) == len(source.split("\n"))
    assert lines[4] == "  var d = 0                 ;"
    assert lines[5].strip() == "go(d);"
    assert not "".join(lines[:4]).strip()
    assert inline_scripts("<script src='/a.js'></script><p>{{ x }}</p>") is None


def test_dom_xss_in_a_templates_inline_script(tmp_path):
    """Python apps keep much of their JavaScript in <script> blocks of their templates, which the JavaScript rules
    never scanned. The DOM sources (location, a message event) reaching innerHTML or document.write there are now
    found on the template's own lines; textContent stays quiet."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"templates/page.html": (
        "{% extends 'base.html' %}\n"
        "<script>\n"
        "  var data = {{ items|tojson }};\n"
        "  document.getElementById('out').innerHTML = decodeURIComponent(location.hash.slice(1));\n"
        "  window.addEventListener('message', (e) => { document.write(e.data); });\n"
        "  document.getElementById('out').textContent = location.hash;\n"
        "</script>\n")})
    assert found == {("templates/page.html", 4, "xss"), ("templates/page.html", 5, "xss")}


def test_form_field_values_written_into_html(tmp_path):
    """A form field's value is whatever was typed or pasted into it: jQuery's .val() and a looked-up element's
    .value written with .html()/innerHTML run it as markup (calibre-web GHSA-wrp6: an upload's file name into
    $("#upload-format").html(); Modoboa GHSA-c467: $("#id_name").val() into a $span held in a variable). .text(),
    an htmlEncode()d value, .html() of a variable not named like a jQuery object, and the response to a fetch of a
    same-origin path that posted the value (pygoat's comparison lab: the server's reply, not the input) stay quiet.
    A server that fetches a URL from the request and sends the body back is still reported (actual's CORS proxy),
    and so is its passing on the upstream's Content-Type."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"static/js/edit.js": (
        "$('#btn-upload').on('change', function () {\n"
        "    var filename = $(this).val();\n"
        "    $('#upload-format').html(filename);\n"
        "    $('#upload-name').text(filename);\n"
        "});\n"
        "function prefill() {\n"
        "    var $span = $('#id_admin').next('span');\n"
        "    $span.html('@' + $('#id_name').val());\n"
        "    $span.html('@' + htmlEncode($('#id_name').val()));\n"
        "    var doc = parser.parse(text);\n"
        "    doc.html($('#id_name').val());\n"
        "    document.getElementById('out').innerHTML = document.getElementById('q').value;\n"
        "}\n"
        "async function compare() {\n"
        "    const v1 = document.getElementById('version').value;\n"
        "    const response = await fetch('/api/compare', {method: 'POST', body: JSON.stringify({v1})});\n"
        "    const data = await response.json();\n"
        "    document.getElementById('out').innerHTML = data.summary;\n"
        "}\n"),
        "proxy.js": (
            "const express = require('express');\n"
            "const app = express();\n"
            "app.get('/proxy', async (req, res) => {\n"
            "    const response = await fetch(req.query.url);\n"
            "    res.set('Content-Type', response.headers.get('content-type'));\n"
            "    res.send(await response.text());\n"
            "});\n")})
    assert found == {("static/js/edit.js", 3, "xss"), ("static/js/edit.js", 8, "xss"), ("static/js/edit.js", 12, "xss"),
                     ("proxy.js", 4, "ssrf"), ("proxy.js", 5, "xss"), ("proxy.js", 6, "xss")}


def test_mcp_tool_arguments_are_untrusted_input(tmp_path):
    """An MCP server's tool arguments are chosen by a model that any text it reads can steer (Vibe-Trading
    GHSA-mjrq-xg2m-qg94: a run id from @mcp.tool joined into a path). Text-typed parameters only; a checked one and
    a function that isn't a tool stay quiet."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"server.py": (
        "import os\n\nfrom fastmcp import FastMCP\n\nmcp = FastMCP('x')\nRUNS = '/srv/runs'\n\n\n"
        "@mcp.tool\n"
        "def get_run_result(run_id: str) -> str:\n"
        "    return open(os.path.join(RUNS, run_id, 'result.json')).read()\n\n\n"
        "@mcp.tool()\n"
        "async def run_swarm(preset: str, wait_seconds: int = 0) -> str:\n"
        "    return open(os.path.join(RUNS, str(wait_seconds))).read()\n\n\n"
        "@mcp.tool\n"
        "def checked(run_id: str) -> str:\n"
        "    if not run_id.isalnum():\n"
        "        raise ValueError('bad id')\n"
        "    return open(os.path.join(RUNS, run_id)).read()\n\n\n"
        "def helper(run_id: str) -> str:\n"
        "    return open(os.path.join(RUNS, run_id)).read()\n")})
    assert found == {("server.py", 11, "path-traversal")}


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
    The request's own path alone is a review hotspot (`//evil.com` is a valid path); after a host from the query it
    is still an open redirect."""
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
        ("web.js", 6, "open-redirect-path", "security_hotspot"),
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


def test_false_alarms_from_small_flask_apps(tmp_path):
    """Shapes from small Flask apps that were flagged once route parameters became sources: a function
    nested in a view, a record fetched by the id (get_clip), a video Response, a URL argv element for mpv, a
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
            '@app.route("/thumb/<clip_id>")\n'
            'def thumb(clip_id):\n'
            '    clip = get_clip(clip_id)\n'
            '    requests.get(clip.urls.poster, timeout=10)\n'
            '    requests.get(request.args["url"], timeout=10)\n'
            '    return Response(stream(clip_id), mimetype="video/mp4")\n'
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
            '@app.route("/video/<clip_id>")\n'
            'def video(clip_id):\n'
            '    try:\n'
            '        clip = get_clip(clip_id)\n'
            '    except KeyError:\n'
            '        return "missing"\n'
            '    requests.get(clip.urls.hd, timeout=10)\n'
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


def test_checked_values_and_functions_that_dont_return_their_argument(tmp_path):
    """From GHSA-6rmf-cv6p-4h27 (django-termsandconditions) and GHSA-g3cm-qg2v-2hj5 (pyload) at their fixes: a value
    used only where a check said yes, the result of a project function that can't return its argument (it returns
    it only inside `if self.is_safe_url(...)`), and the app's own url_root aren't redirect targets from the
    request. A negated check, a helper that does hand the argument back, and host_url joined with the request
    value still are."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "views.py": (
            "import flask\n"
            "from django.http import HttpResponseRedirect\n"
            "from django.utils.encoding import iri_to_uri\n"
            "from flask import redirect, request, url_for\n"
            "from urllib.parse import urljoin\n\n\n"
            "@app.route('/login')\n"
            "def login():\n"
            "    next_url = request.args.get('next')\n"
            "    if next_url and is_safe_redirect_url(next_url):\n"
            "        return redirect(next_url)\n"
            "    if not is_safe_redirect_url(next_url):\n"
            "        return redirect(next_url)\n"
            "    return redirect(urljoin(flask.request.url_root, url_for('app.' + request.args['page'])))\n\n\n"
            "class Terms(View):\n"
            "    def get_return_to(self, from_dict):\n"
            "        return_to = from_dict.get('returnTo', '/')\n"
            "        if self.is_safe_url(return_to):\n"
            "            return iri_to_uri(return_to)\n"
            "        return '/'\n\n"
            "    def get_next(self, from_dict):\n"
            "        return from_dict.get('next', '/')\n\n"
            "    def post(self, request):\n"
            "        return_url = self.get_return_to(self.request.POST)\n"
            "        next_url = self.get_next(self.request.POST)\n"
            "        if return_url:\n"
            "            return HttpResponseRedirect(return_url)\n"
            "        if next_url:\n"
            "            return HttpResponseRedirect(next_url)\n"
            "        return HttpResponseRedirect(urljoin(request.host_url, request.POST['to']))\n"),
    })
    assert {line for path, line, rule, kind in found if rule == "open-redirect"} == {14, 34, 35}


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


def test_keyword_arguments_to_summarised_functions(tmp_path):
    """A helper whose `path` parameter reaches open() is a sink when called with path=..., by position, or through
    a wrapper; passing request data as its harmless `mode`, or as another summarised function's keyword, isn't."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "files.py": (
            "def read(path, mode='r'):\n"
            "    with open(path, 'r') as f:\n"
            "        return f.read()\n\n\n"
            "def read_named(name, path='/srv/data'):\n"
            "    with open('/srv/' + name, 'r') as f:\n"
            "        return f.read()\n"),
        "views.py": (
            "from flask import request\n\nfrom files import read, read_named\n\n\n"
            "@app.route('/a')\n"
            "def a():\n"
            "    read(path=request.args['p'])\n"
            "    read('/srv/x', mode=request.args['m'])\n"
            "    read(request.args['q'])\n"
            "    read_named('x', path=request.args['n'])\n"
            "    read_named(name=request.args['n'])\n"
            "    return ''\n"),
    })
    assert {line for path, line, rule, kind in found
            if path == "views.py" and rule == "path-traversal" and kind == "vulnerability"} == {8, 10, 12}


def test_js_redirects_within_the_site_are_not_open(tmp_path):
    """outline and node-express-mongoose-demo: the request's own path, a fixed relative prefix or a value after "?"
    keep a redirect on the site; the path alone is a hotspot ("//host"). Driven by ordinary apps, not a suite."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {"routes.ts": (
        "router.use(['/share/:id'], (ctx) => {\n"
        "  ctx.redirect(ctx.path.replace(/^\\/share/, '/s') + ctx.request.URL.search)\n"
        "})\n"
        "router.get('/b', async (ctx) => {\n"
        "  ctx.redirect(`/?notice=auth-error&description=${ctx.query.error}`)\n"
        "  ctx.redirect(`/auth/${ctx.query.provider}`)\n"
        "  ctx.redirect(await getValidatedHost(ctx.query.host))\n"
        "  ctx.redirect(`https://www.${ctx.headers.host}${ctx.path}`)\n"
        "  ctx.redirect(ctx.query.next)\n"
        "  ctx.redirect('/' + ctx.query.next)\n"
        "  ctx.redirect(`//${ctx.query.next}`)\n"
        "})\n")})
    assert found == {("routes.ts", 2, "open-redirect-path", "security_hotspot"),
                     ("routes.ts", 9, "open-redirect", "vulnerability"),
                     ("routes.ts", 10, "open-redirect", "vulnerability"),
                     ("routes.ts", 11, "open-redirect", "vulnerability")}


def test_js_ssrf_to_a_fixed_host_and_stack_traces_dropped_outside_development(tmp_path):
    """proshop-v2: `${PAYPAL_API_URL}/v2/checkout/orders/${id}` can't leave PayPal. express-rest-boilerplate:
    the stack is deleted from the response unless in development."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"server.js": (
        "app.get('/a', (req, res) => {\n"
        "  fetch(`${PAYPAL_API_URL}/v2/orders/${req.body.id}`)\n"
        "  fetch(`https://api.example.com/v1/${req.query.id}`)\n"
        "  fetch('https://api.example.com/' + req.query.id)\n"
        "  fetch(`${req.query.base}/v2/orders`)\n"
        "  fetch(`https://${req.query.host}/x`)\n"
        "})\n"
        "const handler = (err, req, res, next) => {\n"
        "  const response = { message: err.message, stack: err.stack }\n"
        "  if (env !== 'development') {\n"
        "    delete response.stack\n"
        "  }\n"
        "  res.json(response)\n"
        "}\n"
        "const leaky = (err, req, res, next) => {\n"
        "  const response = { message: err.message, stack: err.stack }\n"
        "  res.json(response)\n"
        "}\n")})
    assert found == {("server.js", 5, "ssrf"), ("server.js", 6, "ssrf"), ("server.js", 17, "stack-trace-exposure")}


def test_returner_calls_and_handlers_in_javascript(tmp_path):
    """outline: one class's perform() returns request data and another's runs its argument, so a perform() call
    was both source and sink of itself; and a Koa handler's return (`return renderShare(ctx, next)`) isn't data."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"actions.js": (
        "const { exec } = require('child_process')\n"
        "const app = require('express')()\n"
        "class Notify {\n"
        "  perform(event) {\n"
        "    exec('notify ' + event.cmd)\n"
        "  }\n"
        "}\n"
        "class Share {\n"
        "  perform(req) {\n"
        "    return req.query.share\n"
        "  }\n"
        "}\n"
        "const share = new Share()\n"
        "const renderShare = async (req, res, next) => {\n"
        "  return req.params.id\n"
        "}\n"
        "app.get('/x', async (req, res, next) => {\n"
        "  res.json(share.perform(res.locals))\n"
        "  exec(await renderShare(req, res, next))\n"
        "  exec(share.perform(req))\n"
        "})\n")})
    assert found == {("actions.js", 20, "command-injection")}


def test_sqlalchemy_statements_and_safe_redirect_helpers(tmp_path):
    """flaskbb: sa.select(...).where(...) binds its values (dispatch: so does db_session.query(...).filter(...));
    get_first_safe_redirect_url() returns an allowed URL."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {
        "http.py": (
            "def get_safe_redirect_url(url, allowed_hosts, fallback):\n"
            "    return url if url and url.startswith('/') and not url.startswith('//') else fallback\n"),
        "app.py": (
            "import sqlalchemy as sa\nfrom flask import Flask, redirect, request\n\nfrom http import get_safe_redirect_url\n"
            "app = Flask(__name__)\n\n\n"
            "@app.route('/t')\n"
            "def topics():\n"
            "    ids = request.form.getlist('rowid')\n"
            "    db.session.execute(sa.select(Topic).filter(Topic.id.in_(ids))).scalars().all()\n"
            "    term = request.args.get('q')\n"
            "    db.session.execute(sa.select(Topic.name).where(Topic.name.ilike(f'{term}%')).limit(10))\n"
            "    db_session.execute(db_session.query(Topic.id).filter(Topic.name == term).as_scalar()).fetchone()\n"
            "    db.session.execute(sa.text(\"SELECT * FROM t WHERE name = '\" + term + \"'\"))\n"
            "    return redirect(get_safe_redirect_url(request.args.get('next'), ['x'], '/'))\n\n\n"
            "@app.route('/u')\n"
            "def unsafe():\n"
            "    return redirect(request.args.get('next'))\n")})
    assert found == {("app.py", 15, "sql-injection"), ("app.py", 21, "open-redirect")}


def test_the_crypto_module_name_is_not_a_security_purpose():
    """outline: an ETag from crypto.createHash('md5') was a weak-hash verdict because of the word "crypto"."""
    from core.analyzers.python_tools import SECURITY_PURPOSE_RE
    assert not SECURITY_PURPOSE_RE.search("res.setHeader('ETag', crypto.createHash('md5').update(m).digest('hex'))")
    for text in ("const encrypted = encrypt(data)", "bcrypt.hash(password)", "from cryptography import x"):
        assert SECURITY_PURPOSE_RE.search(text), text


def test_what_a_javascript_helper_looks_up_is_stored_data(tmp_path):
    """outline: ctx.redirect(share.canonicalUrl) after `const result = await loadPublicShare({id: ctx.params...})`
    redirects to the stored share's URL. A lookup inline in the sink, a request-shaped name and a helper the
    returner pass finds returning request data still count."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"routes.js": (
        "const app = require('express')()\n"
        "function loadCurrent(req) {\n"
        "  return req.query.next\n"
        "}\n"
        "app.get('/s/:id', async (req, res) => {\n"
        "  const result = await loadPublicShare({ id: req.params.id })\n"
        "  const share = result.share\n"
        "  res.redirect(share.canonicalUrl)\n"
        "})\n"
        "app.get('/a', async (req, res) => {\n"
        "  res.redirect(await loadShare(req.query.id))\n"
        "})\n"
        "app.get('/b', async (req, res) => {\n"
        "  const target = await getRedirectTarget(req.query.next)\n"
        "  res.redirect(target)\n"
        "})\n"
        "app.get('/c', (req, res) => {\n"
        "  const next = loadCurrent(req)\n"
        "  res.redirect(next)\n"
        "})\n")})
    assert found == {("routes.js", 11, "open-redirect"), ("routes.js", 15, "open-redirect"),
                     ("routes.js", 19, "open-redirect")}


def test_signed_in_user_model_metadata_and_compiled_django_sql(tmp_path):
    """taiga: request.user.id, qs.model._meta.db_table and queryset.query.where.as_sql(...) formatted into SQL are
    the server's data or placeholders (wger: _meta.db_table quoted as a value too). A request parameter,
    str(queryset.query) or another quoted value formatted the same way isn't."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"views.py": (
        "from django.db import connection\n\n\n"
        "def watched(request):\n"
        "    sql = 'SELECT * FROM w WHERE user_id = {}'.format(request.user.id)\n"
        "    connection.cursor().execute(sql)\n\n\n"
        "def contacts(request, qs):\n"
        "    qs = qs.exclude(projects__id=request.GET.get('p'))\n"
        "    table = qs.model._meta.db_table\n"
        "    qs = qs.extra(where=['{}.name @@ %s'.format(table)], params=[request.GET.get('q')])\n"
        "    return qs\n\n\n"
        "def counts(request, queryset):\n"
        "    queryset = queryset.filter(name=request.GET.get('name'))\n"
        "    compiler = connection.ops.compiler(queryset.query.compiler)(queryset.query, connection, None)\n"
        "    where, params = queryset.query.where.as_sql(compiler, connection)\n"
        "    connection.cursor().execute('SELECT count(*) FROM t WHERE ' + where, params)\n"
        "    connection.cursor().execute('SELECT count(*) FROM (%s) q' % str(queryset.query))\n"
        "    connection.cursor().execute('SELECT * FROM t WHERE name = %s' % request.GET.get('name'))\n\n\n"
        "def approximate(self, cursor):\n"
        "    cursor.execute(\"SELECT reltuples FROM pg_class WHERE relname = '%s'\" % self.model._meta.db_table)\n"
        "    cursor.execute(\"SELECT 1 FROM t WHERE name = '%s'\" % self.name)\n")})
    assert found == {("views.py", 21, "sql-injection"), ("views.py", 22, "sql-injection"),
                     ("views.py", 27, "sql-value-formatting")}


def test_view_actions_builtins_and_orm_chains_are_not_returner_calls(tmp_path):
    """taiga: DRF's ViewSet.list/create returned request data, so every bare list(...) and every
    Project.objects.create(...) became a source; a view returning response.Ok(...) isn't data for a caller.
    A real helper and a call on self still count."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"views.py": (
        "from django.db import connection\n"
        "from rest_framework.response import Response\n\n\n"
        "class ProjectViewSet:\n"
        "    def list(self, request):\n"
        "        return request.GET.get('q')\n\n"
        "    def create(self, request):\n"
        "        return request.data.get('name')\n\n"
        "    def retrieve(self, request):\n"
        "        return Response(request.GET.get('id'))\n\n"
        "    def other(self, request):\n"
        "        connection.cursor().execute('SELECT 1 WHERE n = ' + self.create(request))\n\n\n"
        "def names(tags):\n"
        "    unique = list(set(tags))\n"
        "    connection.cursor().execute('SELECT 1 WHERE t = ' + unique[0])\n\n\n"
        "def store(Project):\n"
        "    project = Project.objects.create(name='x')\n"
        "    connection.cursor().execute('SELECT 1 WHERE s = ' + project.slug)\n\n\n"
        "def shown(view):\n"
        "    connection.cursor().execute('SELECT 1 WHERE r = ' + view.retrieve(None).data)\n")})
    assert found == {("views.py", 16, "sql-injection")}


def test_django_redirect_replaced_after_a_failed_check_and_reverse(tmp_path):
    """wger: `if not url_has_allowed_host_and_scheme(next_url, ...): next_url = reverse(...)` leaves a checked URL
    or the replacement; reverse() and get_absolute_url() are this site's own. A check that only logs, or a
    replacement under a positive check, isn't."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"views.py": (
        "import logging\n"
        "from django.http import HttpResponseRedirect\n"
        "from django.shortcuts import redirect\n"
        "from django.urls import reverse\n"
        "from django.utils.http import url_has_allowed_host_and_scheme\n\n\n"
        "def login_next(request):\n"
        "    next_url = request.GET.get('next')\n"
        "    if not next_url or not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):\n"
        "        next_url = reverse('core:dashboard')\n"
        "    return redirect(next_url)\n\n\n"
        "def copy(request, Routine):\n"
        "    routine = Routine.objects.get(pk=request.GET.get('pk'))\n"
        "    return HttpResponseRedirect(routine.get_absolute_url())\n\n\n"
        "def gym(request):\n"
        "    return HttpResponseRedirect(reverse('gym:user-list', kwargs={'pk': request.GET.get('gym')}))\n\n\n"
        "def logged(request):\n"
        "    next_url = request.GET.get('next')\n"
        "    if not url_has_allowed_host_and_scheme(next_url, allowed_hosts=None):\n"
        "        logging.warning('odd next %s', next_url)\n"
        "    return redirect(next_url)\n\n\n"
        "def flipped(request):\n"
        "    next_url = request.GET.get('next')\n"
        "    if url_has_allowed_host_and_scheme(next_url, allowed_hosts=None):\n"
        "        next_url = next_url.strip()\n"
        "    return redirect(next_url)\n")})
    assert found == {("views.py", 28, "open-redirect"), ("views.py", 35, "open-redirect")}


def test_sql_value_formatting_skips_migrations_and_constant_identifiers(tmp_path):
    """dispatch: Alembic's upgrade()/downgrade() and env.py's run_migrations_online() rewrite the app's own rows or
    schemas, and `set search_path to
    "{CORE_SCHEMA_NAME}"` names a schema from a constant. Django's migrations folders are skipped too."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {
        "versions/2021_add_slug.py": (
            "from alembic import op\n\n\n"
            "def upgrade():\n"
            "    conn = op.get_bind()\n"
            "    for r in conn.execute('select id, name from org').fetchall():\n"
            "        conn.execute(f\"update org set slug = '{r[1]}' where id = {r[0]}\")\n\n\n"
            "def downgrade():\n"
            "    conn = op.get_bind()\n"
            "    for r in conn.execute('select id, name from org').fetchall():\n"
            "        conn.execute(f\"update org set slug = '{r[1].lower()}' where id = {r[0]}\")\n"),
        "revisions/env.py": (
            "def run_migrations_online():\n"
            "    for schema in get_tenant_schemas(connection):\n"
            "        connection.execute(text(f'set search_path to \"{schema}\"'))\n"),
        "app/migrations/0002_fill.py": (
            "def fill(apps, schema_editor):\n"
            "    for r in rows:\n"
            "        schema_editor.execute(f\"update t set n = '{r.name}'\")\n"),
        "db.py": (
            "CORE_SCHEMA_NAME = 'core'\n\n\n"
            "def migrate(connection, name):\n"
            "    connection.execute(f'set search_path to \"{CORE_SCHEMA_NAME}\"')\n"
            "    connection.execute(f\"select 1 from org where name = '{name}'\")\n"),
    })
    assert found == {("db.py", 6, "sql-value-formatting")}


def test_a_generated_username_is_not_a_secret(tmp_path):
    """linkwarden: an auth callback's `"user" + Math.round(Math.random() * 1e9)` username is a display value; a code
    in the same function, and a token-making function's variable, are still secrets."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"auth.ts": (
        "async function authorize(user) {\n"
        "  const autoGeneratedUsername =\n"
        "    'user' + Math.round(Math.random() * 1000000000);\n"
        "  await prisma.user.create({ data: { username: 'user' + Math.round(Math.random() * 1e9) } });\n"
        "  const resetCode = Math.random().toString(36);\n"
        "  return { autoGeneratedUsername, resetCode };\n"
        "}\n"
        "function makeToken() {\n"
        "  const t = Math.random().toString(36);\n"
        "  return t;\n"
        "}\n")})
    assert found == {("auth.ts", 5, "weak-random-secret"), ("auth.ts", 9, "weak-random-secret")}


def test_host_headers_and_request_option_paths(tmp_path):
    """linkwarden: an RSS feed's site_url from req.headers.host and X-Forwarded-Proto isn't XSS (a victim's browser
    sends the real host; a proxy sets the rest), and an http.request to a checked IP with the request's path and
    headers isn't SSRF. A request-chosen host or URL, a query value and other headers still are."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"proxy.js": (
        "const http = require('http');\n"
        "const axios = require('axios');\n"
        "function handle(req, res) {\n"
        "  const target = new URL(req.url || '');\n"
        "  resolvePinned(target.hostname).then((ip) => {\n"
        "    http.request({ host: ip, path: target.pathname + target.search, headers: { ...req.headers } });\n"
        "  });\n"
        "  http.request({ host: target.hostname, path: '/' });\n"
        "  http.get(req.query.url);\n"
        "  axios.request({ url: req.query.url });\n"
        "}\n"
        "function feed(req, res) {\n"
        "  const host = req.headers.host;\n"
        "  const protocol = req.headers['x-forwarded-proto'] || 'https';\n"
        "  res.write(`<a href=\"${protocol}://${host}/feed\">feed</a>`);\n"
        "  res.write(`<p>${req.query.name}</p>`);\n"
        "  res.write(`<p>${req.headers['user-agent']}</p>`);\n"
        "}\n")})
    assert found == {("proxy.js", 8, "ssrf"), ("proxy.js", 9, "ssrf"), ("proxy.js", 10, "ssrf"),
                     ("proxy.js", 16, "xss"), ("proxy.js", 17, "xss")}


def test_a_javascript_hash_is_judged_by_its_own_function():
    """immich: hashSha1() for file checksums sat within ten lines of a signature check, so its SHA-1 was a
    weak-hash verdict. The enclosing function decides, walking through if/for blocks to the handler."""
    from core.analyzers.python_tools import SECURITY_PURPOSE_RE, enclosing_function_text
    rows = (
        "class CryptoRepository {\n"
        "  verifySha256(value, signature, key) {\n"
        "    return verifier.verify(key, signature);\n"
        "  }\n"
        "\n"
        "  hashSha1(value) {\n"
        "    return createHash('sha1').update(value).digest();\n"
        "  }\n"
        "}\n"
        "app.post('/login', (req, res) => {\n"
        "  const pw = req.body.password;\n"
        "  if (pw) {\n"
        "    const h = md5(pw);\n"
        "  }\n"
        "});\n"
        "const utils = {\n"
        "  token: () => randomBytes(16),\n"
        "  sha1: (bytes) => createHash('sha1').update(bytes).digest('base64'),\n"
        "};\n").splitlines()

    def about_security(line):
        return bool(SECURITY_PURPOSE_RE.search(enclosing_function_text(rows, line, 10)))

    assert not about_security(7)
    assert about_security(13)
    assert not about_security(18)


def test_a_request_getter_argument_is_not_request_data(tmp_path):
    """immich: with the incoming request named `request`, `request.header('accept')` matched the request library's
    request.$METHOD(url) sink around its own argument, and Semgrep resolved fromMaybeArray imported from the project's
    utils/request module as request.fromMaybeArray. The library called with request data is still SSRF."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"guard.ts": (
        "import request from 'request';\n"
        "export const Details = createParamDecorator((data, context) => {\n"
        "  const request = context.switchToHttp().getRequest();\n"
        "  throw new Error(`was requested as ${request.header('accept')}`);\n"
        "});\n"
        "function proxy(req, res) {\n"
        "  request.get(req.query.url);\n"
        "}\n"),
        "utils/request.ts": "export const fromMaybeArray = (v) => (Array.isArray(v) ? v[0] : v);\n",
        "interceptor.ts": (
            "import { fromMaybeArray } from './utils/request';\n"
            "export class Interceptor {\n"
            "  async intercept(context) {\n"
            "    const req = context.switchToHttp().getRequest();\n"
            "    return fromMaybeArray(req.headers['x-immich-checksum']);\n"
            "  }\n"
            "}\n")})
    assert found == {("guard.ts", 7, "ssrf")}


def test_orm_rows_and_self_lookups_are_stored_data(tmp_path):
    """paperless-ngx, CTFd, recipes: a row an ORM query runs to (Users.query.filter_by(...).first(),
    manager.only(...).filter(id=v).first()) and what a `self._get_X()` method looks up are the database's, not the
    request's. A helper that hands back the request's data (self.get_serializer) and a raw value still count."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "import os\n"
        "from flask import Flask, request, send_file\n"
        "from models import Document, Users, manager\n\n"
        "app = Flask(__name__)\n\n\n"
        "class Docs:\n"
        "    def show(self):\n"
        "        doc = self._get_effective_doc(request.args['id'])\n"
        "        return send_file(doc.source_path)\n\n"
        "    def form(self):\n"
        "        data = self.get_serializer(request.args['path'])\n"
        "        return send_file(data)\n\n\n"
        "def resolve():\n"
        "    return manager.only('id').filter(id=request.args.get('v')).first()\n\n\n"
        "@app.route('/rows')\n"
        "def rows():\n"
        "    row = Document.query.filter_by(id=request.args['id']).first()\n"
        "    user, created = Users.objects.get_or_create(name=request.args['name'])\n"
        "    version = resolve()\n"
        "    return send_file(os.path.join(row.path, user.path, version.path))\n\n\n"
        "@app.route('/plain')\n"
        "def plain():\n"
        "    return send_file(request.args['path'])\n\n\n"
        "@app.route('/rules')\n"
        "def rules():\n"
        "    import mimetypes\n"
        "    for rule in Document.objects.filter(owner=request.args['o']).only('path')[:10]:\n"
        "        send_file(rule.path)\n"
        "    return send_file('/data/upload' + mimetypes.guess_extension(request.args['type']))\n")})
    assert found == {("app.py", 15, "path-traversal"), ("app.py", 32, "path-traversal")}


def test_site_urls_session_ids_equal_values_and_plain_text(tmp_path):
    """recipes: a route's URL followed by text that doesn't start with "/" stays on the site; CTFd: a new user's
    id and password HMAC in the session, a value that must equal a known one or abort, a response re-typed as
    text/plain, a cookie whose Secure flag comes from config, and a statement built from a model's __table__."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {
        "views.py": (
            "from django.http import HttpResponse, HttpResponseRedirect\n"
            "from django.urls import reverse\n\n\n"
            "def build_absolute_uri(request, path):\n"
            "    return request.build_absolute_uri(path)\n\n\n"
            "def recipe(request):\n"
            "    pk = request.GET.get('pk')\n"
            "    return HttpResponseRedirect(build_absolute_uri(request, reverse('index')) + f'recipe/{pk}')\n\n\n"
            "def login(request):\n"
            "    return HttpResponseRedirect(reverse('account_login') + '?next=' + request.GET.get('next', '/'))\n\n\n"
            "def slash(request):\n"
            "    return HttpResponseRedirect(reverse('index') + request.GET.get('to'))\n\n\n"
            "def export(request):\n"
            "    return HttpResponse(request.GET.get('csv'), content_type='application/force-download')\n"),
        "app.py": (
            "from flask import Flask, abort, make_response, redirect, request, session\n"
            "from models import Pages, Users, db, hmac, mac\n\n"
            "app = Flask(__name__)\n\n\n"
            "def login_user(user):\n"
            "    session['id'] = user.id\n"
            "    session['hash'] = hmac(user.password)\n\n\n"
            "@app.route('/register', methods=['POST'])\n"
            "def register():\n"
            "    user = Users(name=request.form['name'], password=request.form['password'])\n"
            "    login_user(user)\n"
            "    session['name'] = request.form['name']\n"
            "    return redirect(app.config['ROOT'] + request.script_root + request.full_path)\n\n\n"
            "@app.route('/share')\n"
            "def share():\n"
            "    name = request.args['name']\n"
            "    if name != mac() + '.png':\n"
            "        abort(404)\n"
            "    return make_response(name)\n\n\n"
            "@app.route('/echo')\n"
            "def echo():\n"
            "    resp = make_response(request.args['q'])\n"
            "    resp.mimetype = 'text/plain'\n"
            "    return resp\n\n\n"
            "@app.route('/echo2')\n"
            "def echo2():\n"
            "    return make_response(request.args['q'])\n\n\n"
            "@app.route('/cookie')\n"
            "def cookie():\n"
            "    r = make_response('x')\n"
            "    r.set_cookie('sid', 'v', secure=app.config['SECURE'], httponly=True)\n"
            "    r.set_cookie('a', 'v')\n"
            "    r.set_cookie('b', 'v', secure=False)\n"
            "    return r\n\n\n"
            "def get_page(route):\n"
            "    return db.session.execute(Pages.__table__.select().where(Pages.route == route)).fetchone()\n\n\n"
            "@app.route('/page')\n"
            "def page():\n"
            "    db.session.execute(\"select * from pages where route = '%s'\" % request.args['r'])\n"
            "    get_page(request.args['r'])\n"
            "    return 'ok'\n\n\n"
            "@app.route('/again', methods=['POST'])\n"
            "def again():\n"
            "    name = request.form['name']\n"
            "    repeated = request.form['again']\n"
            "    if name != repeated:\n"
            "        abort(400)\n"
            "    return make_response(name)\n")})
    # vulpy: two request values compared (password != password_again) check nothing about either.
    assert found == {("views.py", 19, "open-redirect"), ("app.py", 16, "trust-boundary"),
                     ("app.py", 37, "xss"), ("app.py", 44, "insecure-cookie"), ("app.py", 45, "insecure-cookie"),
                     ("app.py", 55, "sql-injection"), ("app.py", 55, "sql-value-formatting"), ("app.py", 66, "xss")}


def test_same_page_jumps_and_the_configured_root_are_not_open_redirects(tmp_path):
    """CTFd: the page's own address up to its fragment plus a new fragment, and the configured base URL plus a
    fixed path, stay on the site. The origin alone doesn't: "@evil.example" appended changes the host."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"challenges.js": (
        "function preview() {\n"
        "  window.location.replace(window.location.href.split('#')[0] + '#' + location.hash.substring(1));\n"
        "}\n"
        "function login() {\n"
        "  window.location = CTFd.config.urlRoot + '/login?next=' + window.location.hash.substring(1);\n"
        "}\n"
        "function login2() {\n"
        "  window.location = `${CTFd.config.urlRoot}/login?next=${window.location.hash.substring(1)}`;\n"
        "}\n"
        "function jump() {\n"
        "  window.location = location.hash.substring(1);\n"
        "}\n"
        "function origin() {\n"
        "  window.location = location.origin + location.hash.substring(1);\n"
        "}\n"
        "function chain() {\n"
        "  window.location = CTFd.config.urlRoot + '/login?next=' + CTFd.config.urlRoot + location.pathname + location.hash;\n"
        "}\n"
        "function first() {\n"
        "  window.location = location.hash.substring(1) + CTFd.config.urlRoot + '/login?next=' + location.hash;\n"
        "}\n")})
    assert found == {("challenges.js", 11, "open-redirect"), ("challenges.js", 14, "open-redirect"),
                     ("challenges.js", 20, "open-redirect")}


def test_arguments_a_helper_does_not_hand_back_are_not_its_result(tmp_path):
    """paperless-ngx: a view passes its request three helpers deep, where only a version number is read from it to
    look a document up (and whether one was asked for, to a helper that hands nothing back); the document is the
    database's. Pass-through is per parameter: a helper that returns its
    first argument still taints its result through that one, by position or keyword."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {
        "versioning.py": (
            "from documents.models import Document\n\n\n"
            "def get_request_version_param(request):\n"
            "    return request.query_params.get('version')\n\n\n"
            "def _document_manager(*, include_deleted=False):\n"
            "    log.debug('deleted too: %s', include_deleted)\n"
            "    return Document.objects\n\n\n"
            "def resolve_version(root_doc, request, *, include_deleted=False):\n"
            "    version_param = get_request_version_param(request)\n"
            "    if not version_param:\n"
            "        return latest_version(root_doc)\n"
            "    version_id = int(version_param)\n"
            "    manager = _document_manager(include_deleted=include_deleted)\n"
            "    return manager.only('id').filter(id=version_id).first()\n"),
        "views.py": (
            "from pathlib import Path\n"
            "from rest_framework.viewsets import ModelViewSet\n"
            "from versioning import get_request_version_param, resolve_version\n\n\n"
            "class DocumentViewSet(ModelViewSet):\n"
            "    def _resolve_file_doc(self, root_doc, request):\n"
            "        requested = get_request_version_param(request) is not None\n"
            "        return resolve_version(root_doc, request, include_deleted=requested)\n"
            "    def _effective_doc(self, request_doc, root_doc, request):\n"
            "        if request_doc.root_id is not None and get_request_version_param(request) is None:\n"
            "            return request_doc\n"
            "        return self._resolve_file_doc(root_doc, request)\n\n"
            "    def metadata(self, request, pk=None):\n"
            "        doc = self._effective_doc(self.get_object(), None, request)\n"
            "        return {'size': Path(doc.source_path).stat().st_size}\n\n"
            "    def raw(self, request, pk=None):\n"
            "        doc = self._effective_doc(request.query_params['doc'], None, request)\n"
            "        named = self._effective_doc(root_doc=None, request=request, request_doc=request.data['p'])\n"
            "        first = open(doc.source_path).read()\n"
            "        return first + open(named).read()\n\n"
            "    def counted(self, request):\n"
            "        return self._count(None, open(request.data['f']).read())\n\n"
            "    def _count(self, doc, text):\n"
            "        self.total += 1\n"
            "        return doc\n")})
    # An argument that holds a sink keeps it (OWASP Benchmark: escape_for_html(p.read_text()[:1000])).
    assert found == {("views.py", 22, "path-traversal"), ("views.py", 23, "path-traversal"),
                     ("views.py", 26, "path-traversal")}


def test_a_weak_hash_of_a_secret_is_not_a_password_hash():
    """outline: an account-deletion code is MD5 of the user's JWT secret; a token or code derived from a secret
    keeps it (MD5 preimages are out of reach), unlike a stored password or a signature, where speed or collisions
    break it. Such a hash is for review, not a verdict."""
    from core.analyzers.python_tools import SECURITY_PURPOSE_RE
    for text in ("get deleteConfirmationCode() { return crypto.createHash('md5').update(this.jwtSecret)",
                 "def unsubscribe_token(email): return hashlib.sha1(email + settings.SECRET_KEY)",
                 "def otp(key): return hmac.new(key, counter, hashlib.sha1)"):
        assert not SECURITY_PURPOSE_RE.search(text), text
    for text in ("def store(password): hashlib.md5(password)", "def verify_signature(data, sig)",
                 "certificate_matches(certificate, known_hash)", "hashed = md5(salt + pw)"):
        assert SECURITY_PURPOSE_RE.search(text), text


def test_prompt_templates_are_not_html(tmp_path):
    """paperless-ngx: LLM prompts rendered by a Jinja environment with autoescape off, loaded from a "prompts"
    folder. A templates folder still counts."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"render.py": (
        "from jinja2 import Environment, FileSystemLoader, PackageLoader\n\n"
        "prompts = Environment(loader=PackageLoader('paperless_ai', 'prompts'), autoescape=False)\n"
        "queries = Environment(loader=FileSystemLoader('sql_templates'), autoescape=False)\n"
        "pages = Environment(loader=PackageLoader('site', 'templates'), autoescape=False)\n")})
    assert found == {("render.py", 5, "template-autoescape-disabled")}


def test_a_value_checked_for_quotes_is_not_sql_value_formatting(tmp_path):
    """CTFd: a table name formatted between quotes only after `if '"' not in name and "'" not in name`."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"exports.py": (
        "def reset(db, table_name):\n"
        "    if '\"' not in table_name and \"'\" not in table_name:\n"
        "        db.execute(\"SELECT setval('{t}', 1) FROM x\".format(t=table_name))\n"
        "    db.execute(\"SELECT setval('{t}', 1) FROM x\".format(t=table_name))\n")})
    assert found == {("exports.py", 4, "sql-value-formatting")}


def test_a_regex_with_a_timeout_is_not_regex_injection(tmp_path):
    """recipes: users' own automation patterns, matched with the regex module's timeout, which bounds ReDoS."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "import re\nimport regex\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
        "@app.route('/replace')\n"
        "def replace():\n"
        "    pattern = request.args['p']\n"
        "    text = regex.sub(pattern, '', request.args['t'], timeout=1)\n"
        "    counts = [regex.sub(pattern, '', text), re.sub(pattern, '', text)]\n"
        "    return str(len(counts))\n")})
    assert found == {("app.py", 12, "regex-injection")}


def test_a_path_name_or_extension_is_not_a_file_opened(tmp_path):
    """paperless-ngx: Path(str(document.filename)).suffix reads the extension; nothing is opened."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "from pathlib import Path\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
        "@app.route('/ext')\n"
        "def ext():\n"
        "    name = request.args['f']\n"
        "    kind = Path(name).suffix + Path(name).stem\n"
        "    Path(name).stat()\n"
        "    return 'ok' if kind else 'no'\n")})
    assert found == {("app.py", 11, "path-traversal")}


def test_a_named_check_that_ends_the_request_guards_what_follows(tmp_path):
    """Django's idiom, `if not url_has_allowed_host_and_scheme(nxt, ...): abort(400)`, and a project's own
    `is_safe_url` with an early return, clear what follows; the branch where the check said no doesn't."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "from django.utils.http import url_has_allowed_host_and_scheme\n"
        "from flask import Flask, abort, redirect, request\n\napp = Flask(__name__)\n\n\n"
        "def is_safe_url(target):\n"
        "    return target.startswith('/') and not target.startswith('//')\n\n\n"
        "@app.route('/a')\n"
        "def a():\n"
        "    nxt = request.args['next']\n"
        "    if not url_has_allowed_host_and_scheme(nxt, allowed_hosts=None):\n"
        "        abort(400)\n"
        "    return redirect(nxt)\n\n\n"
        "@app.route('/b')\n"
        "def b():\n"
        "    nxt = request.args['next']\n"
        "    if not is_safe_url(nxt):\n"
        "        return redirect(nxt)\n"
        "    return redirect(nxt)\n\n\n"
        "@app.route('/c')\n"
        "def c():\n"
        "    nxt = request.args['next']\n"
        "    if not nxt:\n"
        "        abort(400)\n"
        "    return redirect(nxt)\n")})
    assert found == {("app.py", 23, "open-redirect"), ("app.py", 32, "open-redirect")}


def test_a_javascript_helper_that_never_returns_its_argument_cleans_its_result(tmp_path):
    """actual (sync server): `const err = requireFileAccess(file, userId); res.send(err)` sends a fixed string or
    nothing. A helper that hands its argument back (also as an arrow's expression body) still taints, and so does a
    method called on another object."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.js": (
        "const express = require('express');\n"
        'const app = express();\n'
        '\n'
        'function requireAccess(file, user) {\n'
        '  if (file.owner === user) {\n'
        '    return null;\n'
        '  }\n'
        "  return 'file-access-not-allowed';\n"
        '}\n'
        '\n'
        'function label(name) {\n'
        "  return 'File ' + name;\n"
        '}\n'
        '\n'
        'const shout = (text) => text.toUpperCase();\n'
        '\n'
        'class Files {\n'
        '  check(name) {\n'
        "    return name.length > 3 ? 'ok' : 'short';\n"
        '  }\n'
        '}\n'
        '\n'
        "app.get('/a', (req, res) => {\n"
        '  const error = requireAccess(req.query.file, 1);\n'
        '  res.send(error);\n'
        '});\n'
        '\n'
        "app.get('/b', (req, res) => {\n"
        '  const title = label(req.query.name);\n'
        '  res.send(title);\n'
        '});\n'
        '\n'
        "app.get('/c', (req, res) => {\n"
        '  const loud = shout(req.query.name);\n'
        '  res.send(loud);\n'
        '});\n'
        '\n'
        "app.get('/d', (req, res) => {\n"
        '  const verdict = new Files().check(req.query.name);\n'
        '  res.send(verdict);\n'
        '});\n'
    )})
    assert found == {("app.js", 30, "xss"), ("app.js", 35, "xss"), ("app.js", 40, "xss")}


def test_a_javascript_check_that_ends_the_request_guards_what_follows(tmp_path):
    """actual: `if (!isValidRedirectUrl(url)) { res.status(400).send(...); return; } res.redirect(url)`, and a CORS
    proxy that fetches only after `if (!isUrlAllowed(url.href)) return ...`. The branch where the check said no,
    and a check that only tests for a value, still leave it open."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.js": (
        "const express = require('express');\n"
        "const app = express();\n\n"
        "function isValidRedirectUrl(url) {\n"
        "  return url.startsWith('/') && !url.startsWith('//');\n"
        "}\n\n"
        "function isUrlAllowed(href) {\n"
        "  return href.startsWith('https://raw.githubusercontent.com/');\n"
        "}\n\n"
        "app.get('/a', (req, res) => {\n"
        "  const url = req.query.url;\n"
        "  if (!isValidRedirectUrl(url)) {\n"
        "    res.status(400).send({ reason: 'Invalid redirect URL' });\n"
        "    return;\n"
        "  }\n"
        "  res.redirect(url);\n"
        "});\n\n"
        "app.post('/proxy', async (req, res) => {\n"
        "  const url = new URL(req.body.url);\n"
        "  if (!isUrlAllowed(url.href)) {\n"
        "    return res.status(403).json({ error: 'URL not allowed' });\n"
        "  }\n"
        "  const response = await fetch(url.href);\n"
        "  res.json({ status: response.status });\n"
        "});\n\n"
        "app.get('/b', (req, res) => {\n"
        "  const url = req.query.url;\n"
        "  if (!isValidRedirectUrl(url)) {\n"
        "    return res.redirect(url);\n"
        "  }\n"
        "  return res.redirect('/');\n"
        "});\n\n"
        "app.get('/c', (req, res) => {\n"
        "  const url = req.query.url;\n"
        "  if (!url) {\n"
        "    return res.status(400).end();\n"
        "  }\n"
        "  res.redirect(url);\n"
        "});\n")})
    assert found == {("app.js", 33, "open-redirect"), ("app.js", 43, "open-redirect")}


def test_a_signed_cookie_is_the_servers_own_data(tmp_path):
    """wiki.js: the login flow read back from a cookie the server signed (`req.unsignCookie(raw)`), or Express's
    `req.signedCookies`, holds what the server stored, like a session. A plain cookie is still the client's."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.js": (
        "const express = require('express');\n"
        "const app = express();\n\n"
        "app.get('/callback', (req, res) => {\n"
        "  const raw = req.cookies.flow;\n"
        "  const unsigned = req.unsignCookie(raw);\n"
        "  const flow = JSON.parse(unsigned.value);\n"
        "  res.redirect(flow.redirect);\n"
        "});\n\n"
        "app.get('/next', (req, res) => {\n"
        "  res.redirect(req.signedCookies.next);\n"
        "});\n\n"
        "app.get('/plain', (req, res) => {\n"
        "  res.redirect(req.cookies.next);\n"
        "});\n")})
    assert found == {("app.js", 16, "open-redirect")}


def test_input_escaped_for_a_regex_is_not_regex_injection(tmp_path):
    """habitica: `new RegExp(String.raw`^${name.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&')}`)` matches the name literally.
    Removing characters some other way leaves a pattern."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.js": (
        "const express = require('express');\n"
        "const app = express();\n\n"
        "app.get('/find', (req, res) => {\n"
        "  const name = req.query.name;\n"
        "  const re = new RegExp(String.raw`^${name.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&')}`);\n"
        "  const loose = new RegExp(name.replace(/\\s/g, ''));\n"
        "  res.json({ a: re.test('x'), b: loose.test('y') });\n"
        "});\n")})
    assert found == {("app.js", 7, "regex-injection")}


def test_a_url_that_starts_as_a_path_on_this_site_stays_there(tmp_path):
    """habitica: `let url = `/static/apple-redirect?code=${code}`; url += `&name=${first}`` only ever adds to the
    query. A variable set to something else later, or one that starts as a bare "/", is still open."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.js": (
        "const express = require('express');\n"
        "const app = express();\n\n"
        "app.post('/apple', (req, res) => {\n"
        "  let url = `/static/apple-redirect?code=${req.body.code}`;\n"
        "  if (req.body.user) {\n"
        "    url += `&name=${req.body.user}`;\n"
        "  }\n"
        "  return res.redirect(303, url);\n"
        "});\n\n"
        "app.post('/later', (req, res) => {\n"
        "  let url = `/home?tab=${req.body.tab}`;\n"
        "  url = req.body.next;\n"
        "  return res.redirect(url);\n"
        "});\n\n"
        "app.post('/bare', (req, res) => {\n"
        "  let url = '/';\n"
        "  url += req.body.next;\n"
        "  return res.redirect(url);\n"
        "});\n")})
    assert found == {("app.js", 15, "open-redirect"), ("app.js", 21, "open-redirect")}


def test_a_resolved_path_checked_against_its_base_and_separator_stays_inside(tmp_path):
    """pyLoad (GHSA-48rp, at its fix): `if not os.path.abspath(p).startswith(os.path.abspath(base) + os.sep):
    return` keeps p inside base. Without the separator /srv/files_evil passes a check for /srv/files (xiaomusic's
    advisory), so that is still a finding."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "import os\nfrom flask import Flask, request\n\napp = Flask(__name__)\nBASE = '/srv/files'\n\n\n"
        "@app.post('/save')\n"
        "def save():\n"
        "    path = os.path.normpath(os.path.join(BASE, request.form['name']))\n"
        "    if not os.path.abspath(path).startswith(os.path.abspath(BASE) + os.sep):\n"
        "        return 'invalid', 400\n"
        "    with open(path, 'wb') as fp:\n"
        "        fp.write(b'x')\n"
        "    return 'ok'\n\n\n"
        "@app.post('/loose')\n"
        "def loose():\n"
        "    path = os.path.join(BASE, request.form['name'])\n"
        "    if not os.path.realpath(path).startswith(BASE):\n"
        "        return 'invalid', 400\n"
        "    with open(path, 'wb') as fp:\n"
        "        fp.write(b'x')\n"
        "    return 'ok'\n")})
    assert found == {("app.py", 23, "path-traversal")}


def test_flask_make_response_of_a_dict_is_json(tmp_path):
    """MLflow (GHSA-vwhf, both sides of its fix): `make_response({"user": user.to_json()})` is a JSON response, as
    are a list and a (dict, status) tuple. A string made from the request is still HTML."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "from flask import Flask, make_response, request\n\napp = Flask(__name__)\n\n\n"
        "@app.get('/user')\n"
        "def user():\n"
        "    name = request.args['name']\n"
        "    if request.args.get('list'):\n"
        "        return make_response([name])\n"
        "    if request.args.get('created'):\n"
        "        return make_response(({'user': name}, 201))\n"
        "    if request.args.get('plain'):\n"
        "        return make_response(f'No user {name}', 404)\n"
        "    return make_response({'user': name})\n")})
    assert found == {("app.py", 14, "xss")}


def test_a_validator_that_raises_guards_what_follows(tmp_path):
    """LLaMA Factory and MLflow (GHSA-527m, GHSA-wc6j at their fixes): `check_lfi_path(image_url)` and
    `validate_path_is_safe(path)` raise when the value is unsafe, so what follows them is checked. Only a check named
    for what it checks: `check_permission(user, name)` says nothing about a path."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "import requests\nfrom flask import Flask, abort, request\n\napp = Flask(__name__)\n\n\n"
        "def check_lfi_path(path):\n"
        "    if '..' in path:\n"
        "        abort(403)\n\n\n"
        "def check_ssrf_url(url):\n"
        "    if not url.startswith('https://'):\n"
        "        abort(403)\n\n\n"
        "def check_permission(user, name):\n"
        "    return user is not None\n\n\n"
        "@app.post('/media')\n"
        "def media():\n"
        "    image_url = request.json['image_url']\n"
        "    check_lfi_path(image_url)\n"
        "    data = open(image_url, 'rb').read()\n"
        "    check_ssrf_url(image_url)\n"
        "    requests.get(image_url, timeout=5)\n"
        "    return str(len(data))\n\n\n"
        "@app.post('/other')\n"
        "def other():\n"
        "    name = request.json['name']\n"
        "    check_permission(None, name)\n"
        "    return open(name).read()\n")})
    assert found == {("app.py", 35, "path-traversal")}


def test_django_url_arguments_that_carry_text_are_request_input(tmp_path):
    """CodeRed CMS (GHSA-h454-rq3m-89rc): re_path(r'^media/(?P<path>.*)$', serve_protected_file) passes any text,
    `..` included, as `path`. Only arguments a route passes as free text: <int:pk>, <slug:slug> and \\d+ can't hold a
    path, and a view no urls.py routes stays as it was."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {
        "site/urls.py": (
            "from django.urls import path, re_path\n\nfrom . import views\n\n"
            "urlpatterns = [\n"
            "    re_path(r'^{0}(?P<path>.*)$'.format('media/'), views.serve_protected_file),\n"
            "    path('docs/<str:name>/', views.doc),\n"
            "    path('items/<int:pk>/<slug:slug>/', views.item),\n"
            "    re_path(r'^old/(?P<pk>\\d+)/$', views.old),\n"
            "]\n"),
        "site/views.py": (
            "import os\n\nfrom django.http import HttpResponse\n\nROOT = '/srv/protected'\n\n\n"
            "def serve_protected_file(request, path):\n"
            "    with open(os.path.join(ROOT, path), 'rb') as f:\n"
            "        return HttpResponse(f.read())\n\n\n"
            "def doc(request, name):\n"
            "    return HttpResponse(open(os.path.join(ROOT, name)).read())\n\n\n"
            "def item(request, pk, slug):\n"
            "    return HttpResponse(open(os.path.join(ROOT, slug, str(pk))).read())\n\n\n"
            "def old(request, pk):\n"
            "    return HttpResponse(open(os.path.join(ROOT, pk)).read())\n\n\n"
            "def helper(request, path):\n"
            "    return open(os.path.join(ROOT, path)).read()\n")})
    assert found == {("site/views.py", 9, "path-traversal"), ("site/views.py", 14, "path-traversal")}


def test_stripping_all_but_name_characters_keeps_a_path_inside(tmp_path):
    """changedetection.io (GHSA-9jj8-v89v-xjvw): re.sub(r'[^\\w.-]+', '', group) keeps "..", so a route could still
    climb out of its folder; the fix's re.sub(r'[^a-z0-9_]+', '', group) leaves a single name."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "import os\nimport re\n\nfrom flask import Flask\n\napp = Flask(__name__)\nROOT = '/srv/data'\n\n\n"
        "@app.route('/old/<string:group>')\n"
        "def old(group):\n"
        "    group = re.sub(r'[^\\w.-]+', '', group.lower())\n"
        "    return open(os.path.join(ROOT, group, 'data.json')).read()\n\n\n"
        "@app.route('/new/<string:group>')\n"
        "def new(group):\n"
        "    group = re.sub(r'[^a-z0-9_]+', '', group.lower())\n"
        "    other = re.sub(r'[^\\w-]', '_', group)\n"
        "    return open(os.path.join(ROOT, group, other)).read()\n")})
    assert found == {("app.py", 13, "path-traversal")}


def test_a_route_parameter_reassigned_from_a_sanitizer_is_clean(tmp_path):
    """`name = secure_filename(name)` replaces the URL's value; only the parameter as passed is request input
    (found with changedetection.io's GHSA-9jj8-v89v-xjvw, which cleans its route parameters in place). A
    reassignment that keeps the value, like .strip(), stays tainted."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "import os\n\nfrom flask import Flask\nfrom werkzeug.utils import secure_filename\n\n"
        "app = Flask(__name__)\nROOT = '/srv/data'\n\n\n"
        "@app.route('/a/<name>')\n"
        "def a(name):\n"
        "    name = secure_filename(name)\n"
        "    return open(os.path.join(ROOT, name)).read()\n\n\n"
        "@app.route('/b/<name>')\n"
        "def b(name):\n"
        "    name = name.strip()\n"
        "    return open(os.path.join(ROOT, name)).read()\n")})
    assert found == {("app.py", 19, "path-traversal")}


def test_fastapi_file_response_opens_its_path(tmp_path):
    """Fides (GHSA-r25m-cr6v-p9hq): a catch-all route served FileResponse(ui_path(path)) for any path; the fix runs
    the path through sanitise_url_path() first, a validator by its (British) name."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "from pathlib import Path\n\nfrom fastapi import FastAPI, Request\nfrom fastapi.responses import FileResponse\n\n"
        "app = FastAPI()\nROOT = Path('/srv/ui')\n\n\n"
        "def ui_path(path: str = ''):\n"
        "    return ROOT / 'admin' / path\n\n\n"
        "def sanitise_url_path(path):\n"
        "    if '..' in path:\n"
        "        raise ValueError(path)\n"
        "    return path\n\n\n"
        "@app.get('/{catchall:path}')\n"
        "def catchall(request: Request):\n"
        "    path = request.path_params['catchall']\n"
        "    return FileResponse(ui_path(path))\n\n\n"
        "@app.get('/fixed/{catchall:path}')\n"
        "def fixed(request: Request):\n"
        "    path = sanitise_url_path(request.path_params['catchall'])\n"
        "    return FileResponse(ui_path(path))\n")})
    assert found == {("app.py", 23, "path-traversal")}


def test_request_data_into_a_template_variable_printed_unescaped(tmp_path):
    """Whoogle (GHSA-mxvc-fwgx-j778): render_template('error.html', error_message='Unable to resolve query: ' + q)
    into a template that prints {{ error_message|safe }}. A variable the template escapes, sanitizes first or prints
    as JSON isn't a sink, and neither is one of a template no view names. A Django form or bound field escapes its own
    widgets (pygoat: {{ form.username|safe }}), and a template rendered with the request for context isn't request
    data (djangoproject.com: instance.render_to_string(request=request) into {{ markdown|safe }}). An admin-only view
    renders the administrator's own HTML (CTFd's page preview)."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {
        "app/templates/error.html": "<p>{{ error_message|safe }}</p>\n<h1>{{ title }}</h1>\n",
        "app/templates/list.html": (
            "{% for item in items %}<li>{{ item.text|safe }}</li>{% endfor %}\n"
            "{{ notes|sanitize_html|safe }}\n<script>var d = {{ data|tojson|safe }};</script>\n"),
        "app/templates/core/page.html": "{% autoescape off %}{{ body }}{% endautoescape %}\n",
        "app/templates/login.html": "{{ form.username|safe }}{{ form|safe }}<p>{{ note|safe }}</p>\n",
        "app/routes.py": (
            "from flask import Flask, render_template, request\n\napp = Flask(__name__)\n\n\n"
            "@app.route('/search')\n"
            "def search():\n"
            "    q = request.args.get('q', '')\n"
            "    if not q:\n"
            "        return render_template('error.html', error_message='Unable to resolve query: ' + q)\n"
            "    return render_template('error.html', error_message='No query', title=q)\n\n\n"
            "@app.route('/list')\n"
            "def listing():\n"
            "    text = request.args['text']\n"
            "    return render_template('list.html', items=[text], notes=text, data=text)\n\n\n"
            "@app.route('/admin/preview', methods=['POST'])\n"
            "@admins_only\n"
            "def preview():\n"
            "    return render_template('error.html', error_message=request.form['content'])\n"),
        "app/views.py": (
            "from django.shortcuts import render\n\n\n"
            "def page(request):\n"
            "    return render(request, 'core/page.html', {'body': request.GET['body'], 'title': 'x'})\n\n\n"
            "def login(request):\n"
            "    form = LoginForm(request.POST)\n"
            "    note = request.user.profile.render_to_string(request=request)\n"
            "    return render(request, 'login.html', {'form': form, 'note': note})\n"),
    })
    assert found == {("app/routes.py", 10, "xss"), ("app/routes.py", 17, "xss"), ("app/views.py", 5, "xss")}


def test_a_record_looked_up_through_a_store_is_the_stored_record(tmp_path):
    """MLflow (GHSA-wc6j-5g83-xfm6 at its fix): run = _get_tracking_store().get_run(run_id) is the stored run, and
    the artifact repository built from it isn't request data; the path, checked by validate_path_is_safe, is."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "from flask import Flask, request, send_file\n\nfrom .store import _get_tracking_store\n\n"
        "app = Flask(__name__)\n\n\n"
        "@app.route('/artifact')\n"
        "def artifact():\n"
        "    run = _get_tracking_store().get_run(request.args['run_id'])\n"
        "    return send_file(run.artifact_uri + '/model.bin')\n\n\n"
        "@app.route('/raw')\n"
        "def raw():\n"
        "    item = request.get_data().get_path()\n"
        "    return send_file(item)\n")})
    assert found == {("app.py", 17, "path-traversal")}


def test_a_session_key_with_a_fixed_prefix_is_not_a_trust_boundary(tmp_path):
    """request.session[f"player_{code}"] = key can't overwrite another entry; request.session[name] = ... can."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"views.py": (
        "import secrets\n\n\n"
        "def join(request):\n"
        "    code = request.GET['code']\n"
        "    request.session[f'player_{code}'] = secrets.token_hex(8)\n"
        "    request.session['seen_' + code] = True\n"
        "    request.session[code] = True\n")})
    assert found == {("views.py", 8, "trust-boundary")}


def test_requests_given_the_url_by_keyword(tmp_path):
    """Scout (GHSA-g53g-q539-93cv): requests.request(method=request.method, url=remote_url) proxied any URL."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "import requests\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
        "@app.route('/remote/cors/<path:remote_url>')\n"
        "def remote_cors(remote_url):\n"
        "    requests.request(method=request.method, url=remote_url, timeout=5)\n"
        "    return 'sent'\n\n\n"
        "@app.route('/fixed')\n"
        "def fixed():\n"
        "    requests.get(url='https://example.com/', params={'q': request.args['q']}, timeout=5)\n"
        "    return 'sent'\n")})
    assert found == {("app.py", 9, "ssrf")}


def test_python_methods_called_on_other_objects_across_files(tmp_path):
    """A summarised method reached through another receiver (`store.load_run(run_id)`, Vibe-Trading GHSA-mjrq), only
    where the calling file imports the defining module and the name isn't one every library object has."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    store = ("import os\nimport pickle\n\n\nclass Store:\n"
             "    def load_run(self, run_id):\n"
             "        return open(os.path.join('/data', run_id)).read()\n\n"
             "    def decode_prefs(self, blob):\n"
             "        return pickle.loads(blob)\n\n"
             "    def update(self, name):\n"
             "        return open(name, 'w')\n")
    views = ("from flask import Flask, request\nfrom app.store import Store\n\napp = Flask(__name__)\n\n\n"
             "@app.route('/run')\n"
             "def run(form):\n"
             "    Store().load_run(request.args['id'])\n"          # 9
             "    Store().decode_prefs(request.cookies['p'])\n"    # 10
             "    form.update(request.args['n'])\n"                # 11: update is anyone's
             "    return 'ok'\n")
    other = ("from flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
             "@app.route('/x')\n"
             "def x(store):\n"
             "    store.load_run(request.args['id'])\n"            # no import of app.store
             "    return 'ok'\n")
    found = semgrep_vulnerabilities(tmp_path, {"app/store.py": store, "app/views.py": views, "app/other.py": other})
    assert found == {("app/views.py", 9, "path-traversal"), ("app/views.py", 10, "unsafe-deserialization")}


def test_starred_unpacking_keeps_request_data(tmp_path):
    """Semgrep leaves a starred target clean (`[*log_key, ext] = request.path_params["path"].split("/")`, Dagster
    GHSA-q93c); the analysis copy unstars it on the same line."""
    from core.analyzers.starred_targets import unstar_targets

    source = "def g():\n    *a, b = x\n    [*a, b] = x\n    h, *r = y\n    f(*args)\n    q = [*a, *b]\n"
    assert unstar_targets(source) == (
        "def g():\n    a , b = x\n    [a , b] = x\n    h, r  = y\n    f(*args)\n    q = [*a, *b]\n")
    assert unstar_targets("f(*args)\n") is None
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "from flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
        "@app.route('/a')\n"
        "def a():\n"
        "    [*parts, ext] = request.args['p'].split('/')\n"
        "    open('/'.join(parts))\n"                                  # 9
        "    *rest, last = request.args['p'].split('/')\n"
        "    open('/'.join(rest))\n"                                   # 11
        "    return 'ok'\n")})
    assert found == {("app.py", 9, "path-traversal"), ("app.py", 11, "path-traversal")}


def test_helpers_that_check_a_path_clean_their_callers(tmp_path):
    """A helper that checks the path before returning it hands nothing back for path traversal (its own pass-through
    answer), so neither a call to it nor a method building on its result is a sink (Vibe-Trading GHSA-mjrq and Dagster
    GHSA-q93c at their fixes); the same helpers without the check still are."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    store = ("from pathlib import Path\n\n\nclass Store:\n"
             "    base_dir = Path('/data')\n\n"
             "    def run_dir(self, run_id):\n"
             "        candidate = Path(run_id)\n"
             "        if '..' in candidate.parts:\n"
             "            raise ValueError('bad')\n"
             "        return self.base_dir / candidate.name\n\n"
             "    def raw_dir(self, run_id):\n"
             "        return self.base_dir / run_id\n\n"
             "    def load_run(self, run_id):\n"
             "        run_file = self.run_dir(run_id) / 'run.json'\n"
             "        return run_file.read_text()\n\n"
             "    def load_raw(self, run_id):\n"
             "        run_file = self.raw_dir(run_id) / 'run.json'\n"
             "        return run_file.read_text()\n")
    views = ("from flask import Flask, request\nfrom app.store import Store\n\napp = Flask(__name__)\n\n\n"
             "@app.route('/a')\n"
             "def a():\n"
             "    Store().load_run(request.args['id'])\n"          # 9: checked
             "    Store().load_raw(request.args['id'])\n"          # 10
             "    p = Store().run_dir(request.args['id'])\n"
             "    open(p)\n"                                       # 12: checked
             "    q = Store().raw_dir(request.args['id'])\n"
             "    open(q)\n"                                       # 14
             "    return 'ok'\n")
    found = semgrep_vulnerabilities(tmp_path, {"app/store.py": store, "app/views.py": views})
    assert found == {("app/views.py", 10, "path-traversal"), ("app/views.py", 14, "path-traversal")}


def test_a_path_object_is_a_sink_where_it_is_used(tmp_path):
    """Path(x) assigned to a variable opens nothing; its uses are the sinks. Its .name is a basename through the
    variable too (Vibe-Trading GHSA-mjrq's fix: candidate = Path(run_id) ... base / candidate.name)."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "from pathlib import Path\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
        "@app.route('/a')\n"
        "def a():\n"
        "    candidate = Path(request.args['n'])\n"
        "    open(Path('/data') / candidate.name)\n"           # 10: a basename
        "    other = Path(request.args['m'])\n"
        "    open(other)\n"                                    # 12
        "    return Path(request.args['k']).read_text()\n")})  # 13
    assert found == {("app.py", 12, "path-traversal"), ("app.py", 13, "path-traversal")}


def test_remote_replies_and_filterset_rows_are_not_request_data(tmp_path):
    """What an outbound HTTP call returns is the remote server's data (taiga's importers: a project id sent to
    GitHub, then an avatar URL from the reply), and a django-filter FilterSet's .qs is rows (netbox)."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "import requests\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
        "@app.route('/a')\n"
        "def a():\n"
        "    repo = requests.get('https://api.github.com/repos/' + request.args['p']).json()\n"
        "    requests.get(repo['avatar_url'])\n"                         # 10: the reply's URL
        "    requests.get(request.args['u'])\n"                          # 11
        "    rows = ItemFilter(request.args, queryset=items).qs\n"
        "    open(rows[0])\n"                                            # 13: rows
        "    open(request.args['f'])\n"                                  # 14
        "    return 'ok'\n")})
    assert found == {("app.py", 11, "ssrf"), ("app.py", 14, "path-traversal")}


def test_a_check_named_helper_that_is_itself_the_sink(tmp_path):
    """A helper named like a check (`validate_credentials`) is trusted as one by name, which hid its own via-sink
    when it is the outbound request (PostHog GHSA-jrwm: validate_zendesk_credentials(subdomain=...) GETs
    https://{subdomain}.zendesk.com). Also reached under an import alias. The fix's compiled-pattern allowlist
    (`subdomain_regex.match(subdomain)` and return) clears the value; a real check named the same way still does."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    zendesk = ("import requests\n\n\n"
               "def validate_credentials(subdomain, api_key):\n"
               "    res = requests.get(f'https://{subdomain}.zendesk.com/api/v2/tickets/count')\n"
               "    return res.status_code == 200\n")
    checks = ("from urllib.parse import urlparse\n\n\n"
              "def validate_url(url):\n"
              "    return url if urlparse(url).hostname == 'api.example.com' else 'https://api.example.com/'\n")
    views = ("import re\nimport requests\n"
             "from app.pipelines.zendesk import validate_credentials as validate_zendesk_credentials\n"
             "from app.checks import validate_url\n"
             "from flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
             "@app.route('/schema', methods=['POST'])\n"
             "def schema():\n"
             "    subdomain = request.form.get('subdomain', '')\n"
             "    if not validate_zendesk_credentials(subdomain=subdomain, api_key='k'):\n"   # 13
             "        return 'no'\n"
             "    requests.get(validate_url(request.form['u']))\n"                           # 15: a real check
             "    return 'ok'\n\n\n"
             "@app.route('/fixed', methods=['POST'])\n"
             "def fixed():\n"
             "    subdomain = request.form.get('subdomain', '')\n"
             "    subdomain_regex = re.compile('^[a-zA-Z-]+$')\n"
             "    if not subdomain_regex.match(subdomain):\n"
             "        return 'bad subdomain'\n"
             "    validate_zendesk_credentials(subdomain=subdomain, api_key='k')\n"           # 25: allowlisted
             "    checker = Checker()\n"
             "    if not checker.match(request.form['s']):\n"
             "        return 'no'\n"
             "    validate_zendesk_credentials(subdomain=request.form['s'], api_key='k')\n"   # 29: not a pattern
             "    return 'ok'\n")
    found = semgrep_vulnerabilities(tmp_path, {"app/pipelines/zendesk.py": zendesk, "app/checks.py": checks,
                                               "app/views.py": views})
    assert found == {("app/views.py", 13, "ssrf"), ("app/views.py", 29, "ssrf")}


def test_agent_tool_arguments_are_untrusted(tmp_path):
    """The arguments a model fills in for an agent tool class (Vibe-Trading GHSA-3j25: RememberTool.execute(**kwargs)
    joins memory_type into a path; LangChain-style `_run(self, query: str)`): only the method the framework calls,
    in a *Tool class that describes itself to the model, and not numeric parameters."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"tools.py": (
        "import os\nimport subprocess\nfrom src.agent.tools import BaseTool\n\n\n"
        "class RememberTool(BaseTool):\n"
        "    name = 'remember'\n"
        "    description = 'Persistent memory.'\n\n"
        "    def execute(self, **kwargs):\n"
        "        kind = kwargs.get('memory_type', 'project')\n"
        "        return open(os.path.join('/memory', kind + '.md'), 'w')\n\n\n"     # 12
        "class SearchTool(BaseTool):\n"
        "    name: str = 'search'\n"
        "    description: str = 'Search files.'\n\n"
        "    def _run(self, query: str, limit: int = 5):\n"
        "        subprocess.run('grep ' + query, shell=True)\n"                    # 20
        "        return open(os.path.join('/x', str(limit)))\n\n\n"               # 21: a number
        "class NotATool(Base):\n"
        "    description = 'x'\n\n"
        "    def execute(self, **kwargs):\n"
        "        return open(kwargs['name'])\n\n\n"                               # 28: not a tool
        "class MigrationTool(BaseTool):\n"
        "    def run(self, path):\n"
        "        return open(path)\n\n\n"                                         # 33: not described to a model
        "class Helper(BaseTool):\n"
        "    description = 'x'\n\n"
        "    def helper(self, path):\n"
        "        return open(path)\n")})                                          # 39: not the entry point
    assert found == {("tools.py", 12, "path-traversal"), ("tools.py", 20, "command-injection")}


def test_generic_methods_through_receivers_of_a_project_class(tmp_path):
    """A generic method name (`add`, `get`) is connected only through a receiver assigned an instance of the
    project class that defines it (Vibe-Trading GHSA-3j25: self._memory = memory or PersistentMemory(), then
    self._memory.add(title, content, memory_type)), not through any other object with an add()."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    memory = ("import os\n\n\nclass PersistentMemory:\n"
              "    def add(self, title, content, memory_type, description=''):\n"
              "        path = os.path.join('/memory', memory_type, title + '.md')\n"
              "        return open(path, 'w')\n")
    views = ("from flask import Flask, request\nfrom app.memory import PersistentMemory\n\napp = Flask(__name__)\n\n\n"
             "class Notes:\n"
             "    def __init__(self, memory=None):\n"
             "        self._memory = memory or PersistentMemory()\n\n"
             "    def remember(self, kind):\n"
             "        return self._memory.add('t', 'c', kind)\n\n\n"
             "@app.route('/a')\n"
             "def a(tags):\n"
             "    Notes().remember(request.args['kind'])\n"                    # 17
             "    store = PersistentMemory()\n"
             "    store.add('t', 'c', memory_type=request.args['k'])\n"        # 19
             "    tags.add('t', 'c', request.args['k'])\n"                     # 20: some other add()
             "    return 'ok'\n")
    found = semgrep_vulnerabilities(tmp_path, {"app/memory.py": memory, "app/views.py": views})
    assert found == {("app/views.py", 17, "path-traversal"), ("app/views.py", 19, "path-traversal")}


def test_a_regular_expression_find_is_not_xpath(tmp_path):
    """ElementTree's find/findall take an XPath; a regular expression's findall doesn't (Vibe-Trading's
    `_TOKEN_RE.findall(text.lower())` on a query, once agent tool arguments were sources)."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "import re\nfrom flask import Flask, request\n\napp = Flask(__name__)\n_TOKEN_RE = re.compile('[a-z]+')\n\n\n"
        "@app.route('/a')\n"
        "def a(tree):\n"
        "    _TOKEN_RE.findall(request.args['q'])\n"                       # 10
        "    re.findall(request.args['p'], 'text')\n"                       # 11: a regex, not XPath
        "    tree.findall(request.args['x'])\n"                             # 12
        "    return 'ok'\n")})
    assert ("app.py", 12, "xpath-injection") in found
    assert not {f for f in found if f[2] == "xpath-injection" and f[1] in (10, 11)}


def test_a_helper_called_inside_an_f_string_is_asked_what_it_hands_back(tmp_path):
    """The pass-through analysis asks about calls whose result is assigned or returned, and now one interpolated
    into an f-string too (PostHog GHSA-jrwm at its fix: f"{get_base_url(region, subdomain)}resources/users", where
    region is only compared and subdomain was checked against an allowlist first)."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "import re\nimport requests\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
        "def get_base_url(region, subdomain):\n"
        "    if region == 'US' and subdomain:\n"
        "        return f'https://{subdomain}.rest.vitally.io/'\n"
        "    return 'https://rest.vitally-eu.io/'\n\n\n"
        "@app.route('/a', methods=['POST'])\n"
        "def a():\n"
        "    subdomain = request.form.get('subdomain', '')\n"
        "    if not re.match('^[a-zA-Z-]+$', subdomain):\n"
        "        return 'bad'\n"
        "    requests.get(f\"{get_base_url(request.form['region'], subdomain)}resources/users\")\n"   # 19
        "    requests.get(f\"{get_base_url('US', request.form['s'])}resources/users\")\n"            # 20
        "    return 'ok'\n")})
    assert found == {("app.py", 20, "ssrf")}


def test_a_summary_resting_on_a_helper_that_hands_back_some_parameters(tmp_path):
    """A summarised function whose sink argument comes from a helper that hands back only some of its parameters is
    summarised again once the passes are known (PostHog GHSA-jrwm at its fix: validate_credentials(secret_token,
    region, subdomain) requests f"{get_base_url(region, subdomain)}...", and region is only compared)."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    vitally = ("import requests\n\n\n"
               "def get_base_url(region, subdomain):\n"
               "    if region == 'US' and subdomain:\n"
               "        return f'https://{subdomain}.rest.vitally.io/'\n"
               "    return 'https://rest.vitally-eu.io/'\n\n\n"
               "def validate_credentials(secret_token, region, subdomain):\n"
               "    res = requests.get(f'{get_base_url(region, subdomain)}resources/users?limit=1')\n"
               "    return res.status_code == 200\n")
    views = ("from flask import Flask, request\nfrom app.vitally import validate_credentials\n"
             "from app.vitally import validate_credentials as validate_vitally_credentials\n\napp = Flask(__name__)\n\n\n"
             "@app.route('/a', methods=['POST'])\n"
             "def a():\n"
             "    validate_credentials(secret_token='t', subdomain='acme', region=request.form['region'])\n"   # 10
             "    validate_credentials(secret_token='t', subdomain=request.form['s'], region='US')\n"          # 11
             "    validate_vitally_credentials(secret_token='t', subdomain='a', region=request.form['r'])\n"   # 12
             "    return 'ok'\n")
    found = semgrep_vulnerabilities(tmp_path, {"app/vitally.py": vitally, "app/views.py": views})
    # 12: the alias follows the function's summary once that loses region.
    assert found == {("app/views.py", 11, "ssrf")}


STORED_MODELS = """from django.db import models


class Attachment(models.Model):
    filename = models.CharField(max_length=255)
    note = models.TextField(blank=True)
    kind = models.CharField(max_length=10, choices=[("a", "A")])
    size = models.IntegerField(default=0)

    def label(self):
        return mark_safe(f"<b>{self.filename}</b>")

    def note_html(self):
        return mark_safe(f"<i>{self.note}</i>")

    image = models.ImageField(upload_to="files", null=True)

    def thumbnail(self):
        return mark_safe(f'<img src="{self.image.url}">')


class Ticket(models.Model):
    title = models.CharField(max_length=200)
    body = models.TextField()
"""

STORED_VIEWS = """from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django import forms

from .models import Attachment, Ticket


def upload(request):
    for f in request.FILES.getlist("files"):
        Attachment.objects.create(filename=f.name, size=f.size, note="uploaded", image=f)
    return HttpResponse("ok")


def show(request, pk):
    item = get_object_or_404(Attachment, pk=pk)
    return HttpResponse(f"<h1>{item.filename}</h1><p>{item.note}</p>")


class TicketForm(forms.ModelForm):
    class Meta:
        model = Ticket
        fields = ["body"]


def ticket(request, pk):
    row = Ticket.objects.get(pk=pk)
    heading = HttpResponse(f"<h1>{row.title}</h1>")
    return HttpResponse(f"<div>{row.body}</div>")


def export(request, pk):
    item = Attachment.objects.get(pk=pk)
    return HttpResponse(f"filename: {item.filename}", content_type="text/yaml")
"""

STORED_ADMIN = """from django.contrib import admin
from django.utils.html import format_html
from django.utils.safestring import mark_safe

from .models import Attachment


@admin.register(Attachment)
class AttachmentAdmin(admin.ModelAdmin):
    def name_display(self, obj):
        return mark_safe(f'<span class="file">{obj.filename}</span>')

    def kind_display(self, obj):
        return mark_safe(f"<span>{obj.kind} {obj.size}</span>")

    def safe_display(self, obj):
        return format_html("<span>{}</span>", obj.filename)

    def unsafe_format(self, obj):
        return format_html(f"<span>{obj.filename}</span>")
"""


def test_a_check_clears_its_own_branch_not_the_else(tmp_path):
    """`if ext in ALLOWED:` clears ext in its body. Semgrep's range for the pattern is the whole if statement,
    so the else branch (where the check failed) was cleared too; the analysis copy makes it an if of its own."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "from flask import Flask, request\nfrom markupsafe import Markup\n\napp = Flask(__name__)\n"
        "ALLOWED = {'.png', '.jpg'}\n\n\n"
        "@app.route('/kind')\ndef kind():\n"
        "    ext = request.args['ext']\n"
        "    if ext in ALLOWED:\n"
        "        return Markup(f'<i>{ext}</i>')\n"           # 12: checked
        "    elif len(ext) > 3:\n"
        "        return Markup(f'<b>{ext}</b>')\n"           # 14: failed the check
        "    else:\n"
        "        return Markup(f'<u>{ext}</u>')\n"           # 16: failed the check
    )})
    assert found == {("app.py", 14, "xss"), ("app.py", 16, "xss")}


def test_model_fields_written_from_the_request_and_read_back_as_html(tmp_path):
    """Stored XSS, model by model: Attachment.filename is filled from an upload's name and Ticket.body from a
    ModelForm, so reading them back into HTML counts. Attachment.note (a constant), kind (fixed choices), size (a
    number) and Ticket.title (never written from a request) don't, nor does format_html's own escaping, an
    uploaded image's .url (the storage percent-encodes it) or a YAML response."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {
        "app/__init__.py": "", "app/models.py": "from django.utils.safestring import mark_safe\n" + STORED_MODELS,
        "app/views.py": STORED_VIEWS, "app/admin.py": STORED_ADMIN,
    })
    assert found == {("app/models.py", 12, "xss"),       # self.filename in the model's own method
                     ("app/views.py", 16, "xss"),        # item.filename after get_object_or_404
                     ("app/views.py", 28, "xss"),        # row.body (the ModelForm's field)
                     ("app/admin.py", 11, "xss"),        # obj.filename in the registered admin
                     ("app/admin.py", 20, "xss")}        # format_html with the field in its format string


def test_drf_serializer_data_and_its_field_checks(tmp_path):
    """A DRF serializer's validated_data is the request body (firefighter GHSA-fqvv: create() hands
    validated_data["attachments"] to a Jira client that fetches each URL); a field the serializer checks in
    validate_<field>, which DRF runs first, is clean (the fix's validate_attachments)."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    client = ("import httpx\n\n\nclass RaidJiraClient:\n"
              "    @staticmethod\n"
              "    def add_attachments_to_issue(issue_id, urls):\n"
              "        for url in urls:\n"
              "            httpx.get(url)\n\n\n"
              "client = RaidJiraClient()\n")
    serializers = (
        "from rest_framework import serializers\nfrom app.client import client as jira_client\n\n\n"
        "class TicketSerializer(serializers.ModelSerializer[Ticket]):\n"
        "    attachments = serializers.CharField()\n\n"
        "    def create(self, validated_data):\n"
        "        jira_client.add_attachments_to_issue(1, validated_data['attachments'].split(','))\n"   # 9
        "        return 1\n\n\n"
        "class CheckedSerializer(serializers.Serializer):\n"
        "    def validate_attachments(self, value):\n"
        "        if not value.startswith('https://files.example.com/'):\n"
        "            raise serializers.ValidationError('no')\n"
        "        return value\n\n"
        "    def create(self, validated_data):\n"
        "        jira_client.add_attachments_to_issue(1, validated_data['attachments'].split(','))\n"   # 20: checked
        "        jira_client.add_attachments_to_issue(1, [validated_data.get('other')])\n"              # 21
        "        return 1\n\n\n"
        "class NotASerializer(Base):\n"
        "    def create(self, validated_data):\n"
        "        jira_client.add_attachments_to_issue(1, validated_data['a'])\n")                      # 27
    found = semgrep_vulnerabilities(tmp_path, {"app/client.py": client, "app/serializers.py": serializers})
    assert found == {("app/serializers.py", 9, "ssrf"), ("app/serializers.py", 21, "ssrf")}


def test_django_sign_in_and_csp_settings(tmp_path):
    """Settings that open sign-in or switch off the CSP's script protection, as hotspots: an Entra tenant of
    "common" (or none: allauth's default), trusting a provider's email, and 'unsafe-inline'/'unsafe-eval' in
    script-src. Not: a tenant from the environment (unset gives None, and sign-in fails), 'unsafe-inline' for
    styles, or next to a nonce, hash or 'strict-dynamic' (browsers ignore it there; it's a fallback)."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_findings(tmp_path, {
        "bad/settings.py": (
            "import os\n\nSOCIALACCOUNT_PROVIDERS = {\n    \"microsoft\": {\n"
            "        \"APPS\": [{\"client_id\": \"x\", \"settings\": {\"tenant\": \"common\"}}],\n"   # 5
            "    },\n}\nSOCIALACCOUNT_EMAIL_AUTHENTICATION = True\n"                                 # 8
            "CSP_SCRIPT_SRC = [\"'self'\", \"'unsafe-inline'\"]\n"                                    # 9
            "CONTENT_SECURITY_POLICY = {\"DIRECTIVES\": {\"script-src\": [\"'self'\", \"'unsafe-eval'\"]}}\n\n\n"
            "def policy(response):\n"
            "    response[\"Content-Security-Policy\"] = \"default-src 'self'; script-src 'self' 'unsafe-inline'\"\n"
            "    directives = {\"script-src\": [\"'self'\"]}\n"
            "    directives[\"script-src\"].append(\"'unsafe-inline'\")\n"                            # 16
            "    return response\n"),
        "bad2/settings.py": (
            "SOCIALACCOUNT_PROVIDERS = {\n    \"microsoft\": {\n"                                     # 2: no tenant
            "        \"APPS\": [{\"client_id\": \"x\"}],\n        \"VERIFIED_EMAIL\": True,\n    },\n}\n"),
        "good/settings.py": (
            "import os\n\nSOCIALACCOUNT_PROVIDERS = {\n    \"microsoft\": {\n"
            "        \"APPS\": [{\"client_id\": \"x\", \"settings\": {\"tenant\": os.environ.get(\"TENANT\")}}],\n"
            "    },\n    \"google\": {\"SCOPE\": [\"email\"]},\n}\n"
            "CSP_STYLE_SRC = [\"'self'\", \"'unsafe-inline'\"]\n"
            "CSP_SCRIPT_SRC = [\"'self'\", \"'nonce-abc'\", \"'unsafe-inline'\"]\n\n\n"
            "def policy(response, nonce):\n"
            "    response[\"Content-Security-Policy\"] = f\"script-src 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'\"\n"
            "    response[\"X-Policy\"] = \"script-src 'nonce-x' 'strict-dynamic' 'unsafe-inline' https:\"\n"
            "    directives = {\"style-src\": [\"'self'\"]}\n"
            "    directives[\"style-src\"].append(\"'unsafe-inline'\")\n"
            "    return response\n"),
    })
    rules = ("allauth-microsoft-any-tenant", "allauth-trusts-provider-email", "csp-allows-inline-script")
    assert {f for f in found if f[2] in rules} == {
        ("bad/settings.py", 5, "allauth-microsoft-any-tenant", "security_hotspot"),
        ("bad/settings.py", 8, "allauth-trusts-provider-email", "security_hotspot"),
        ("bad/settings.py", 9, "csp-allows-inline-script", "security_hotspot"),
        ("bad/settings.py", 10, "csp-allows-inline-script", "security_hotspot"),
        ("bad/settings.py", 14, "csp-allows-inline-script", "security_hotspot"),
        ("bad/settings.py", 16, "csp-allows-inline-script", "security_hotspot"),
        ("bad2/settings.py", 2, "allauth-microsoft-any-tenant", "security_hotspot"),
        ("bad2/settings.py", 4, "allauth-trusts-provider-email", "security_hotspot"),
    }


def test_ldap_paged_searches_and_bind_dns_from_the_request(tmp_path):
    """A FastAPI directory connector: a filter in ldap3's paged search and a bind DN built from the user name are
    injection like a search filter is; escape_filter_chars / escape_rdn and a fixed service account are not."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"ldap_api.py": (
        "from fastapi import FastAPI\nfrom ldap3 import Connection, Server\n"
        "from ldap3.utils.dn import escape_rdn\n\napp = FastAPI()\nserver = Server('ldaps://dc.example.org')\n"
        "BASE = 'ou=people,dc=example,dc=org'\n\n\n"
        "@app.get('/groups')\ndef members(group: str):\n"
        "    conn = Connection(server, user='cn=svc,dc=example,dc=org', password='x', auto_bind=True)\n"
        "    return list(conn.extend.standard.paged_search(BASE, f'(memberOf=cn={group},{BASE})'))\n\n\n"  # 13
        "@app.post('/login')\ndef login(username: str, password: str):\n"
        "    conn = Connection(server, user=f'uid={username},{BASE}', password=password)\n"             # 18
        "    return {'ok': conn.bind()}\n\n\n"
        "@app.post('/login/safe')\ndef login_safe(username: str, password: str):\n"
        "    conn = Connection(server, user=f'uid={escape_rdn(username)},{BASE}', password=password)\n"
        "    return {'ok': conn.bind()}\n"
    )})
    assert found == {("ldap_api.py", 13, "ldap-injection"), ("ldap_api.py", 18, "ldap-injection")}


def test_requests_through_a_client_or_session_object(tmp_path):
    """SSRF through a requests Session or an httpx Client, made in the function or kept in a field by __init__,
    including `getattr(self._client, method)(url)` (firefighter GHSA-fqvv's HttpClient, reached through
    `http_client = HttpClient()` then `http_client.get(url)`)."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "import httpx\nimport requests\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
        "class HttpClient:\n"
        "    def __init__(self, client_kwargs=None):\n"
        "        self._client = httpx.Client(**(client_kwargs or {}))\n\n"
        "    def call(self, method, url, **kwargs):\n"
        "        return getattr(self._client, method)(url, **kwargs)\n\n"
        "    def get(self, url, **kwargs):\n"
        "        return self.call('get', url, **kwargs)\n\n\n"
        "@app.route('/a')\n"
        "def a(other):\n"
        "    session = requests.Session()\n"
        "    session.get(request.args['u'])\n"                       # 22
        "    with httpx.Client() as client:\n"
        "        client.post(url=request.args['v'])\n"                # 24
        "        client.request('GET', request.args['w'])\n"          # 25
        "        client.get('https://api.example.com/', params={'q': request.args['q']})\n"   # 26: a query
        "    http_client = HttpClient()\n"
        "    http_client.get(request.args['y'])\n"                    # 28
        "    other.get(request.args['z'])\n"                          # 29: not a client
        "    return 'ok'\n")})
    assert found == {("app.py", 22, "ssrf"), ("app.py", 24, "ssrf"), ("app.py", 25, "ssrf"), ("app.py", 28, "ssrf")}


def test_flask_restful_resource_url_parameters(tmp_path):
    """A Flask-RESTful Resource's handler parameters are the URL's variable parts, given where the class is
    registered (OpenResolve GHSA-h3h4: api.add_resource(LookupRecordType, '/<rdtype>/<domain>')); only those the
    URL fills with text, and only for registered classes."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "import os\nfrom flask import Flask\nfrom flask_restful import Api, Resource\n\n\n"
        "class LookupRecordType(Resource):\n"
        "    def get(self, rdtype, domain):\n"
        "        return open(os.path.join('/zones', domain))\n\n\n"            # 8
        "class Certificate(Resource):\n"
        "    def get(self, certificate_id):\n"
        "        return open(os.path.join('/certs', certificate_id))\n\n\n"    # 13: an int converter
        "class Unregistered(Resource):\n"
        "    def get(self, name):\n"
        "        return open(name)\n\n\n"                                       # 18
        "app = Flask(__name__)\napi = Api(app)\n"
        "api.add_resource(LookupRecordType, '/<rdtype>/<domain>')\n"
        "api.add_resource(Certificate, '/certificates/<int:certificate_id>')\n")})
    assert found == {("app.py", 8, "path-traversal")}


def test_a_substring_check_routes_a_value_without_checking_it(tmp_path):
    """`if "'" in name: return` clears name, but `if 'http' in q: return redirect(q)` only sends q one way or
    the other (Whoogle GHSA-mxvc: the else branch rendered q into an error page printed |safe)."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {
        "app.py": ("from flask import Flask, request, redirect, render_template\n\napp = Flask(__name__)\n\n\n"
                   "@app.route('/url')\ndef url():\n"
                   "    q = request.args.get('q')\n"
                   "    if len(q) > 0 and 'http' in q:\n"
                   "        return redirect(q)\n"                                                         # 10
                   "    else:\n"
                   "        return render_template('error.html', error_message='Unable: ' + q)\n\n\n"   # 12
                   "@app.route('/b')\ndef b():\n"
                   "    q = request.args.get('q')\n"
                   "    if '<' in q:\n"
                   "        return 'no'\n"
                   "    return render_template('error.html', error_message=q)\n"),                      # 19
        "templates/error.html": "<div>{{ error_message|safe }}</div>\n"})
    assert found == {("app.py", 10, "open-redirect"), ("app.py", 12, "xss")}


def test_a_fixed_host_kept_in_a_field(tmp_path):
    """A client whose __init__ keeps a URL with a fixed host in a field builds its request URLs from it
    (taiga's GithubClient: self.api_url = "https://api.github.com/{}", then self.api_url.format(uri_path) in its
    get()); one whose base URL is a plain parameter doesn't. Each reached through a receiver of its own class."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    github = ("import requests\n\n\n"
              "class GithubClient:\n"
              "    def __init__(self, token):\n"
              "        self.api_url = 'https://api.github.com/{}'\n"
              "        self.token = token\n\n"
              "    def get(self, uri_path):\n"
              "        return requests.get(self.api_url.format(uri_path))\n")
    mirror = ("import requests\n\n\n"
              "class Mirror:\n"
              "    def __init__(self, base):\n"
              "        self.base = base\n\n"
              "    def get(self, uri_path):\n"
              "        return requests.get(self.base.format(uri_path))\n")
    views = ("from flask import Flask, request\nfrom app.github import GithubClient\nfrom app.mirror import Mirror\n\n"
             "app = Flask(__name__)\n\n\n"
             "@app.route('/a')\n"
             "def a():\n"
             "    github = GithubClient('t')\n"
             "    github.get('repos/' + request.args['p'])\n"     # 11: a path on GitHub's host
             "    mirror = Mirror('{}')\n"
             "    mirror.get(request.args['p'])\n"                 # 13
             "    return 'ok'\n")
    found = semgrep_vulnerabilities(tmp_path, {"app/github.py": github, "app/mirror.py": mirror, "app/views.py": views})
    assert found == {("app/views.py", 13, "ssrf")}


def test_sql_text_from_a_builder_that_returns_its_params(tmp_path):
    """`sql, params = build(...)` hands back SQL text and the values to bind (label-studio's summary updates):
    the text isn't request data even when the params are; a builder returning one string still is."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "from django.db import connection\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
        "def build(keys):\n"
        "    return 'jsonb_set(x, %s)', [list(keys)]\n\n\n"
        "def build_text(keys):\n"
        "    return 'x = ' + keys[0]\n\n\n"
        "@app.route('/a')\n"
        "def a():\n"
        "    ann_sql, ann_params = build([request.args['k']])\n"
        "    connection.cursor().execute(f'UPDATE t SET c = {ann_sql}', ann_params)\n"     # 18
        "    clause = build_text([request.args['k']])\n"
        "    connection.cursor().execute(f'UPDATE t SET {clause}')\n"                      # 20
        "    return 'ok'\n")})
    assert found == {("app.py", 20, "sql-injection")}


def test_a_sandboxed_jinja_environment_made_in_another_module(tmp_path):
    """A project's own SandboxedEnvironment subclass, made in one module and rendered with in another (paperless-ngx's
    JinjaEnvironment for storage-path templates), is a sandbox; a plain Environment isn't."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    environment = ("from jinja2 import Environment\nfrom jinja2.sandbox import SandboxedEnvironment\n\n\n"
                   "class JinjaEnvironment(SandboxedEnvironment):\n    pass\n\n\n"
                   "_template_environment = JinjaEnvironment()\nplain_environment = Environment()\n")
    views = ("from flask import Flask, request\n"
             "from app.environment import _template_environment, plain_environment\n\napp = Flask(__name__)\n\n\n"
             "@app.route('/a')\n"
             "def a():\n"
             "    _template_environment.from_string(request.args['t']).render()\n"   # 9
             "    plain_environment.from_string(request.args['t']).render()\n"       # 10
             "    return 'ok'\n")
    found = semgrep_vulnerabilities(tmp_path, {"app/environment.py": environment, "app/views.py": views})
    assert found == {("app/views.py", 10, "template-injection")}


def test_a_regex_compiled_only_to_check_it(tmp_path):
    """Compiling a user's pattern alone in a try only checks it (paperless-ngx's validate_regex_pattern); compiling
    it for use is still a sink."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "import re\nimport regex\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
        "@app.route('/a')\n"
        "def a():\n"
        "    try:\n"
        "        regex.compile(request.args['p'])\n"                     # 11: a check
        "    except regex.error as exc:\n"
        "        return str(exc)\n"
        "    pattern = re.compile(request.args['q'])\n"                  # 14
        "    return str(pattern.fullmatch('x'))\n")})
    assert {f for f in found if f[2] == "regex-injection"} == {("app.py", 14, "regex-injection")}


def test_request_chosen_response_content_type_is_xss(tmp_path):
    """A Content-Type taken from the request lets text/html run whatever the body holds (SecurityEval CWE-113
    sonar_1/sonar_2: request.args into Headers.add and response.headers[...]). A type looked up in a fixed table, a
    constant, a Content-Type forwarded on an outgoing request, and an attachment (downloaded, never rendered) stay quiet."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "import requests\nfrom flask import Flask, Response, request\n"
        "from werkzeug.datastructures import Headers\n\napp = Flask(__name__)\n"
        "TYPES = {'csv': 'text/csv', 'json': 'application/json'}\n\n\n"
        "@app.route('/a')\n"
        "def a():\n"
        "    headers = Headers()\n"
        "    headers.add('Content-Type', request.args['Content-Type'])\n"
        "    response = Response()\n"
        "    response.headers = headers\n"
        "    return response\n\n\n"
        "@app.route('/b')\n"
        "def b():\n"
        "    response = Response()\n"
        "    response.headers['content-type'] = request.args.get('type')\n"
        "    return response\n\n\n"
        "@app.route('/c')\n"
        "def c():\n"
        "    return Response(open('static/report').read(), mimetype=request.args.get('type'))\n\n\n"
        "@app.route('/d')\n"
        "def d():\n"
        "    return Response('a,b', mimetype=TYPES.get(request.args.get('format'), 'text/plain'))\n\n\n"
        "@app.route('/e')\n"
        "def e():\n"
        "    headers = {'Content-Type': request.headers.get('Content-Type')}\n"
        "    headers['content-type'] = request.headers.get('Content-Type')\n"
        "    upstream = requests.post('https://api.example.com/x', data=b'', headers=headers, timeout=5)\n"
        "    return Response('ok', mimetype='text/plain')\n"),
        "views.py": (
            "from django.http import FileResponse, HttpResponse\n\n\n"
            "def export(request):\n"
            "    return FileResponse(open('x', 'rb'), as_attachment=True, content_type=request.GET.get('type'))\n\n\n"
            "def show(request):\n"
            "    return HttpResponse(open('x').read(), content_type=request.GET.get('type'))\n")})
    assert found == {("app.py", 12, "xss"), ("app.py", 21, "xss"), ("app.py", 27, "xss"), ("views.py", 9, "xss")}


def test_request_chosen_response_content_type_is_xss_in_node(tmp_path):
    """n8n GHSA-c8hm: a stored upload served with the Content-Type the query string names, so ?mimeType=text/html
    runs it as a page. Express setHeader/type/writeHead and Koa's ctx.type are reported; a type from a fixed
    table or looked up from the file name, an attachment, n8n's fix (a CSP sandbox for HTML) and a stored record's
    type (wiki's assets, loaded through WIKI.models.assets) stay quiet."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"server.js": (
        "const express = require('express');\nconst mime = require('mime');\n"
        "const app = express();\nconst TYPES = { csv: 'text/csv' };\n\n"
        "app.get('/file', (req, res) => {\n"
        "  res.setHeader('Content-Type', req.query.type);\n"
        "  res.sendFile('/srv/upload');\n"
        "});\n"
        "app.get('/a', (req, res) => {\n"
        "  res.type(req.query.format);\n"
        "  res.end();\n"
        "});\n"
        "app.get('/b', (req, res) => {\n"
        "  res.writeHead(200, { 'Content-Type': req.query.type });\n"
        "  res.end();\n"
        "});\n"
        "app.get('/c', (req, res) => {\n"
        "  res.set('Content-Type', TYPES[req.query.format]);\n"
        "  res.set('Content-Type', mime.getType(req.path));\n"
        "  res.end();\n"
        "});\n"
        "app.get('/d', (req, res) => {\n"
        "  res.attachment('report');\n"
        "  res.type(req.query.type);\n"
        "  res.end();\n"
        "});\n"
        "app.get('/e', (req, res) => {\n"
        "  const { mimeType, action } = req.query;\n"
        "  if (mimeType) {\n"
        "    res.setHeader('Content-Type', mimeType);\n"
        "    if (mimeType.includes('html') && action === 'view') {\n"
        "      res.header('Content-Security-Policy', 'sandbox');\n"
        "    }\n"
        "  }\n"
        "  res.end();\n"
        "});\n"
        "app.get('/f/:id', async (req, res) => {\n"
        "  const asset = await app.models.assets.getAsset(req.params.id);\n"
        "  res.type(asset.mimeType).send(asset.body);\n"
        "});\n"),
        "koa.js": (
            "const Koa = require('koa');\nconst app = new Koa();\n\n"
            "app.use(async (ctx) => {\n"
            "  ctx.type = ctx.query.type;\n"
            "  ctx.body = 'x';\n"
            "});\n")})
    assert found == {("server.js", 7, "xss"), ("server.js", 11, "xss"), ("server.js", 15, "xss"),
                     ("koa.js", 5, "xss")}

