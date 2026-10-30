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
    assert found == {(7, "sql-injection"), (8, "command-injection"), (9, "path-traversal"), (10, "xss"),
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
