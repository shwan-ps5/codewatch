"""javascript-express.yml: Express/Node command injection, path traversal and SSRF through the module shapes
javascript-taint.yml doesn't resolve, each line reported by one rule only."""
import pytest
import yaml

from core import catalog
from core.analyzers.base import Context
from core.analyzers.multi_tools import Semgrep

RULES = catalog.BUILTIN_RULES_DIR


def scan(tmp_path, files):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    for name, body in files.items():
        (tmp_path / name).write_text(body)
    ctx = Context(root=tmp_path, files=list(files), semgrep_config="", custom_rules=catalog.custom_semgrep_rules())
    return [(f.path, f.line, f.rule) for f in Semgrep().run(ctx).findings if f.rule.startswith("codewatch.js.")]


def lines(found, rule):
    return {(path, line) for path, line, r in found if r == rule}


def test_sources_and_sanitizers_are_javascript_taint_ymls():
    taint = {r["id"]: r for r in yaml.safe_load((RULES / "javascript-taint.yml").read_text())["rules"]}
    express = {r["id"]: r for r in yaml.safe_load((RULES / "javascript-express.yml").read_text())["rules"]}
    assert set(express) == {"codewatch.js.express.command-injection", "codewatch.js.express.path-traversal",
                            "codewatch.js.express.ssrf"}
    for kind in ("command-injection", "path-traversal", "ssrf"):
        mine, theirs = express[f"codewatch.js.express.{kind}"], taint[f"codewatch.js.{kind}"]
        assert mine["pattern-sources"] == theirs["pattern-sources"], kind
        assert mine["pattern-sanitizers"] == theirs["pattern-sanitizers"], kind
        assert mine["metadata"]["cwe"] == theirs["metadata"]["cwe"], kind


def test_command_injection_through_node_specifier_promisify_and_execa(tmp_path):
    found = scan(tmp_path, {
        "cmd.js": (
            "const express = require('express')\n"
            "const cp = require('node:child_process')\n"
            "const { exec } = require('child_process')\n"
            "const util = require('util')\n"
            "const { execa, execaCommand } = require('execa')\n"
            "const run = util.promisify(exec)\n"
            "const app = express()\n"
            "app.get('/a', (req, res) => { cp.exec('ping ' + req.query.host) })\n"
            "app.get('/b', (req, res) => { cp.execFile('sh', ['-c', req.query.cmd]) })\n"
            "app.get('/c', (req, res) => { cp.spawn(req.query.cmd, { shell: true }) })\n"
            "app.get('/d', async (req, res) => { await run('ping ' + req.query.host) })\n"
            "app.get('/e', (req, res) => { execa(req.query.c, { shell: true }) })\n"
            "app.get('/f', (req, res) => { execaCommand('ls ' + req.query.d) })\n"
            "app.get('/g', (req, res) => { exec('ping ' + req.query.host) })\n"
            "app.get('/h', (req, res) => { cp.execFile('ls', [req.query.d]) })\n"
            "app.get('/i', (req, res) => { execa('ls', [req.query.d]) })\n"
            "app.get('/j', (req, res) => { cp.exec('ping ' + parseInt(req.query.n)) })\n"
        ),
        "cmd.ts": (
            "import * as child from 'node:child_process'\n"
            "import { execSync } from 'node:child_process'\n"
            "import { Request, Response } from 'express'\n"
            "export function a(req: Request, res: Response) { child.exec('ping ' + req.query.host) }\n"
            "export function b(req: Request, res: Response) { execSync(`ls ${req.query.dir}`) }\n"
        ),
    })
    assert lines(found, "codewatch.js.express.command-injection") == {
        ("cmd.js", n) for n in (8, 9, 10, 11, 12, 13)} | {("cmd.ts", 4), ("cmd.ts", 5)}
    # Plain child_process stays javascript-taint.yml's; argument arrays without a shell and numbers are quiet.
    assert lines(found, "codewatch.js.command-injection") == {("cmd.js", 14)}


def test_path_traversal_through_fs_promises_fs_extra_and_send_file_options(tmp_path):
    found = scan(tmp_path, {
        "files.js": (
            "const express = require('express')\n"
            "const fs = require('fs')\n"
            "const fsp = require('fs/promises')\n"
            "const fse = require('fs-extra')\n"
            "const path = require('path')\n"
            "const { readFile } = require('fs')\n"
            "const app = express()\n"
            "app.get('/a', async (req, res) => { await fsp.readFile(path.join('/data', req.query.f)) })\n"
            "app.get('/b', (req, res) => { fse.remove(req.query.f) })\n"
            "app.get('/c', (req, res) => { fs.mkdirSync(req.body.dir, { recursive: true }) })\n"
            "app.get('/d', (req, res) => { res.sendFile(path.resolve(req.params.f), { headers: {} }) })\n"
            "app.get('/e', (req, res) => { res.sendFile(path.join(__dirname, req.query.f), (err) => {}) })\n"
            "app.post('/f', (req, res) => { fs.rename('/tmp/upload', path.join('/up', req.body.name), () => {}) })\n"
            "app.get('/g', (req, res) => { readFile(path.join(__dirname, req.query.f), () => {}) })\n"
            "app.get('/h', (req, res) => { res.sendFile(req.params[0], { root: '/srv' }) })\n"
            "app.get('/i', (req, res) => { fse.remove(path.join('/d', path.basename(req.query.f))) })\n"
            "app.get('/j', (req, res) => { res.sendFile(req.query.f) })\n"
        ),
        "files.ts": (
            "import { readFile } from 'fs/promises'\n"
            "import { createReadStream } from 'node:fs'\n"
            "import { Request, Response } from 'express'\n"
            "export async function a(req: Request, res: Response) { await readFile(req.query.f as string) }\n"
            "export function b(req: Request, res: Response) { createReadStream(req.query.f as string).pipe(res) }\n"
        ),
    })
    assert lines(found, "codewatch.js.express.path-traversal") == {
        ("files.js", n) for n in (8, 9, 10, 11, 12, 13)} | {("files.ts", 4), ("files.ts", 5)}
    assert lines(found, "codewatch.js.path-traversal") == {("files.js", 14), ("files.js", 17)}


def test_ssrf_through_direct_client_calls_and_undici(tmp_path):
    found = scan(tmp_path, {
        "out.js": (
            "const express = require('express')\n"
            "const superagent = require('superagent')\n"
            "const needle = require('needle')\n"
            "const undici = require('undici')\n"
            "const app = express()\n"
            "app.get('/a', async (req, res) => { await superagent(req.query.url) })\n"
            "app.get('/b', async (req, res) => { await needle('get', req.query.url) })\n"
            "app.get('/c', async (req, res) => { await undici.request(req.query.url) })\n"
            "app.get('/d', async (req, res) => { await needle.post(req.body.hook, {}) })\n"
            "app.get('/e', async (req, res) => { await superagent.get(req.query.url) })\n"
            "app.get('/f', async (req, res) => { await needle('get', 'https://api.example.com/' + req.query.p) })\n"
            "app.get('/g', async (req, res) => { await superagent('https://api.example.com/x').query(req.query) })\n"
        ),
        "out.ts": (
            "import { fetch as ufetch } from 'undici'\n"
            "import { Request, Response } from 'express'\n"
            "export async function a(req: Request, res: Response) { await ufetch(req.query.url as string) }\n"
        ),
    })
    assert lines(found, "codewatch.js.express.ssrf") == {("out.js", n) for n in (6, 7, 8, 9)} | {("out.ts", 3)}
    assert lines(found, "codewatch.js.ssrf") == {("out.js", 10)}
