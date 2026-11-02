"""Express/Node command injection, path traversal and SSRF through the module shapes Semgrep doesn't resolve on its
own (node: specifiers, fs/promises, fs-extra, promisified exec, execa, direct HTTP client calls), multer's own file
names, and helpers that look a record up rather than return request data."""
import pytest

from core.analyzers.multi_tools import Semgrep
from tests.test_detection import semgrep_vulnerabilities


def scan(tmp_path, files):
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    return semgrep_vulnerabilities(tmp_path, files)


def lines(found, rule):
    return {(path, line) for path, line, r in found if r == rule}


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
    # Argument arrays without a shell and numbers are quiet.
    assert lines(found, "command-injection") == {
        ("cmd.js", n) for n in (8, 9, 10, 11, 12, 13, 14)} | {("cmd.ts", 4), ("cmd.ts", 5)}


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
            "app.get('/k', (req, res) => { fse.ensureDir(path.join('/up', req.params.user)) })\n"
        ),
        "files.ts": (
            "import { readFile } from 'fs/promises'\n"
            "import { createReadStream } from 'node:fs'\n"
            "import { Request, Response } from 'express'\n"
            "export async function a(req: Request, res: Response) { await readFile(req.query.f as string) }\n"
            "export function b(req: Request, res: Response) { createReadStream(req.query.f as string).pipe(res) }\n"
        ),
    })
    # Creating a directory (lines 10, 18) is left out: low impact, and the id is usually checked elsewhere.
    assert lines(found, "path-traversal") == {
        ("files.js", n) for n in (8, 9, 11, 12, 13, 14, 17)} | {("files.ts", 4), ("files.ts", 5)}


def test_multer_file_names_are_the_servers_and_originalname_the_clients(tmp_path):
    found = scan(tmp_path, {
        "upload.js": (
            "const express = require('express')\n"
            "const fs = require('fs')\n"
            "const path = require('path')\n"
            "const app = express()\n"
            "app.post('/a', (req, res) => { fs.rename(req.file.path, '/up/x', () => {}) })\n"
            "app.post('/b', (req, res) => { fs.unlink(path.join('/tmp', req.file.filename), () => {}) })\n"
            "app.post('/c', (req, res) => { fs.readFile(req.files[0].path, () => {}) })\n"
            "app.post('/d', (req, res) => { fs.readFile(req.files.avatar[0].path, () => {}) })\n"
            "app.post('/e', (req, res) => { fs.rename(req.file.path, path.join('/up', req.body.name), () => {}) })\n"
            "app.post('/f', async (req, res) => { await fetch(req.file.originalname) })\n"
        ),
    })
    assert lines(found, "path-traversal") == {("upload.js", 9)}
    assert lines(found, "ssrf") == {("upload.js", 10)}


def test_a_loader_helper_returns_what_it_looked_up_not_request_data(tmp_path):
    found = scan(tmp_path, {
        "ideas.js": (
            "const fsp = require('fs/promises')\n"
            "const path = require('path')\n\n"
            "async function loadIdea(req, reply) {\n"
            "  const page = await WIKI.models.pages.getPage({ siteId: req.params.siteId, id: req.params.pageId })\n"
            "  if (!page) {\n"
            "    reply.notFound('no idea')\n"
            "    return null\n"
            "  }\n"
            "  const board = WIKI.models.feedback.boardOfIdea(req.params.siteId, page.locale, page.path)\n"
            "  return { page, board }\n"
            "}\n\n"
            "function getParam(req) {\n"
            "  return req.query.x\n"
            "}\n\n"
            "async function removeFile(id) {\n"
            "  await fsp.rm(path.join('/data', id))\n"
            "}\n\n"
            "app.post('/withdraw', async (req, reply) => {\n"
            "  const idea = await loadIdea(req, reply)\n"
            "  const { page } = idea\n"
            "  await removeFile(page.id)\n"
            "})\n\n"
            "app.post('/remove', async (req, reply) => {\n"
            "  const name = getParam(req)\n"
            "  await removeFile(name)\n"
            "})\n"
        ),
    })
    assert lines(found, "path-traversal") == {("ideas.js", 30)}
