"""Rule collectors, one per analyzer. Each reads the installed tool's own metadata (or a free online source).

A collected rule may carry "_doc" (Markdown explaining what's wrong and how to fix it, with examples) and
"_same_as" (IDs of rules in other tools that perform the same check); build.py moves those into docs.json
and the duplicate index. Documentation is only copied from permissively licensed tools.
"""
import inspect
import json
import re
import subprocess
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..analyzers.accessibility import HTML_VALIDATE_CONFIG
from ..analyzers.base import TOOLS_DIR, by_prefix, node_tool, tool_path
from ..analyzers.extra import eslint_classify
from ..analyzers.multi_tools import CPPCHECK_NOISE, CPPCHECK_SEVERITY, SEMGREP_SEVERITY, semgrep_type
from ..analyzers.python_tools import BANDIT_SEVERITY, RUFF_EXTEND_IGNORE, RUFF_RULES

PYTHON, JS, C, HTML, CSS, WEB, IAC, ANY = "python", "javascript", "c/c++", "html", "css", "web", "iac", "any"
SEMGREP_PACK_URL = "https://semgrep.dev/c/p/default"
ESLINT_DOC_URL = "https://raw.githubusercontent.com/eslint/eslint/main/docs/src/rules/{}.md"
LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^)\s]+)\)")
CWE_RE = re.compile(r"CWE-(\d+)")
BANDIT_DOC_RE = re.compile(r"/(b\d{3})[_-]", re.IGNORECASE)
JS_LANGS = {"javascript", "typescript", "js", "ts"}


def fetch(url, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": "codewatch-catalog"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def run(*args, cwd=None):
    return subprocess.run(list(args), capture_output=True, text=True, check=False, cwd=cwd).stdout


def humanize(name):
    words = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name.replace("-", " ").replace("_", " ")).split()
    return " ".join(words).capitalize() if words else name


def rule(tool, code, title, languages, type_, severity, *, license_, summary="", docs="", refs=(), cwe=(),
         wcag=(), owasp=(), doc=None, same_as=()):
    entry = {
        "id": f"{tool}/{code}", "tool": tool, "code": code, "title": title, "languages": list(languages),
        "type": type_, "severity": severity, "summary": summary, "docs": docs, "license": license_,
        "references": list(refs), "cwe": sorted(set(cwe)), "wcag": sorted(set(wcag)), "owasp": list(owasp),
    }
    if doc:
        entry["_doc"] = doc
    if same_as:
        entry["_same_as"] = list(same_as)
    return entry


def links_in(text):
    seen, out = set(), []
    for label, url in LINK_RE.findall(text or ""):
        if url not in seen:
            seen.add(url)
            out.append({"label": label, "url": url})
    return out


# --- Python ---------------------------------------------------------------------------------------------


def ruff():
    data = json.loads(run(tool_path("ruff"), "rule", "--all", "--output-format", "json") or "[]")
    out = []
    for r in data:
        if not r.get("code") or r["code"] in RUFF_EXTEND_IGNORE:
            continue
        severity, type_ = by_prefix(r["code"], RUFF_RULES, ("minor", "code_smell"))
        # flake8-bandit codes mirror bandit's: S105 is B105.
        same = [f"bandit/B{r['code'][1:]}"] if re.fullmatch(r"S\d{3}", r["code"]) else []
        out.append(rule("ruff", r["code"], humanize(r["name"]), [PYTHON], type_, severity, license_="MIT (ruff)",
                        summary=r["summary"], docs=f"https://docs.astral.sh/ruff/rules/{r['name']}/",
                        refs=links_in(r.get("explanation")), doc=r.get("explanation"), same_as=same))
    return out


def rst_to_markdown(doc):
    """Bandit docstrings are reStructuredText; enough conversion for headings and code blocks to read well."""
    out, in_code = [], False
    for line in doc.splitlines():
        if line.strip().startswith(".. code-block::"):
            out.append("```")
            in_code = True
            continue
        if in_code and line and not line.startswith((" ", "\t")):
            out.append("```")
            in_code = False
        if line.strip().startswith((".. seealso::", ".. versionadded::", ".. versionchanged::")):
            continue
        out.append(line[4:] if in_code and line.startswith("    ") else line)
    if in_code:
        out.append("```")
    text = "\n".join(out).replace(":Example:", "**Example:**")
    return re.sub(r"^\*\*B\d{3}:.*?\*\*\s*", "", text.strip())


def bandit():
    from bandit.core import extension_loader, issue

    manager = extension_loader.MANAGER
    out = [bandit_plugin(p, issue) for p in manager.plugins]
    out += [bandit_blacklist(bid, b) for bid, b in sorted(manager.blacklist_by_id.items())]
    return out


def bandit_plugin(plugin, issue):
    fn = plugin.plugin
    source = inspect.getsource(inspect.getmodule(fn))
    cwes = {getattr(issue.Cwe, n) for n in re.findall(r"cwe=issue\.Cwe\.(\w+)", source)} - {0}
    doc = inspect.getdoc(fn) or ""
    paragraphs = [p for p in doc.split("\n\n")[1:] if p and not p.startswith(("..", ":"))]
    return rule("bandit", f"{fn._test_id}:{plugin.name}", humanize(plugin.name), [PYTHON], "vulnerability", "varies",
                license_="Apache-2.0 (bandit)", summary=" ".join(paragraphs[0].split())[:400] if paragraphs else "",
                docs=f"https://bandit.readthedocs.io/en/latest/plugins/{fn._test_id.lower()}_{plugin.name}.html",
                cwe=cwes, doc=rst_to_markdown(doc), refs=links_in(doc))


def bandit_blacklist(bid, b):
    return rule("bandit", f"{bid}:blacklist", humanize(b["name"]), [PYTHON], "security_hotspot",
                BANDIT_SEVERITY.get(b.get("level", "MEDIUM"), "minor"), license_="Apache-2.0 (bandit)",
                summary=b["message"], docs="https://bandit.readthedocs.io/en/latest/blacklists/",
                cwe=[b["cwe"]] if b.get("cwe") else [],
                doc=f"{b['message']}\n\nFlagged calls and imports: " + ", ".join(f"`{q}`" for q in b["qualnames"]))


def basedpyright():
    binary = tool_path("basedpyright")
    bundle = next(Path(binary).resolve().parents[1].glob(
        "lib/python*/site-packages/basedpyright/dist/pyright.js"), None) if binary else None
    names = sorted(set(re.findall(r'"(report[A-Z][A-Za-z]+)"', bundle.read_text(errors="replace")))) if bundle else []
    return [rule("basedpyright", n, humanize(n.removeprefix("report")), [PYTHON], "bug", "major",
                 license_="MIT (basedpyright)",
                 docs=f"https://docs.basedpyright.com/latest/configuration/config-files/#{n}")
            for n in names]


def detect_secrets():
    kinds = ", ".join(humanize(n.removesuffix("Detector")) for n in run(
        tool_path("detect-secrets") or "detect-secrets", "scan", "--list-all-plugins").split())
    return [rule("detect-secrets", "hard-coded-secret", "Hard-coded secret or API key", [ANY], "vulnerability",
                 "blocker", license_="Apache-2.0 (detect-secrets)",
                 summary=f"Detects: {kinds}. Matches found only by entropy or keyword are reported as security "
                         "hotspots.", docs="https://github.com/Yelp/detect-secrets#currently-supported-plugins")]


def single():
    return [
        rule("radon", "cyclomatic-complexity", "Function too complex (cyclomatic complexity)", [PYTHON],
             "code_smell", "major", license_="MIT (radon)", summary="Too many independent paths through one function.",
             docs="https://radon.readthedocs.io/en/latest/intro.html#cyclomatic-complexity",
             refs=[{"label": "McCabe, A Complexity Measure (IEEE TSE, 1976)",
                    "url": "https://doi.org/10.1109/TSE.1976.233837"},
                   {"label": "NIST SP 500-235: Structured Testing",
                    "url": "https://www.nist.gov/publications/structured-testing-testing-methodology-using-cyclomatic-complexity-metric"}]),
        rule("lizard", "cyclomatic-complexity", "Function too complex (cyclomatic complexity)", [JS, C],
             "code_smell", "major", license_="MIT (lizard)", summary="Too many independent paths through one function.",
             docs="https://github.com/terryyin/lizard"),
        rule("complexipy", "cognitive-complexity", "Function hard to follow (cognitive complexity)", [PYTHON],
             "code_smell", "major", license_="MIT (complexipy)",
             summary="Nesting and breaks in linear control flow make code hard to read.",
             docs="https://github.com/rohaquinlop/complexipy",
             refs=[{"label": "G. Ann Campbell, Cognitive Complexity (2018, ACM TechDebt)",
                    "url": "https://doi.org/10.1145/3194164.3194186"}]),
        rule("jscpd", "duplicated-block", "Duplicated code block", [ANY], "code_smell", "minor",
             license_="MIT (jscpd)", summary="The same block of code appears in more than one place.",
             docs="https://github.com/kucherenko/jscpd"),
        rule("pip-audit", "vulnerable-dependency", "Dependency with a known vulnerability", [PYTHON],
             "vulnerability", "varies", license_="Apache-2.0 (pip-audit)",
             summary="A dependency has a published advisory (severity taken from the advisory).",
             docs="https://github.com/pypa/pip-audit",
             refs=[{"label": "OSV vulnerability database", "url": "https://osv.dev"},
                   {"label": "PyPA Advisory Database", "url": "https://github.com/pypa/advisory-database"}]),
    ]


# --- C/C++ and infrastructure ---------------------------------------------------------------------------


def cppcheck():
    path = tool_path("cppcheck")
    if not path:
        return []
    out = []
    for e in ET.fromstring(run(path, "--errorlist")).iter("error"):
        if e.get("severity") not in CPPCHECK_SEVERITY or e.get("id") in CPPCHECK_NOISE:
            continue
        severity, type_ = CPPCHECK_SEVERITY[e.get("severity")]
        # cppcheck's messages are GPL; the catalogue keeps the ID, classification and CWE only.
        out.append(rule("cppcheck", e.get("id"), humanize(e.get("id")), [C], type_, severity,
                        license_="GPL-3.0 (cppcheck): ID only", docs="https://cppcheck.sourceforge.io/manual.html",
                        cwe=[int(e.get("cwe"))] if e.get("cwe", "0") != "0" else []))
    return out


def checkov():
    binary = TOOLS_DIR / "checkov-venv" / "bin" / "checkov"
    if not binary.exists():
        return []
    out, seen = [], set()
    for framework in ("dockerfile", "terraform", "github_actions", "kubernetes"):
        # --list only prints a Markdown table: | n | Id | Type | Entity | Policy | IaC | Resource Link |
        for line in run(str(binary), "--list", "--framework", framework).splitlines():
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) < 7 or not cells[1].startswith("CKV") or cells[1] in seen:
                continue
            seen.add(cells[1])
            out.append(rule("checkov", cells[1], cells[4], [IAC], "security_hotspot", "major",
                            license_="Apache-2.0 (checkov)", summary=f"{framework} check", docs=cells[6]))
    return out


# --- Node tools -----------------------------------------------------------------------------------------


def node_metadata():
    with tempfile.NamedTemporaryFile("w", suffix=".json") as cfg:
        json.dump(HTML_VALIDATE_CONFIG, cfg)
        cfg.flush()
        return json.loads(run("node", str(TOOLS_DIR / "rule-metadata.mjs"), cfg.name, cwd=TOOLS_DIR) or "{}")


def clean_eslint_doc(text):
    """ESLint's docs use front matter and ::: correct/incorrect containers; turn those into plain Markdown."""
    text = re.sub(r"\A---\n.*?\n---\n", "", text, flags=re.DOTALL)
    text = re.sub(r"^::: ?(incorrect|correct)[^\n]*$", lambda m: f"**{m[1].capitalize()} code:**", text, flags=re.MULTILINE)
    text = re.sub(r"^:::\s*$", "", text, flags=re.MULTILINE)
    return re.sub(r"\{%.*?%\}", "", text).strip()


def local_doc(path):
    try:
        return clean_eslint_doc(path.read_text())
    except OSError:
        return None


def eslint_doc(rule_id):
    if rule_id.startswith("security/"):
        return local_doc(TOOLS_DIR / "node_modules/eslint-plugin-security/docs/rules" / f"{rule_id[9:]}.md")
    try:
        return clean_eslint_doc(fetch(ESLINT_DOC_URL.format(rule_id), timeout=30).decode())
    except OSError:
        return None


def eslint(data):
    ids = [r["id"] for r in data.get("eslint", [])]
    with ThreadPoolExecutor(max_workers=8) as pool:
        texts = dict(zip(ids, pool.map(eslint_doc, ids)))
    out = []
    for r in data.get("eslint", []):
        severity, type_ = eslint_classify(r["id"], 2)
        lic = "Apache-2.0 (eslint-plugin-security)" if r["id"].startswith("security/") else "MIT (ESLint)"
        out.append(rule("eslint", r["id"], r["description"] or humanize(r["id"]), [JS], type_, severity,
                        license_=lic, docs=r["url"], doc=texts.get(r["id"]), refs=links_in(texts.get(r["id"]))))
    return out


def jsx_a11y(data):
    docs_dir = TOOLS_DIR / "node_modules/eslint-plugin-jsx-a11y/docs/rules"
    return [rule("jsx-a11y", r["id"], r["description"] or humanize(r["id"]), [JS], "accessibility", "major",
                 license_="MIT (eslint-plugin-jsx-a11y)", docs=r["url"],
                 doc=local_doc(docs_dir / f"{r['id'].removeprefix('jsx-a11y/')}.md"))
            for r in data.get("jsx-a11y", [])]


def html_a11y(data):
    out = []
    for r in data.get("html-a11y", []):
        technique = r["id"].removeprefix("wcag/").upper() if r["id"].startswith("wcag/") else None
        refs = [{"label": f"WCAG technique {technique}",
                 "url": f"https://www.w3.org/WAI/WCAG22/Techniques/html/{technique}"}] if technique else []
        out.append(rule("html-a11y", r["id"], humanize(r["id"].replace("wcag/", "WCAG ")), [HTML], "accessibility",
                        "major", license_="MIT (html-validate)", docs=r["url"], refs=refs))
    return out


def stylelint(data):
    docs_dir = TOOLS_DIR / "node_modules/stylelint/lib/rules"
    return [rule("stylelint", r["id"], humanize(r["id"]), [CSS], "code_smell" if r["warning"] else "bug",
                 "minor" if r["warning"] else "major", license_="MIT (stylelint)", docs=r["url"],
                 doc=local_doc(docs_dir / r["id"] / "README.md"))
            for r in data.get("stylelint", [])]


def axe(data):
    out = []
    for r in data.get("axe", []):
        wcag = [".".join(t[4:]) for t in r["tags"] if re.fullmatch(r"wcag\d{3,4}", t)]
        refs = [{"label": f"WCAG 2.2 SC {sc}", "url": f"https://www.w3.org/WAI/WCAG22/quickref/#{sc}"} for sc in wcag]
        out.append(rule("axe", r["id"], r["help"], [WEB], "accessibility", "varies", license_="MPL-2.0 (axe-core)",
                        summary=r["description"], docs=r["url"], refs=refs, wcag=wcag))
    return out


def node():
    if not node_tool("eslint"):
        return []
    data = node_metadata()
    return eslint(data) + jsx_a11y(data) + html_a11y(data) + stylelint(data) + axe(data)


# --- Semgrep registry -----------------------------------------------------------------------------------


def catalog_language(lang):
    if lang in JS_LANGS:
        return JS
    return C if lang in ("c", "cpp") else lang


def bandit_equivalent(meta):
    """Semgrep rules ported from bandit link to the bandit check they came from."""
    source = str(meta.get("source-rule-url") or "")
    match = BANDIT_DOC_RE.search(source) if "bandit" in source else None
    return [f"bandit-code/{match[1].upper()}"] if match else []


def cwe_numbers(values):
    return [int(m) for c in values or [] for m in CWE_RE.findall(c)]


def semgrep_entry(r):
    meta = r.get("metadata") or {}
    # Semgrep Rules License: only the ID, languages and the CWE/OWASP facts are recorded, not rule text.
    return rule("semgrep", r["id"], humanize(r["id"].rsplit(".", 1)[-1]),
                sorted({catalog_language(lang) for lang in r.get("languages", [])}), semgrep_type(r["id"], meta),
                SEMGREP_SEVERITY.get(r.get("severity"), "minor"), license_="Semgrep Rules License v1.0: ID only",
                docs=f"https://semgrep.dev/r/{r['id']}", cwe=cwe_numbers(meta.get("cwe")),
                owasp=[o.split(" ")[0] for o in meta.get("owasp") or [] if "2025" in o],
                same_as=bandit_equivalent(meta))


def semgrep():
    import yaml

    return [semgrep_entry(r) for r in yaml.safe_load(fetch(SEMGREP_PACK_URL))["rules"]]


SOURCES = [
    ("ruff", ruff), ("bandit", bandit), ("basedpyright", basedpyright), ("single-rule tools", single),
    ("detect-secrets", detect_secrets), ("cppcheck", cppcheck), ("checkov", checkov), ("Node tools", node),
    ("semgrep registry", semgrep),
]
