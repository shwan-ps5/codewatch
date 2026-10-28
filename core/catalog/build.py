"""Import: regenerate catalog/imported/ from the installed analyzers and online sources.

Only the imported layer is written; catalog/custom/ is never touched.
"""
import json
import subprocess
from datetime import UTC, datetime

from ..analyzers.base import TOOLS_DIR, tool_path
from . import sources, standards

VERSION_COMMANDS = {
    "ruff": ["ruff", "--version"], "bandit": ["bandit", "--version"], "semgrep": ["semgrep", "--version"],
    "basedpyright": ["basedpyright", "--version"], "complexipy": ["complexipy", "--version"],
    "detect-secrets": ["detect-secrets", "--version"], "cppcheck": ["cppcheck", "--version"],
    "pip-audit": ["pip-audit", "--version"],
}


def tool_versions():
    versions = {}
    for name, (exe, *args) in VERSION_COMMANDS.items():
        path = tool_path(exe)
        if path:
            out = subprocess.run([path, *args], capture_output=True, text=True, check=False).stdout.strip()
            versions[name] = out.splitlines()[0] if out else "?"
    package = TOOLS_DIR / "package.json"
    if package.exists():
        versions.update(json.loads(package.read_text()).get("dependencies", {}))
    return versions


def collect_rules(log):
    rules, failures = [], {}
    for name, collect in sources.SOURCES:
        try:
            found = collect()
        except Exception as exc:  # noqa: BLE001 - one unreachable source must not abort the import
            failures[name] = str(exc)[:500]
            log(f"  {name}: FAILED ({exc})")
            continue
        log(f"  {name}: {len(found)} rules")
        rules += found
    return rules, failures


def split_docs(rules):
    docs = {}
    for r in rules:
        doc = r.pop("_doc", None)
        if doc:
            docs[r["id"]] = doc
    return docs


def diff(previous, current):
    before, after = {r["id"] for r in previous}, {r["id"] for r in current}
    return {"added": sorted(after - before), "removed": sorted(before - after)}


def build(target, log=print, previous=None):
    log("Fetching MITRE CWE data")
    cwe = standards.Cwe(sources.fetch(standards.CWE_XML_URL))
    std = cwe.summary()
    log("Fetching W3C WCAG 2.2 data")
    std["wcag"] = standards.wcag(sources.fetch(standards.WCAG_JSON_URL))
    rules, failures = collect_rules(log)
    if failures and not rules:
        raise RuntimeError(f"Every source failed: {failures}")
    docs = split_docs(rules)
    referenced = sorted({c for r in rules for c in r["cwe"]})
    std["cwe_details"] = {str(c): d for c in referenced if (d := cwe.details(c))}
    rules.sort(key=lambda r: r["id"])
    meta = {
        "imported_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "rules": len(rules), "by_tool": {}, "tools": tool_versions(), "failed_sources": failures,
        "standards": {"cwe": f"{std['cwe_version']} ({std['cwe_date']})", "wcag": "2.2", "owasp": "2025"},
    }
    for r in rules:
        meta["by_tool"][r["tool"]] = meta["by_tool"].get(r["tool"], 0) + 1
    target.mkdir(parents=True, exist_ok=True)
    files = {"rules.json": rules, "standards.json": std, "docs.json": docs, "meta.json": meta,
             "changes.json": {**diff(previous or [], rules), "at": meta["imported_at"]}}
    for name, data in files.items():
        tmp = target / f".{name}.tmp"
        tmp.write_text(json.dumps(data, indent=1) + "\n")
        tmp.replace(target / name)
    return meta
