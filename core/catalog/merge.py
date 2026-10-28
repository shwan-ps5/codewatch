"""Combine imported rules with the custom layer (mappings, overrides, codewatch's own rules)."""
import copy
import re

import yaml

CWE_RE = re.compile(r"CWE-(\d+)")
CWE_URL = "https://cwe.mitre.org/data/definitions/{}.html"
WCAG_URL = "https://www.w3.org/WAI/WCAG22/quickref/#{}"
OVERRIDABLE = ("severity", "type", "title", "summary", "disabled")
SEMGREP_SEVERITY = {"ERROR": "critical", "WARNING": "major", "INFO": "minor"}
SEMGREP_TYPE = {"security": "vulnerability", "correctness": "bug"}


def listed(meta, key):
    return meta.get(key) or []


def normal_language(lang):
    return "javascript" if lang in ("js", "ts", "typescript") else lang


def custom_rule(r, path):
    meta = r.get("metadata") or {}
    return {
        "id": f"codewatch/{r['id']}", "tool": "codewatch", "code": r["id"],
        "title": meta.get("title") or r["message"].split(".")[0].strip(),
        "languages": [normal_language(lang) for lang in r.get("languages", [])],
        "type": meta.get("type") or SEMGREP_TYPE.get(meta.get("category", ""), "code_smell"),
        "severity": SEMGREP_SEVERITY.get(r.get("severity"), "minor"), "summary": r["message"].strip(),
        "docs": "", "license": f"custom ({path.name})", "origin": "custom",
        "references": [{"label": url, "url": url} for url in listed(meta, "references")],
        "cwe": sorted({int(m) for c in listed(meta, "cwe") for m in CWE_RE.findall(c)}),
        "wcag": [str(w) for w in listed(meta, "wcag")],
        "owasp": [o.split(" ")[0] for o in listed(meta, "owasp")],
    }


def load_custom_rules(paths):
    return [custom_rule(r, path) for path in paths for r in (yaml.safe_load(path.read_text()) or {}).get("rules", [])]


def add_mapping(rule, field, values, label):
    new = set(values) - set(rule[field])
    if new:
        rule[field] = sorted(set(rule[field]) | new)
        rule.setdefault("mapped_by", []).append(label)


def apply_mappings(rules, mappings):
    for kind in ("cwe", "wcag", "owasp"):
        table = mappings.get(kind, {})
        for r in rules:
            values = table.get(r["id"]) or table.get(f"{r['tool']}/*") or []
            add_mapping(r, kind, values, "codewatch")


def source_pairs(rules, by_id):
    """Equivalences a source declared ("_same_as"); bandit references are by test ID, e.g. B602."""
    bandit_codes = {r["code"].split(":")[0]: r["id"] for r in rules if r["tool"] == "bandit"}
    pairs = []
    for r in rules:
        for other in r.pop("_same_as", []):
            is_bandit = other.startswith(("bandit/", "bandit-code/"))
            target = bandit_codes.get(other.split("/", 1)[1]) if is_bandit else other
            if target in by_id:
                pairs.append([r["id"], target])
    return pairs


def resolve_same_as(rules, mappings):
    """Equivalent rules across tools: from the sources themselves plus custom/mappings.json "equivalent"."""
    by_id = {r["id"]: r for r in rules}
    pairs = list(mappings.get("equivalent", [])) + source_pairs(rules, by_id)
    for group in pairs:
        members = [m for m in group if m in by_id]
        for m in members:
            by_id[m]["same_as"] = sorted(set(by_id[m].get("same_as", [])) | (set(members) - {m}))


def add_standard_refs(rule, standards):
    present = {ref["url"] for ref in rule["references"]}
    names = standards.get("cwe_names", {})
    for c in rule["cwe"]:
        if CWE_URL.format(c) not in present:
            rule["references"].append({"label": f"CWE-{c}: {names.get(str(c), '')}".rstrip(": "),
                                       "url": CWE_URL.format(c)})
    for sc in rule["wcag"]:
        if WCAG_URL.format(sc) not in present:
            rule["references"].append({"label": f"WCAG 2.2 SC {sc}", "url": WCAG_URL.format(sc)})


def owasp_for(cwes, standards):
    from . import expanded_cwes

    expanded = expanded_cwes(cwes, standards.get("cwe_parents", {}))
    return [cat["id"] for cat in standards.get("owasp", {}).get("categories", []) if expanded & set(cat["cwes"])]


def builtin_rules():
    from ..analyzers.codewatch_checks import RULES

    return [{"id": f"codewatch/{r['code']}", "tool": "codewatch", "docs": "", "wcag": [], "owasp": [],
             "license": "codewatch", "origin": "codewatch", **copy.deepcopy(r)} for r in RULES]


def merge(imported, standards, mappings, overrides, custom_paths):
    rules = [copy.deepcopy(r) for r in imported] + builtin_rules() + load_custom_rules(custom_paths)
    for r in rules:
        r.setdefault("origin", "imported")
    apply_mappings(rules, mappings)
    resolve_same_as(rules, mappings)
    for r in rules:
        for field, value in (overrides.get(r["id"]) or {}).items():
            if field in OVERRIDABLE:
                r[field] = value
                r["overridden"] = True
        r["owasp"] = sorted(set(r["owasp"]) | set(owasp_for(r["cwe"], standards)))
        add_standard_refs(r, standards)
    return sorted(rules, key=lambda r: r["id"])
