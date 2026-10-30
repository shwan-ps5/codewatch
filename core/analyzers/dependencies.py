import fnmatch
import json
import re
import tomllib
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .base import Analyzer, Finding, Result, ToolError

OSV_URL = "https://api.osv.dev/v1/vulns/{}"
OSV_SEVERITY = {"CRITICAL": "blocker", "HIGH": "critical", "MODERATE": "major", "MEDIUM": "major", "LOW": "minor"}
REQUIREMENTS_GLOB = "requirements*.txt"


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def manifests(files, root):
    found = []
    for f in files:
        name = Path(f).name
        if fnmatch.fnmatch(name, REQUIREMENTS_GLOB):
            found.append(f)
        elif name == "pyproject.toml":
            try:
                data = tomllib.loads((root / f).read_text())
            except (OSError, tomllib.TOMLDecodeError):
                continue
            if data.get("project", {}).get("dependencies"):
                found.append(f)
    return found


def osv_severity(vuln_ids):
    """GitHub-reviewed advisories carry a CRITICAL/HIGH/MODERATE/LOW rating that PYSEC entries lack."""
    for vid in sorted(vuln_ids, key=lambda v: not v.startswith("GHSA")):
        try:
            with urllib.request.urlopen(OSV_URL.format(vid), timeout=10) as resp:
                rating = json.load(resp).get("database_specific", {}).get("severity")
        except (OSError, ValueError):
            continue
        if rating in OSV_SEVERITY:
            return OSV_SEVERITY[rating]
    return "major"


class PipAudit(Analyzer):
    """Known CVEs/advisories in Python dependencies, resolved transitively by pip-audit against PyPI + OSV."""

    name = "pip-audit"
    executable = "pip-audit"

    def applies(self, ctx):
        return bool(manifests(ctx.files, ctx.root))

    def audit(self, ctx, manifest):
        """Dependencies with advisories, resolved from the manifest. If pip can't resolve it (a package missing
        for this Python, a private index), the packages installed in the project's own venv are audited instead;
        None if neither works."""
        args = [str(Path(manifest).parent)] if manifest.endswith(".toml") else ["-r", manifest]
        for attempt in ([*args], *(["--path", str(p)] for p in project_site_packages(ctx.root))):
            try:
                out = self.exec([*attempt, "--format", "json", "--progress-spinner", "off"], ctx, ok_codes=(0, 1))
                return json.loads(out)["dependencies"]
            except (ToolError, ValueError, KeyError):
                continue
        return None

    def run(self, ctx):
        pending, seen, unresolved = [], set(), 0
        for manifest in manifests(ctx.files, ctx.root):
            text = read_manifest(ctx.root / manifest)
            deps = self.audit(ctx, manifest)
            if deps is None:
                unresolved += 1
                continue
            for dep in deps:
                for vuln in dep.get("vulns", []):
                    if (manifest, dep["name"], vuln["id"]) not in seen:
                        seen.add((manifest, dep["name"], vuln["id"]))
                        pending.append((manifest, text, dep, vuln))
        result = Result()
        with ThreadPoolExecutor(max_workers=8) as pool:
            result.findings = list(pool.map(vulnerability_finding, pending))
        result.metrics["vulnerable_dependencies"] = len({normalize(dep["name"]) for _, _, dep, _ in pending})
        result.metrics["dependency_vulnerabilities"] = len(result.findings)
        result.metrics["dependency_critical_vulnerabilities"] = sum(
            f.severity in ("blocker", "critical") for f in result.findings
        )
        result.metrics["dependency_manifests_unresolved"] = unresolved
        return result


def project_site_packages(root):
    return sorted(Path(root).glob("*venv/lib/python3*/site-packages"))


def read_manifest(path):
    """Requirements files are sometimes saved as UTF-16 (PowerShell's default); pip reads those by their BOM."""
    raw = path.read_bytes()
    for bom, encoding in ((b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16"), (b"\xef\xbb\xbf", "utf-8-sig")):
        if raw.startswith(bom):
            return raw.decode(encoding, errors="replace")
    return raw.decode("utf-8", errors="replace")


def advisory_summary(vuln):
    """First prose line of an advisory; GitHub advisories start with Markdown headings."""
    lines = (vuln.get("description") or "").splitlines()
    return next((ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")), "")[:300]


def vulnerability_finding(item):
    manifest, text, dep, vuln = item
    ids = [vuln["id"], *vuln.get("aliases", [])]
    cve = next((a for a in ids if a.startswith("CVE-")), vuln["id"])
    line = declaration_line(text, dep["name"])
    fix = ", ".join(vuln.get("fix_versions") or []) or "none available"
    where = "" if line else " (transitive)"
    return Finding("pip-audit", cve, osv_severity(ids), "vulnerability",
                   f"{dep['name']} {dep['version']}{where}: {cve} \u2014 fixed in {fix}. {advisory_summary(vuln)}",
                   manifest, line)


def declaration_line(text, package):
    target = normalize(package)
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"""\s*["']?([A-Za-z0-9][A-Za-z0-9._-]*)""", line)
        if m and normalize(m[1]) == target:
            return i
    return None
