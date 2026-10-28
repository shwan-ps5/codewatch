import json
import re
import tomllib
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .base import Analyzer, Finding, Result

OSV_URL = "https://api.osv.dev/v1/vulns/{}"
OSV_SEVERITY = {"CRITICAL": "blocker", "HIGH": "critical", "MODERATE": "major", "MEDIUM": "major", "LOW": "minor"}
REQUIREMENTS_RE = re.compile(r"requirements[\w.-]*\.txt$")


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def manifests(files, root):
    found = []
    for f in files:
        name = Path(f).name
        if REQUIREMENTS_RE.search(name):
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

    def run(self, ctx):
        result = Result()
        vulnerable = set()
        pending = []
        for manifest in manifests(ctx.files, ctx.root):
            if manifest.endswith(".toml"):
                args = [str(Path(manifest).parent)]
            else:
                args = ["-r", manifest]
            out = self.exec([*args, "--format", "json", "--progress-spinner", "off"], ctx, ok_codes=(0, 1))
            text = (ctx.root / manifest).read_text()
            seen = set()
            for dep in json.loads(out)["dependencies"]:
                for vuln in dep.get("vulns", []):
                    key = (dep["name"], vuln["id"])
                    if key in seen:
                        continue
                    seen.add(key)
                    vulnerable.add(normalize(dep["name"]))
                    pending.append((manifest, text, dep, vuln))

        def build(item):
            manifest, text, dep, vuln = item
            ids = [vuln["id"], *vuln.get("aliases", [])]
            cve = next((a for a in ids if a.startswith("CVE-")), vuln["id"])
            line = declaration_line(text, dep["name"])
            fix = ", ".join(vuln.get("fix_versions") or []) or "none available"
            where = "" if line else " (transitive)"
            summary = next(
                (ln.strip() for ln in (vuln.get("description") or "").splitlines()
                 if ln.strip() and not ln.lstrip().startswith("#")), ""
            )[:300]
            return Finding(
                "pip-audit", cve, osv_severity(ids), "vulnerability",
                f"{dep['name']} {dep['version']}{where}: {cve} — fixed in {fix}. {summary}",
                manifest, line,
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            result.findings = list(pool.map(build, pending))
        result.metrics["vulnerable_dependencies"] = len(vulnerable)
        result.metrics["dependency_vulnerabilities"] = len(result.findings)
        result.metrics["dependency_critical_vulnerabilities"] = sum(
            f.severity in ("blocker", "critical") for f in result.findings
        )
        return result


def declaration_line(text, package):
    target = normalize(package)
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"""\s*["']?([A-Za-z0-9][A-Za-z0-9._-]*)""", line)
        if m and normalize(m[1]) == target:
            return i
    return None
