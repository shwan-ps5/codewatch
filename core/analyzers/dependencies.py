import fnmatch
import json
import re
import tomllib
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

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


# --- JavaScript lockfiles, checked against OSV directly ------------------------------------------------------

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_BATCH_SIZE = 1000
LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
YARN_VERSION_RE = re.compile(r"""^\s+version:?\s+"?([^"\s]+)"?\s*$""")
PNPM_PEER_SUFFIX_RE = re.compile(r"[(_].*$")


def mark(found, package, dev):
    """A package counts as development-only when every place that installs it says so."""
    found[package] = found.get(package, True) and bool(dev)


def package_lock_packages(text):
    """{(name, version): development only} from package-lock.json / npm-shrinkwrap.json, lockfile versions 1-3."""
    data = json.loads(text)
    found = {}
    for key, entry in (data.get("packages") or {}).items():
        if "node_modules/" not in key or entry.get("link") or not entry.get("version"):
            continue
        name = entry.get("name") or key.rsplit("node_modules/", 1)[1]
        mark(found, (name, entry["version"]), entry.get("dev") or entry.get("devOptional"))
    stack = list((data.get("dependencies") or {}).items()) if not data.get("packages") else []
    while stack:
        name, entry = stack.pop()
        if isinstance(entry, dict) and entry.get("version") and not str(entry["version"]).startswith("file:"):
            mark(found, (name, entry["version"]), entry.get("dev"))
            stack.extend((entry.get("dependencies") or {}).items())
    return found


def yarn_spec_name(spec):
    """`"@scope/pkg@^1.2"` or `pkg@npm:^1.2` -> the package name; None for workspace, patch and link entries."""
    spec = spec.strip().strip('"')
    at = spec.find("@", 1)
    name, rest = (spec[:at], spec[at + 1:]) if at > 0 else ("", "")
    if not name or rest.startswith(("workspace:", "patch:", "link:", "portal:", "file:")):
        return None
    return name


def yarn_lock_packages(text):
    """{(name, version): False} from yarn.lock, classic (v1) and Berry formats, which don't mark dev packages."""
    found, names = {}, []
    for line in text.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":") and not line.startswith("#"):
            names = [n for n in (yarn_spec_name(s) for s in line.rstrip()[:-1].split(",")) if n]
        elif names and (match := YARN_VERSION_RE.match(line)):
            found.update(((name, match[1]), False) for name in names)
            names = []
    return found


def pnpm_lock_packages(text):
    """{(name, version): development only} from pnpm-lock.yaml: `/name/1.2.3` (v5), `/name@1.2.3(peer)` (v6) or
    `name@1.2.3` (v9, which no longer marks dev packages)."""
    data = yaml.safe_load(text) or {}
    found = {}
    for raw, entry in (data.get("packages") or {}).items():
        key = PNPM_PEER_SUFFIX_RE.sub("", str(raw).lstrip("/"))
        at = key.rfind("@")
        if at > 0:
            name, version = key[:at], key[at + 1:]
        else:
            name, _, version = key.rpartition("/")
        if name and version and version[0].isdigit():
            mark(found, (name, version), isinstance(entry, dict) and entry.get("dev"))
    return found


LOCKFILE_PARSERS = {"package-lock.json": package_lock_packages, "npm-shrinkwrap.json": package_lock_packages,
                    "yarn.lock": yarn_lock_packages, "pnpm-lock.yaml": pnpm_lock_packages}


def osv_post(url, body):
    request = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as resp:
        return json.load(resp)


def osv_get(vuln_id):
    with urllib.request.urlopen(OSV_URL.format(vuln_id), timeout=10) as resp:
        return json.load(resp)


def osv_advisories(packages):
    """{(name, version): [vulnerability id]} for npm packages, in batches."""
    packages = sorted(packages)
    hits = {}
    for start in range(0, len(packages), OSV_BATCH_SIZE):
        chunk = packages[start:start + OSV_BATCH_SIZE]
        body = {"queries": [{"package": {"name": n, "ecosystem": "npm"}, "version": v} for n, v in chunk]}
        for pkg, result in zip(chunk, osv_post(OSV_BATCH_URL, body).get("results", []), strict=False):
            ids = [v["id"] for v in result.get("vulns") or []]
            if ids:
                hits[pkg] = ids
    return hits


def fixed_versions(vuln, name):
    return sorted({event["fixed"] for affected in vuln.get("affected", [])
                   if affected.get("package", {}).get("name") == name
                   for rng in affected.get("ranges", []) for event in rng.get("events", []) if "fixed" in event})


def lockfile_line(text, name):
    """Line where the lockfile lists the package, or None."""
    needles = (f'"node_modules/{name}"', f'"{name}@', f"{name}@", f"/{name}@", f"/{name}/", f'"{name}": {{')
    for i, line in enumerate(text.splitlines(), 1):
        if any(n in line for n in needles):
            return i
    return None


class OsvLockfiles(Analyzer):
    """Known advisories in the exact package versions an npm, yarn or pnpm lockfile pins, looked up in OSV."""

    name = "osv"

    def applies(self, ctx):
        return any(Path(f).name in LOCKFILES for f in ctx.files)

    def available(self):
        return True

    def run(self, ctx):
        locked = {}
        for f in ctx.files:
            parse = LOCKFILE_PARSERS.get(Path(f).name)
            if not parse:
                continue
            try:
                text = (ctx.root / f).read_text(errors="replace")
                packages = parse(text)
            except (OSError, ValueError, yaml.YAMLError):
                continue
            locked[f] = (text, packages)
        try:
            advisories = osv_advisories({pkg for _, packages in locked.values() for pkg in packages})
        except (OSError, ValueError) as exc:
            raise ToolError(f"OSV query failed: {exc}") from exc
        ids = sorted({i for found in advisories.values() for i in found})
        with ThreadPoolExecutor(max_workers=8) as pool:
            details = dict(zip(ids, pool.map(self.details, ids), strict=True))
        result = Result()
        for path, (text, packages) in sorted(locked.items()):
            for (name, version), dev in sorted(packages.items()):
                for vid in advisories.get((name, version), []):
                    result.findings.append(self.finding(path, text, (name, version, dev), details.get(vid) or {"id": vid}))
        result.metrics["vulnerable_dependencies"] = len({pkg for _, packages in locked.values() for pkg in packages
                                                         if pkg in advisories})
        result.metrics["dependency_vulnerabilities"] = len(result.findings)
        result.metrics["dependency_critical_vulnerabilities"] = sum(
            f.severity in ("blocker", "critical") for f in result.findings)
        return result

    @staticmethod
    def details(vuln_id):
        try:
            return osv_get(vuln_id)
        except (OSError, ValueError):
            return None

    @staticmethod
    def finding(path, text, package, vuln):
        """A development-only package (build tools, test runners) isn't shipped, so its advisory is for review."""
        name, version, dev = package
        ids = [vuln["id"], *vuln.get("aliases", [])]
        cve = next((a for a in ids if a.startswith("CVE-")), vuln["id"])
        rating = vuln.get("database_specific", {}).get("severity")
        fix = ", ".join(fixed_versions(vuln, name)) or "none available"
        summary = vuln.get("summary") or advisory_summary(vuln)
        where = " (development only)" if dev else ""
        return Finding("osv", cve, OSV_SEVERITY.get(rating, "major"), "security_hotspot" if dev else "vulnerability",
                       f"{name} {version}{where}: {cve} \u2014 fixed in {fix}. {summary}"[:600], path,
                       lockfile_line(text, name))
