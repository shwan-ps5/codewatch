import csv
import io
import json
import os
import tempfile
from pathlib import Path

import yaml

from .base import (
    BUG,
    CODE,
    CODE_SMELL,
    CRITICAL,
    HOTSPOT,
    JS,
    MAJOR,
    MINOR,
    PY,
    VULNERABILITY,
    Analyzer,
    C,
    Finding,
    Result,
    isolated_tool,
    node_tool,
)
from .constant_branches import blank_dead_branches
from .python_tools import complexity_severity
from .slices import index_slices

SEMGREP_SEVERITY = {"ERROR": CRITICAL, "WARNING": MAJOR, "INFO": MINOR}
SEMGREP_TYPE = {"security": VULNERABILITY, "correctness": BUG}

CPPCHECK_SEVERITY = {
    "error": (CRITICAL, BUG),
    "warning": (MAJOR, BUG),
    "portability": (MINOR, BUG),
    "performance": (MINOR, CODE_SMELL),
    "style": (MINOR, CODE_SMELL),
}
CPPCHECK_NOISE = {"missingInclude", "missingIncludeSystem", "checkersReport", "unmatchedSuppression",
                  "toomanyconfigs", "normalCheckLevelMaxBranches", "unknownMacro", "syntaxError"}
# Structs declared in headers often mirror an external layout (SDK, hardware, file format): every field exists
# to match it, so cppcheck's "never read" is expected there. Structs local to a .c/.cpp file are still checked.
HEADER_ONLY_NOISE = {"unusedStructMember"}
HEADERS = {".h", ".hh", ".hpp", ".hxx", ".inl"}

JSCPD_FORMATS = "python,javascript,typescript,jsx,tsx,c,cpp,java,go,rust,csharp"


class Lizard(Analyzer):
    """Complexity for non-Python languages; radon covers Python."""

    name = executable = "lizard"
    extensions = JS | C | (CODE - PY)

    def run(self, ctx):
        files = ctx.files_with(self.extensions)
        out = self.exec(["--csv", *files], ctx, ok_codes=(0, 1))
        threshold = ctx.complexity_threshold
        result = Result()
        total = 0
        for row in csv.reader(io.StringIO(out)):
            if len(row) < 11 or not row[1].isdigit():
                continue
            ccn, path, func, start, end = int(row[1]), row[6], row[7], int(row[9]), int(row[10])
            total += ccn
            if ccn > threshold:
                result.findings.append(
                    Finding("lizard", "cyclomatic-complexity", complexity_severity(ccn, threshold), CODE_SMELL,
                            f"{func} has cyclomatic complexity {ccn} (threshold {threshold})",
                            ctx.rel(path), start, end)
                )
        result.metrics["complexity_other"] = total
        return result


class Semgrep(Analyzer):
    name = executable = "semgrep"
    extensions = CODE | {".yml", ".yaml", ".html"}

    def binary(self):
        # Own venv: semgrep pins dependencies (e.g. an old mcp) that conflict with codewatch's.
        return isolated_tool("semgrep") or super().binary()

    def run(self, ctx):
        with tempfile.NamedTemporaryFile("w", suffix=".yml") as custom, tempfile.TemporaryDirectory() as copies:
            configs = ["--config", ctx.semgrep_config] if ctx.semgrep_config else []
            custom_ids = []
            if ctx.custom_rules:
                custom.write(ctx.custom_rules)
                custom.flush()
                configs += ["--config", custom.name]
                custom_ids = [r["id"] for r in yaml.safe_load(ctx.custom_rules).get("rules", [])]
            if not configs:
                return Result()
            targets, originals = analysis_copies(ctx, ctx.files_with(self.extensions), Path(copies))
            args = ["scan", *configs, "--json", "--metrics=off", "--quiet", "--disable-version-check", *targets]
            data = json.loads(self.exec(args, ctx, ok_codes=(0, 1)))
        result = Result()
        for item in data["results"]:
            item["path"] = originals.get(item["path"], item["path"])
            extra = item["extra"]
            # Semgrep prefixes rules from a local file with path segments; map them back to codewatch's IDs.
            custom_id = next((cid for cid in custom_ids if item["check_id"].endswith(cid)), None)
            result.findings.append(
                Finding("codewatch" if custom_id else "semgrep", custom_id or item["check_id"], SEMGREP_SEVERITY.get(extra.get("severity"), MINOR),
                        semgrep_type(item["check_id"], extra.get("metadata", {})), extra["message"].strip(),
                        ctx.rel(item["path"]), item["start"]["line"], item["end"]["line"])
            )
        return result


def analysis_copy(source):
    """Python source as Semgrep should see it: dead constant branches blanked and slices made indexes.
    None when nothing changes."""
    folded = blank_dead_branches(source)
    indexed = index_slices(folded or source)
    return indexed or folded


def analysis_copies(ctx, files, copies):
    """Targets for Semgrep: Python files that need it are scanned as rewritten copies (see analysis_copy).
    Returns the target list and {copy path: original relative path}."""
    targets, originals = [], {}
    for rel in files:
        rewritten = None
        if rel.endswith(".py"):
            try:
                rewritten = analysis_copy((ctx.root / rel).read_text())
            except (OSError, UnicodeDecodeError):
                rewritten = None
        if rewritten is None:
            targets.append(rel)
            continue
        copy = copies / rel
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_text(rewritten)
        targets.append(str(copy))
        originals[str(copy)] = rel
    return targets, originals


def semgrep_type(check_id, metadata):
    """Only rules Semgrep marks "vuln" (taint-checked or a definite flaw) are vulnerabilities;
    "audit" and other security rules flag risky code to review, so they're hotspots."""
    category = metadata.get("category", "")
    if category != "security":
        return SEMGREP_TYPE.get(category, CODE_SMELL)
    vuln = "vuln" in (metadata.get("subcategory") or []) and ".audit." not in check_id
    return VULNERABILITY if vuln else HOTSPOT


class Cppcheck(Analyzer):
    name = executable = "cppcheck"
    extensions = C

    def run(self, ctx):
        with tempfile.NamedTemporaryFile("w", suffix=".txt") as listing:
            listing.write("\n".join(ctx.files_with(C)))
            listing.flush()
            err = self.exec(
                ["--enable=warning,style,performance,portability", "--inline-suppr", "--quiet",
                 "--max-configs=1", f"-j{os.cpu_count() or 2}",
                 "--template={file}\t{line}\t{severity}\t{id}\t{message}", f"--file-list={listing.name}"],
                ctx, stream="stderr",
            )
        result = Result()
        for line in err.splitlines():
            parts = line.split("\t", 4)
            if len(parts) != 5 or parts[3] in CPPCHECK_NOISE or parts[2] not in CPPCHECK_SEVERITY:
                continue
            path, lineno, sev, rule, message = parts
            if rule in HEADER_ONLY_NOISE and Path(path).suffix.lower() in HEADERS:
                continue
            severity, type_ = CPPCHECK_SEVERITY[sev]
            result.findings.append(
                Finding("cppcheck", rule, severity, type_, message, ctx.rel(path), int(lineno) or None)
            )
        return result


class Jscpd(Analyzer):
    name = executable = "jscpd"
    extensions = CODE

    def binary(self):
        return node_tool("jscpd")

    def run(self, ctx):
        with tempfile.TemporaryDirectory() as out_dir:
            self.exec(["--reporters", "json", "--output", out_dir, "--silent",
                       "--absolute", "--format", JSCPD_FORMATS, "--min-tokens", "70",
                       *(["--ignore", ",".join(ctx.exclusions)] if ctx.exclusions else []), str(ctx.root)],
                      ctx, cwd=out_dir)
            report = Path(out_dir) / "jscpd-report.json"
            data = json.loads(report.read_text()) if report.exists() else {"duplicates": [], "statistics": {}}
        tracked = set(ctx.files)
        result = Result()
        for dup in data["duplicates"]:
            sides = [dup["firstFile"], dup["secondFile"]]
            paths = [ctx.rel(s["name"]) for s in sides]
            for side, path, other_side, other in zip(sides, paths, sides[::-1], paths[::-1], strict=True):
                if path not in tracked:
                    continue
                start, end = side["start"], side["end"]
                result.duplicated_lines.setdefault(path, set()).update(range(start, end + 1))
                result.findings.append(
                    Finding("jscpd", "duplicated-block", MINOR, CODE_SMELL,
                            f"{end - start + 1} duplicated lines, also in {other}:{other_side['start']}",
                            path, start, end)
                )
        dup_lines = sum(len(v) for v in result.duplicated_lines.values())
        total = data.get("statistics", {}).get("total", {}).get("lines") or 0
        result.metrics["duplicated_lines"] = dup_lines
        if total:
            result.metrics["duplicated_lines_percent"] = round(100 * dup_lines / total, 2)
        return result
