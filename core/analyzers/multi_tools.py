import csv
import io
import json
import os
import tempfile
from pathlib import Path

from .base import CODE, JS, PY, Analyzer, C, Finding, Result, node_tool
from .python_tools import complexity_severity

SEMGREP_SEVERITY = {"ERROR": "critical", "WARNING": "major", "INFO": "minor"}
SEMGREP_TYPE = {"security": "vulnerability", "correctness": "bug"}

CPPCHECK_SEVERITY = {
    "error": ("critical", "bug"),
    "warning": ("major", "bug"),
    "portability": ("minor", "bug"),
    "performance": ("minor", "code_smell"),
    "style": ("minor", "code_smell"),
}
CPPCHECK_NOISE = {"missingInclude", "missingIncludeSystem", "checkersReport", "unmatchedSuppression",
                  "toomanyconfigs", "normalCheckLevelMaxBranches", "unknownMacro", "syntaxError"}

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
                    Finding("lizard", "cyclomatic-complexity", complexity_severity(ccn, threshold), "code_smell",
                            f"{func} has cyclomatic complexity {ccn} (threshold {threshold})",
                            ctx.rel(path), start, end)
                )
        result.metrics["complexity_other"] = total
        return result


class Semgrep(Analyzer):
    name = executable = "semgrep"
    extensions = CODE

    def run(self, ctx):
        args = ["scan", "--config", ctx.semgrep_config, "--json", "--metrics=off", "--quiet",
                "--disable-version-check", *ctx.files_with(CODE)]
        data = json.loads(self.exec(args, ctx, ok_codes=(0, 1)))
        result = Result()
        for item in data["results"]:
            extra = item["extra"]
            result.findings.append(
                Finding("semgrep", item["check_id"], SEMGREP_SEVERITY.get(extra.get("severity"), "minor"),
                        semgrep_type(item["check_id"], extra.get("metadata", {})), extra["message"].strip(),
                        ctx.rel(item["path"]), item["start"]["line"], item["end"]["line"])
            )
        return result


def semgrep_type(check_id, metadata):
    category = metadata.get("category", "")
    # "audit" rules flag security-sensitive code that needs a human look rather than a confirmed flaw.
    if category == "security" and (".audit." in check_id or "audit" in metadata.get("subcategory", [])):
        return "security_hotspot"
    return SEMGREP_TYPE.get(category, "code_smell")


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
            for side, path, other_side, other in zip(sides, paths, sides[::-1], paths[::-1]):
                if path not in tracked:
                    continue
                start, end = side["start"], side["end"]
                result.duplicated_lines.setdefault(path, set()).update(range(start, end + 1))
                result.findings.append(
                    Finding("jscpd", "duplicated-block", "minor", "code_smell",
                            f"{end - start + 1} duplicated lines, also in {other}:{other_side['start']}",
                            path, start, end)
                )
        dup_lines = sum(len(v) for v in result.duplicated_lines.values())
        total = data.get("statistics", {}).get("total", {}).get("lines") or 0
        result.metrics["duplicated_lines"] = dup_lines
        if total:
            result.metrics["duplicated_lines_percent"] = round(100 * dup_lines / total, 2)
        return result
