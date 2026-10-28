import ast
import json
import tempfile
from pathlib import Path

from .base import JS, PY, TOOLS_DIR, Analyzer, Finding, Result, node_tool
from .python_tools import complexity_severity

SECRET_HEURISTICS = {"Base64 High Entropy String", "Hex High Entropy String", "Secret Keyword"}
DOCKERFILES = ("Dockerfile", "Containerfile")


def function_lines(path):
    """Qualified name ("Class::method") -> (first line, last line), as complexipy names functions."""
    try:
        tree = ast.parse(path.read_text(errors="replace"))
    except (OSError, SyntaxError, ValueError):
        return {}
    found = {}

    def walk(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = f"{prefix}::{child.name}" if prefix else child.name
                if not isinstance(child, ast.ClassDef):
                    found.setdefault(name, (child.lineno, child.end_lineno))
                walk(child, name)

    walk(tree, "")
    return found


class CognitiveComplexity(Analyzer):
    """How hard code is to follow: nesting and breaks in linear flow cost more than plain branches."""

    name = executable = "complexipy"
    extensions = PY

    def run(self, ctx):
        threshold = ctx.cognitive_threshold
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"
            self.exec([*ctx.files_with(PY), "--output-format", "json", "--output", str(out), "--quiet",
                       "--ignore-complexity", "--cache-dir", tmp], ctx, ok_codes=(0, 1))
            rows = json.loads(out.read_text()) if out.exists() else []
        result = Result()
        lines_by_file = {}
        for row in rows:
            if row["complexity"] <= threshold:
                continue
            path = ctx.rel(row["path"])
            if path not in lines_by_file:
                lines_by_file[path] = function_lines(ctx.root / path)
            start, end = lines_by_file[path].get(row["function_name"], (None, None))
            name = row["function_name"].replace("::", ".")
            result.findings.append(
                Finding("complexipy", "cognitive-complexity", complexity_severity(row["complexity"], threshold),
                        "code_smell", f"{name} has cognitive complexity {row['complexity']} "
                                      f"(threshold {threshold})", path, start, end)
            )
        result.metrics["cognitive_complexity"] = sum(r["complexity"] for r in rows)
        return result


class TypeCheck(Analyzer):
    """Type errors (wrong arguments, None access, bad returns) with basedpyright in standard mode."""

    name = "basedpyright"
    executable = "basedpyright"
    extensions = PY

    def run(self, ctx):
        config = {
            "typeCheckingMode": "standard",
            "include": [str(ctx.root / f) for f in ctx.files_with(PY)],
            # Third-party packages may not be installed where the scan runs; unresolved imports are not code bugs.
            "reportMissingImports": "none",
            "reportMissingModuleSource": "none",
            "reportAttributeAccessIssue": "warning",
        }
        venv = next((ctx.root / v for v in ("venv", ".venv") if (ctx.root / v / "bin" / "python").exists()), None)
        if venv:
            config.update(venvPath=str(venv.parent), venv=venv.name)
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "pyrightconfig.json"
            cfg.write_text(json.dumps(config))
            out = self.exec(["--outputjson", "--project", str(cfg)], ctx, ok_codes=(0, 1))
        result = Result()
        for d in json.loads(out or "{}").get("generalDiagnostics", []):
            if d["severity"] != "error":
                continue
            start, end = d["range"]["start"]["line"] + 1, d["range"]["end"]["line"] + 1
            result.findings.append(
                Finding("basedpyright", d.get("rule") or "type-error", "major", "bug",
                        d["message"].split("\n")[0], ctx.rel(d["file"]), start, end)
            )
        return result


class Secrets(Analyzer):
    """Hard-coded credentials and API keys with detect-secrets."""

    name = "detect-secrets"
    executable = "detect-secrets"

    def run(self, ctx):
        out = self.exec(["scan", *ctx.files], ctx)
        result = Result()
        for path, items in json.loads(out)["results"].items():
            by_line = {}
            for item in items:
                by_line.setdefault(item["line_number"], set()).add(item["type"])
            for line, types in sorted(by_line.items()):
                specific = sorted(types - SECRET_HEURISTICS)
                result.findings.append(
                    Finding("detect-secrets", specific[0] if specific else min(types),
                            "blocker" if specific else "major",
                            "vulnerability" if specific else "security_hotspot",
                            f"Possible hard-coded secret ({', '.join(sorted(types))}); move it to configuration "
                            "or a secret store, and rotate it if it was ever committed", ctx.rel(path), line)
                )
        return result


class Checkov(Analyzer):
    """Misconfigurations in Dockerfiles, Terraform, Kubernetes manifests and GitHub Actions workflows."""

    name = "checkov"
    executable = "checkov"

    def binary(self):
        path = TOOLS_DIR / "checkov-venv" / "bin" / "checkov"
        return str(path) if path.exists() else super().binary()

    def applies(self, ctx):
        return any(self.is_iac(f) for f in ctx.files)

    @staticmethod
    def is_iac(path):
        p = Path(path)
        return (p.name.startswith(DOCKERFILES) or p.suffix == ".tf"
                or (p.suffix in (".yml", ".yaml") and ".github/workflows" in path))

    def run(self, ctx):
        files = [f for f in ctx.files if self.is_iac(f)]
        args = ["--output", "json", "--quiet", "--compact", "--skip-download",
                "--framework", "dockerfile", "terraform", "github_actions", "kubernetes"]
        for f in files:
            args += ["--file", f]
        out = self.exec(args, ctx, ok_codes=(0, 1))
        reports = json.loads(out or "[]")
        result = Result()
        for report in reports if isinstance(reports, list) else [reports]:
            result.findings += [checkov_finding(ctx, c) for c in report.get("results", {}).get("failed_checks", [])]
        return result


def checkov_finding(ctx, check):
    first, last = check.get("file_line_range") or [None, None]
    resource = f" ({check['resource']})" if check.get("resource") else ""
    return Finding("checkov", check["check_id"], "major", "security_hotspot", check["check_name"] + resource,
                   checkov_path(ctx, check["file_path"]), first or None, last or None)


def checkov_path(ctx, path):
    """Checkov reports paths as absolute or as "/relative/to/root" depending on how files were passed."""
    if path.startswith(str(ctx.root)):
        return ctx.rel(path)
    return path.lstrip("/")


class EslintQuality(Analyzer):
    """Bugs, risky APIs and maintainability for JS/TS: ESLint core rules plus eslint-plugin-security."""

    name = "eslint"
    executable = "eslint"
    extensions = JS

    def binary(self):
        return node_tool("eslint")

    def run(self, ctx):
        config = TOOLS_DIR / "eslint-quality.config.js"
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            self.exec(["--config", str(config), "--format", "json", "--output-file", str(report),
                       "--no-warn-ignored", *ctx.files_with(JS)], ctx, ok_codes=(0, 1))
            data = json.loads(report.read_text()) if report.exists() else []
        result = Result()
        for file_report in data:
            for m in file_report["messages"]:
                rule = m.get("ruleId") or "parse-error"
                severity, type_ = eslint_classify(rule, m.get("severity"))
                result.findings.append(
                    Finding("eslint", rule, severity, type_, m["message"], ctx.rel(file_report["filePath"]),
                            m.get("line"), m.get("endLine"))
                )
        return result


ESLINT_BUG_RULES = {
    "no-undef", "no-unreachable", "no-dupe-keys", "no-dupe-else-if", "no-self-compare", "no-cond-assign",
    "no-unmodified-loop-condition", "no-unreachable-loop", "use-isnan", "valid-typeof", "no-func-assign",
    "no-import-assign", "no-const-assign", "no-unsafe-finally", "no-unsafe-negation", "no-fallthrough",
    "no-sparse-arrays", "no-compare-neg-zero", "getter-return", "no-setter-return", "no-async-promise-executor",
    "require-atomic-updates", "eqeqeq", "no-throw-literal", "no-unused-expressions", "consistent-return",
}


def eslint_classify(rule, level):
    if rule == "parse-error":
        return "major", "bug"
    if rule.startswith("security/") or rule in ("no-eval", "no-implied-eval", "no-new-func"):
        return "major", "security_hotspot"
    if rule in ESLINT_BUG_RULES:
        return ("major" if level == 2 else "minor"), "bug"
    return "minor", "code_smell"


class Stylelint(Analyzer):
    """CSS errors (invalid values, unknown properties, duplicates) with stylelint's recommended rules."""

    name = "stylelint"
    executable = "stylelint"
    extensions = {".css"}

    def binary(self):
        return node_tool("stylelint")

    def run(self, ctx):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            self.exec(["--config", str(TOOLS_DIR / "stylelint.config.json"), "--formatter", "json",
                       "--output-file", str(report), "--allow-empty-input", *ctx.files_with(self.extensions)],
                      ctx, ok_codes=(0, 2))
            data = json.loads(report.read_text()) if report.exists() else []
        result = Result()
        for file_report in data:
            for w in file_report["warnings"]:
                error = w["severity"] == "error"
                result.findings.append(
                    Finding("stylelint", w["rule"], "major" if error else "minor", "bug" if error else "code_smell",
                            w["text"].removesuffix(f" ({w['rule']})"), ctx.rel(file_report["source"]),
                            w.get("line"), w.get("endLine"))
                )
        return result
