import ast
import json
import re
import tempfile
from pathlib import Path

from .base import (
    BLOCKER,
    BUG,
    CODE_SMELL,
    HOTSPOT,
    JS,
    MAJOR,
    MINOR,
    PY,
    TOOLS_DIR,
    VULNERABILITY,
    Analyzer,
    Finding,
    Result,
    isolated_tool,
    node_tool,
)
from .python_tools import LineCache, complexity_severity

# Lines naming a commit, checksum or integrity hash: high-entropy by design, not credentials.
NOT_SECRET_LINES = (r"""(?i)["']?(commit|sha\d{0,3}|hash|digest|integrity|checksum|etag|rev|revision|provenance"""
                    r"""|fingerprint)["']?\s{0,5}[:=]""")
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
                        CODE_SMELL, f"{name} has cognitive complexity {row['complexity']} "
                                      f"(threshold {threshold})", path, start, end)
            )
        result.metrics["cognitive_complexity"] = sum(r["complexity"] for r in rows)
        return result


# Without Django's mypy plugin, pyright misreads model fields (descriptors) and a few Django internals.
# These message shapes are only ever those misreadings, so they're dropped rather than reported.
KNOWN_FALSE_POSITIVES = [
    re.compile(r'parameter "default" of type "type\[NOT_PROVIDED\]"'),
    re.compile(r'not assignable to declared type "cached_property"'),
    re.compile(r'Method "__str__" overrides class "Model" in an incompatible manner'),
    re.compile(r'on type "\w{1,60}Field"'),
    re.compile(r'Object of type "\(\.\.\.\) -> object" cannot be used with "with"'),
]


def known_false_positive(message):
    return any(p.search(message) for p in KNOWN_FALSE_POSITIVES)


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
            if d["severity"] != "error" or known_false_positive(d["message"]):
                continue
            # File-level diagnostics (e.g. a file that can't be read) carry no range.
            where = d.get("range")
            start, end = (where["start"]["line"] + 1, where["end"]["line"] + 1) if where else (None, None)
            result.findings.append(
                Finding("basedpyright", d.get("rule") or "type-error", MAJOR, BUG,
                        d["message"].split("\n")[0], ctx.rel(d["file"]), start, end)
            )
        return result


class Secrets(Analyzer):
    """Hard-coded credentials and API keys with detect-secrets, plus known token formats it has no plugin for."""

    name = "detect-secrets"
    executable = "detect-secrets"

    def run(self, ctx):
        out = self.exec(["scan", "--exclude-lines", NOT_SECRET_LINES, *ctx.files], ctx)
        result = Result()
        lines = LineCache(ctx.root)
        for path, items in json.loads(out)["results"].items():
            by_line = {}
            for item in items:
                by_line.setdefault(item["line_number"], set()).add(item["type"])
            for line, types in sorted(by_line.items()):
                if types <= ENTROPY_ONLY and not CREDENTIAL_CONTEXT_RE.search(credential_context(lines, path, line)):
                    continue
                specific = sorted(types - SECRET_HEURISTICS)
                result.findings.append(
                    Finding("detect-secrets", specific[0] if specific else min(types),
                            BLOCKER if specific else MAJOR,
                            VULNERABILITY if specific else HOTSPOT,
                            f"Possible hard-coded secret ({', '.join(sorted(types))}); move it to configuration "
                            "or a secret store, and rotate it if it was ever committed", ctx.rel(path), line)
                )
        result.findings += known_tokens(ctx, {(f.path, f.line) for f in result.findings})
        return result


# A random-looking string alone is usually a hash, id or fixture; it's a secret candidate when named like one.
ENTROPY_ONLY = {"Base64 High Entropy String", "Hex High Entropy String"}
CREDENTIAL_CONTEXT_RE = re.compile(
    r"(?i)(?<![a-z])(?:api_?|private_?|secret_?|access_?|signing_?)?keys?(?![a-z])|apikey|token|secret|passw|pwd"
    r"|(?<![a-z])auth(?!or)|credential|bearer|signature"
)
TOKEN_FORMATS = [
    ("SonarQube Token", re.compile(r"\b(?:squ|sqp|sqa)_[0-9a-f]{40}\b")),
    ("GitHub Token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b")),
    ("GitLab Token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,64}")),
    ("Anthropic API Key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,200}")),
    ("OpenAI API Key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,200}T3BlbkFJ[A-Za-z0-9]{20,200}")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Hugging Face Token", re.compile(r"\bhf_[A-Za-z0-9]{34,40}\b")),
    ("npm Token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("codewatch Token", re.compile(r"\bcw_[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])")),
]
MAX_TOKEN_SCAN_BYTES = 2 * 1024 * 1024


def credential_context(lines, path, line):
    """In Python, the whole function around the string (check_password() comparing a hard-coded hash); in data
    and other files just the line, since neighbouring JSON keys say nothing about this value."""
    return lines.function_text(path, line) if path.endswith(".py") else lines.get(path, line)


def known_tokens(ctx, already):
    findings = []
    for path in ctx.files:
        full = ctx.root / path
        try:
            if full.stat().st_size > MAX_TOKEN_SCAN_BYTES:
                continue
            text = full.read_text(errors="strict")
        except (OSError, UnicodeDecodeError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if (path, n) in already:
                continue
            kind = next((k for k, pattern in TOKEN_FORMATS if pattern.search(line)), None)
            if kind:
                findings.append(Finding("detect-secrets", kind, BLOCKER, VULNERABILITY,
                                        f"{kind} committed to the repository; revoke it and load it from configuration",
                                        path, n))
    return findings


class Checkov(Analyzer):
    """Misconfigurations in Dockerfiles, Terraform, Kubernetes manifests and GitHub Actions workflows."""

    name = executable = "checkov"

    def binary(self):
        return isolated_tool(self.name) or super().binary()

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
    return Finding(Checkov.name, check["check_id"], MAJOR, HOTSPOT, check["check_name"] + resource,
                   checkov_path(ctx, check["file_path"]), first or None, last or None)


def checkov_path(ctx, path):
    """Checkov reports paths as absolute or as "/relative/to/root" depending on how files were passed."""
    if path.startswith(str(ctx.root)):
        return ctx.rel(path)
    return path.lstrip("/")


class EslintQuality(Analyzer):
    """Bugs, risky APIs and maintainability for JS/TS: ESLint core rules plus eslint-plugin-security."""

    name = executable = "eslint"
    extensions = JS

    def binary(self):
        return node_tool(self.name)

    def run(self, ctx):
        result = Result()
        result.findings = drop_shared_globals(ctx, self.lint(ctx, "eslint-quality.config.js", ctx.files_with(JS)))
        typed = typed_ts_files(ctx)
        if typed:
            # A file the TypeScript project can't load reports a parse error here; the main pass already covers it.
            result.findings += [f for f in self.lint(ctx, "eslint-typed.config.js", typed) if f.rule != "parse-error"]
        return result

    def lint(self, ctx, config, files):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            self.exec(["--config", str(TOOLS_DIR / config), "--format", "json", "--output-file", str(report),
                       "--no-warn-ignored", *files], ctx, ok_codes=(0, 1))
            data = json.loads(report.read_text()) if report.exists() else []
        findings = []
        for file_report in data:
            for m in file_report["messages"]:
                rule = m.get("ruleId") or "parse-error"
                severity, type_ = eslint_classify(rule, m.get("severity"))
                findings.append(Finding(self.name, rule, severity, type_, m["message"],
                                        ctx.rel(file_report["filePath"]), m.get("line"), m.get("endLine")))
        return findings


TS = {".ts", ".tsx", ".mts", ".cts"}


def typed_ts_files(ctx):
    """TypeScript files with a tsconfig.json in their directory or above it (within the scanned tree)."""
    configs = {Path(f).parent for f in ctx.files if Path(f).name == "tsconfig.json"}
    return [f for f in ctx.files_with(TS) if any(d == Path(".") or d in Path(f).parents for d in configs)]


UNDEFINED_RE = re.compile(r"^'([\w$]{1,100})' is not defined")
TOP_LEVEL_DEF_RE = re.compile(r"^(?:async\s+)?(?:function\*?|var|let|const|class)\s+([\w$]{1,100})", re.MULTILINE)
GLOBAL_ASSIGN_RE = re.compile(r"\b(?:window|globalThis|self)\.([\w$]{1,100})\s{0,5}=[^=]")
HOST_GLOBAL_MIN_FILES = 3


def drop_shared_globals(ctx, findings):
    """no-undef sees one file at a time. Names another script defines at top level, or that several files use
    without anyone defining them (globals the host page or runtime injects), are not undefined."""
    undefined = [(f, m[1]) for f in findings if f.rule == "no-undef" and (m := UNDEFINED_RE.match(f.message))]
    if not undefined:
        return findings
    defined = set()
    for path in ctx.files_with(JS):
        try:
            text = (ctx.root / path).read_text(errors="replace")
        except OSError:
            continue
        defined.update(TOP_LEVEL_DEF_RE.findall(text))
        defined.update(GLOBAL_ASSIGN_RE.findall(text))
    files_using = {}
    for f, name in undefined:
        files_using.setdefault(name, set()).add(f.path)
    shared = {n for n, paths in files_using.items() if n in defined or len(paths) >= HOST_GLOBAL_MIN_FILES}
    drop = {id(f) for f, name in undefined if name in shared}
    return [f for f in findings if id(f) not in drop]


ESLINT_BUG_RULES = {
    "no-undef", "no-unreachable", "no-dupe-keys", "no-dupe-else-if", "no-self-compare", "no-cond-assign",
    "no-unmodified-loop-condition", "no-unreachable-loop", "use-isnan", "valid-typeof", "no-func-assign",
    "no-import-assign", "no-const-assign", "no-unsafe-finally", "no-unsafe-negation", "no-fallthrough",
    "no-sparse-arrays", "no-compare-neg-zero", "getter-return", "no-setter-return", "no-async-promise-executor",
    "require-atomic-updates", "eqeqeq", "no-throw-literal", "no-unused-expressions", "consistent-return",
    "no-mixed-operators", "no-restricted-syntax", "@typescript-eslint/no-floating-promises",
    "@typescript-eslint/no-misused-promises",
}


def eslint_classify(rule, level):
    if rule == "parse-error":
        return MAJOR, BUG
    if rule.startswith("security/") or rule in ("no-eval", "no-implied-eval", "no-new-func"):
        return MAJOR, HOTSPOT
    if rule in ESLINT_BUG_RULES:
        return (MAJOR if level == 2 else MINOR), BUG
    return MINOR, CODE_SMELL


class Stylelint(Analyzer):
    """CSS errors (invalid values, unknown properties, duplicates) with stylelint's recommended rules."""

    name = executable = "stylelint"
    extensions = {".css"}

    def binary(self):
        return node_tool(self.name)

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
                    Finding(self.name, w["rule"], MAJOR if error else MINOR, BUG if error else CODE_SMELL,
                            w["text"].removesuffix(f" ({w['rule']})"), ctx.rel(file_report["source"]),
                            w.get("line"), w.get("endLine"))
                )
        return result
