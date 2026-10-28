import json
import re

from .base import (
    BLOCKER,
    BUG,
    CODE_SMELL,
    CRITICAL,
    HOTSPOT,
    INFO,
    MAJOR,
    MINOR,
    PY,
    Analyzer,
    Finding,
    Result,
    by_prefix,
    is_test_file,
)

# Rule families enabled on top of a project's own ruff config; S (bandit) is left to bandit itself.
RUFF_EXTEND_SELECT = [
    "B", "SIM", "C4", "PERF", "RET", "ARG", "ERA", "FIX", "PLE", "PLW", "PLR", "PIE", "RUF", "DTZ", "BLE",
    "TRY", "ASYNC", "DJ", "LOG", "G", "INT", "EXE", "T10",
]
# Codes that are noise for whole-repo quality tracking (style nits, or covered by radon/complexipy).
RUFF_EXTEND_IGNORE = ["PLR2004", "PLR0911", "PLR0912", "PLR0915", "PLR0914", "PLR0917", "TRY003", "RUF012"]

RUFF_RULES = [
    ("E9", BLOCKER, BUG),
    ("F82", CRITICAL, BUG),
    ("F63", MAJOR, BUG),
    ("F7", MAJOR, BUG),
    ("PLE", MAJOR, BUG),
    ("ASYNC", MAJOR, BUG),
    ("T10", MAJOR, BUG),
    ("B", MAJOR, BUG),
    ("PLW", MINOR, BUG),
    ("DTZ", MINOR, BUG),
    ("BLE", MINOR, BUG),
    ("S", MAJOR, HOTSPOT),
    ("FIX", INFO, CODE_SMELL),
]

# Parameters whose names are dictated by a framework (Django views/migrations/signals, pytest fixtures).
FRAMEWORK_ARGS = {"request", "schema_editor", "apps", "sender", "args", "kwargs", "context", INFO}
UNUSED_ARG_RE = re.compile(r"`(\w{1,100})`")


def framework_required(code, message, path):
    if not code or not code.startswith("ARG"):
        return False
    if is_test_file(path):
        return True
    match = UNUSED_ARG_RE.search(message)
    return bool(match) and match[1] in FRAMEWORK_ARGS


BANDIT_SEVERITY = {"HIGH": CRITICAL, "MEDIUM": MAJOR, "LOW": MINOR}
DOWNGRADE = {CRITICAL: MAJOR, MAJOR: MINOR, MINOR: INFO}


def complexity_severity(value, threshold):
    return CRITICAL if value > 2 * threshold else MAJOR


class Ruff(Analyzer):
    name = executable = "ruff"
    extensions = PY

    def run(self, ctx):
        files = ctx.files_with(PY)
        out = self.exec(
            ["check", "--output-format", "json", "--exit-zero", "--no-cache",
             "--extend-select", ",".join(RUFF_EXTEND_SELECT), "--extend-ignore", ",".join(RUFF_EXTEND_IGNORE),
             *files], ctx
        )
        result = Result()
        for item in json.loads(out or "[]"):
            code = item.get("code")
            if framework_required(code, item["message"], ctx.rel(item["filename"])):
                continue
            if code is None:
                severity, type_ = BLOCKER, BUG
                rule = "syntax-error"
            else:
                severity, type_ = by_prefix(code, RUFF_RULES, (MINOR, CODE_SMELL))
                rule = code
            result.findings.append(
                Finding(
                    "ruff",
                    rule,
                    severity,
                    type_,
                    item["message"],
                    ctx.rel(item["filename"]),
                    item["location"]["row"],
                    item.get("end_location", {}).get("row"),
                )
            )
        return result


class Bandit(Analyzer):
    name = executable = "bandit"
    extensions = PY

    def run(self, ctx):
        # B101 (assert) fires on every pytest assertion.
        out = self.exec(["-f", "json", "-q", "--exit-zero", "-s", "B101", *ctx.files_with(PY)], ctx)
        result = Result()
        for item in json.loads(out)["results"]:
            severity = BANDIT_SEVERITY.get(item["issue_severity"], MINOR)
            if item["issue_confidence"] == "LOW":
                severity = DOWNGRADE[severity]
            # bandit matches API use without following data, so its findings are things to review, not verdicts.
            lines = item.get("line_range") or [item["line_number"]]
            result.findings.append(
                Finding(
                    "bandit",
                    f"{item['test_id']}:{item['test_name']}",
                    severity,
                    HOTSPOT,
                    item["issue_text"],
                    ctx.rel(item["filename"]),
                    item["line_number"],
                    max(lines),
                )
            )
        return result


class Radon(Analyzer):
    name = executable = "radon"
    extensions = PY

    def run(self, ctx):
        files = ctx.files_with(PY)
        threshold = ctx.complexity_threshold
        result = Result()
        functions = radon_functions(json.loads(self.exec(["cc", "-j", *files], ctx)))
        result.findings = [radon_finding(ctx, path, b, threshold) for path, b in functions
                           if b["complexity"] > threshold]
        result.metrics["complexity_python"] = sum(b["complexity"] for _, b in functions)
        mi = [v["mi"] for v in json.loads(self.exec(["mi", "-j", *files], ctx)).values() if "mi" in v]
        if mi:
            result.metrics["maintainability_index"] = round(sum(mi) / len(mi), 1)
        return result


def radon_functions(report):
    """(path, block) for every function and method; files radon couldn't parse map to an error dict."""
    out = []
    for path, blocks in report.items():
        if isinstance(blocks, list):
            out += [(path, b) for b in blocks if b["type"] in ("function", "method")]
    return out


def radon_finding(ctx, path, block, threshold):
    name = f"{block['classname']}.{block['name']}" if block.get("classname") else block["name"]
    return Finding("radon", "cyclomatic-complexity", complexity_severity(block["complexity"], threshold),
                   CODE_SMELL, f"{name} has cyclomatic complexity {block['complexity']} (threshold {threshold})",
                   ctx.rel(path), block["lineno"], block["endline"])
