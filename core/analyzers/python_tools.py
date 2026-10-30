import ast
import json
import re
from pathlib import Path

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
    VULNERABILITY,
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


# B101 (assert) fires on every pytest assertion. B404/B603/B607 flag importing subprocess and calling it with an
# argument list, which is the safe way to call it; B602/B605 still catch shell=True and os.system.
BANDIT_SKIPPED = ("B101", "B404", "B603", "B607")
# random is only a weakness when it makes something an attacker must not guess. The function around the call
# (its name, docstring and what it stores the value in) says what the number is for.
SECRET_USE_RE = re.compile(
    r"(?i)\b(?:\w*session[ _]?id\w*|\w*token|token_\w+|\w*secret\w*|\w*passw\w*|pwd|\w*nonce|\w*salt|otp|\w*csrf\w*"
    r"|\w*api_?key\w*|auth|auth_\w+|authenticat\w*|authoriz\w*|cred|credentials?|cipher\w*|\w*crypt\w*"
    r"|unpredictable|\w*cookie\w*|\w*remember\w*|\w+_key|iv)\b"
    r"|session\s{0,5}\[|\bkey\s{0,5}=[^=\n]{0,80}rand",
)
CONTEXT_LINES = 5
# A digest protects something when it stands for a secret or vouches for data (signatures, certificates).
SECURITY_PURPOSE_RE = re.compile(
    rf"{SECRET_USE_RE.pattern}|\b(\w+_)?(cert\w*|sign(ed|er|ing|atures?)?|hmac\w*|integrity|verif\w*)\b", re.IGNORECASE)


def security_purpose(cache, path, line):
    """The code around a finding is about secrets or verification: the innermost Python function, else a window."""
    if path.endswith(".py"):
        text = cache.function_text(path, line)
    else:
        text = "\n".join(cache.lines(path)[max(0, line - 1 - 2 * CONTEXT_LINES):line + 2 * CONTEXT_LINES])
    return bool(SECURITY_PURPOSE_RE.search(text))


def is_random_call(call):
    func = call.func
    return (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == "random") or (
        isinstance(func, ast.Name) and func.id in RANDOM_FUNCTIONS)


def random_function_name(call):
    return call.func.attr if isinstance(call.func, ast.Attribute) else call.func.id


RANDOM_FUNCTIONS = {"random", "randint", "randrange", "choice", "choices", "sample", "shuffle", "uniform",
                    "getrandbits", "randbytes", "normalvariate", "gauss", "triangular"}


class LineCache:
    def __init__(self, root):
        self.root, self.files, self.trees = Path(root), {}, {}

    def lines(self, path):
        if path not in self.files:
            try:
                self.files[path] = (self.root / path).read_text(errors="replace").splitlines()
            except OSError:
                self.files[path] = []
        return self.files[path]

    def get(self, path, line):
        rows = self.lines(path)
        return rows[line - 1] if 0 < line <= len(rows) else ""

    def purpose_text(self, path, line):
        """What a random value on this line is for: the keyword it is passed as (rtt_ms=random.uniform(...) is about
        rtt_ms, whatever else the function does), else the surrounding function."""
        tree = self.tree(path)
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)} if tree else {}
        for call in parents:
            if not (isinstance(call, ast.Call) and call.lineno == line and is_random_call(call)):
                continue
            node = call
            while node in parents and not isinstance(node, ast.stmt):
                if isinstance(parents[node], ast.keyword) and parents[node].arg:
                    return parents[node].arg
                node = parents[node]
        return self.function_text(path, line)

    def only_shuffles(self, path, line):
        """random.shuffle() reorders data and makes no value an attacker could guess."""
        calls = [n for n in ast.walk(self.tree(path) or ast.Module(body=[], type_ignores=[]))
                 if isinstance(n, ast.Call) and n.lineno == line and is_random_call(n)]
        return bool(calls) and all(random_function_name(c) == "shuffle" for c in calls)

    def tree(self, path):
        if path not in self.trees:
            try:
                self.trees[path] = ast.parse("\n".join(self.lines(path)))
            except (SyntaxError, ValueError):
                self.trees[path] = None
        return self.trees[path]

    def function_text(self, path, line):
        """Source of the innermost function around a line, or a few lines either side at module level."""
        around = [n for n in ast.walk(self.tree(path) or ast.Module(body=[], type_ignores=[]))
                  if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                  and n.lineno <= line <= (n.end_lineno or n.lineno)]
        if around:
            inner = max(around, key=lambda n: n.lineno)
            start, end = inner.lineno, inner.end_lineno or line
        else:
            start, end = max(1, line - CONTEXT_LINES), line + CONTEXT_LINES
        return "\n".join(self.lines(path)[start - 1:end])


class Bandit(Analyzer):
    name = executable = "bandit"
    extensions = PY

    def run(self, ctx):
        out = self.exec(["-f", "json", "-q", "--exit-zero", "-s", ",".join(BANDIT_SKIPPED), *ctx.files_with(PY)], ctx)
        result = Result()
        source = LineCache(ctx.root)
        for item in json.loads(out)["results"]:
            # random() making a token, key or session id is a definite weakness; elsewhere it's not one at all.
            if item["test_id"] == "B311" and (
                    source.only_shuffles(item["filename"], item["line_number"])
                    or not SECRET_USE_RE.search(source.purpose_text(item["filename"], item["line_number"]))):
                continue
            type_ = VULNERABILITY if item["test_id"] == "B311" else HOTSPOT
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
                    type_,
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
