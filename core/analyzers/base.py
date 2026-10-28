import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

PY = {".py"}
JS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
C = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
CODE = PY | JS | C | {".java", ".go", ".rs", ".cs", ".rb", ".php", ".kt", ".swift"}

BLOCKER, CRITICAL, MAJOR, MINOR, INFO = "blocker", "critical", "major", "minor", "info"
BUG, VULNERABILITY, HOTSPOT, CODE_SMELL, ACCESSIBILITY = (
    "bug", "vulnerability", "security_hotspot", "code_smell", "accessibility"
)

TOOL_TIMEOUT = 1800
TOOLS_DIR = Path(os.environ.get("CODEWATCH_TOOLS", Path(__file__).resolve().parents[2] / "tools"))


@dataclass
class Finding:
    tool: str
    rule: str
    severity: str
    type: str
    message: str
    path: str
    line: int | None = None
    end_line: int | None = None


@dataclass
class Result:
    findings: list[Finding] = field(default_factory=list)
    metrics: dict[str, float] = field(default_factory=dict)
    covered_lines: dict[str, set[int]] = field(default_factory=dict)
    coverable_lines: dict[str, set[int]] = field(default_factory=dict)
    duplicated_lines: dict[str, set[int]] = field(default_factory=dict)


@dataclass
class Context:
    root: Path
    files: list[str]
    complexity_threshold: int = 10
    semgrep_config: str = "p/default"
    exclusions: list[str] = field(default_factory=list)
    a11y_urls: list[str] = field(default_factory=list)
    cognitive_threshold: int = 15
    max_literal_repeats: int = 3
    custom_rules: str = ""
    coverage_report: Path | None = None
    coverage_base: Path | None = None

    def files_with(self, extensions):
        return [f for f in self.files if Path(f).suffix.lower() in extensions]

    def rel(self, path):
        p = Path(path)
        if p.is_absolute():
            try:
                p = p.relative_to(self.root)
            except ValueError:
                return str(p)
        return os.path.normpath(str(p)).removeprefix("./")


class ToolError(RuntimeError):
    pass


def tool_path(name):
    local = Path(sys.executable).parent / name
    return str(local) if local.exists() else shutil.which(name)


def isolated_tool(name):
    """Python analyzers kept in their own venv under tools/ because their pins clash with codewatch's."""
    path = TOOLS_DIR / f"{name}-venv" / "bin" / name
    return str(path) if path.exists() else None


def node_tool(name):
    """Pinned Node analyzers from tools/ (npm ci --prefix tools); never npx, which would honour a scanned repo's .npmrc."""
    path = TOOLS_DIR / "node_modules" / ".bin" / name
    return str(path) if path.exists() else None


class Analyzer:
    name = ""
    executable = ""
    extensions: set[str] | None = None

    def applies(self, ctx: Context) -> bool:
        return self.extensions is None or bool(ctx.files_with(self.extensions))

    def binary(self):
        return tool_path(self.executable)

    def available(self) -> bool:
        return self.binary() is not None

    def run(self, ctx: Context) -> Result:
        raise NotImplementedError

    def exec(self, args, ctx, ok_codes=(0,), stream="stdout", cwd=None):
        proc = subprocess.run(
            [self.binary(), *args],
            cwd=cwd or ctx.root,
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT,
            check=False,
        )
        if proc.returncode not in ok_codes:
            raise ToolError(f"{self.name} exited {proc.returncode}: {proc.stderr.strip()[-2000:]}")
        return proc.stdout if stream == "stdout" else proc.stderr


TEST_PATH_RE = re.compile(r"(^|/)(tests?|__tests__|spec)/|(^|/)test_[^/]{0,200}\.py$|_test\.py$|\.(test|spec)\.[jt]sx?$")


def is_test_file(path):
    return bool(TEST_PATH_RE.search(path))


def by_prefix(code, table, default):
    """First table row whose prefix is the code's whole rule family: "S" matches S602 but not SIM108."""
    for prefix, *mapping in table:
        rest = code[len(prefix):]
        if code.startswith(prefix) and (not rest or rest[0].isdigit() or prefix[-1].isdigit()):
            return tuple(mapping)
    return default
