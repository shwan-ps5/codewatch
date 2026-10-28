import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

PY = {".py"}
JS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
C = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
CODE = PY | JS | C | {".java", ".go", ".rs", ".cs", ".rb", ".php", ".kt", ".swift"}

TOOL_TIMEOUT = 1800


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


class Analyzer:
    name = ""
    executable = ""
    extensions: set[str] | None = None

    def applies(self, ctx: Context) -> bool:
        return self.extensions is None or bool(ctx.files_with(self.extensions))

    def available(self) -> bool:
        return tool_path(self.executable) is not None

    def run(self, ctx: Context) -> Result:
        raise NotImplementedError

    def exec(self, args, ctx, ok_codes=(0,), stream="stdout"):
        proc = subprocess.run(
            [tool_path(self.executable), *args],
            cwd=ctx.root,
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT,
            check=False,
        )
        if proc.returncode not in ok_codes:
            raise ToolError(f"{self.name} exited {proc.returncode}: {proc.stderr.strip()[-2000:]}")
        return proc.stdout if stream == "stdout" else proc.stderr


def by_prefix(code, table, default):
    for prefix, *mapping in table:
        if code.startswith(prefix):
            return tuple(mapping)
    return default
