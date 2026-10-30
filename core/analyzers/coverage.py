import ast
from pathlib import Path

import defusedxml.ElementTree as ET

from .base import Analyzer, Result, is_test_file
from .codewatch_checks import docstring_nodes


class Coverage(Analyzer):
    """Imports a Cobertura XML (coverage.py, istanbul) or LCOV report produced by the project's own test run."""

    name = "coverage"

    def available(self):
        return True

    def applies(self, ctx):
        return ctx.coverage_report is not None

    def run(self, ctx):
        if ctx.coverage_report is None:
            return Result()
        report = Path(ctx.coverage_report)
        lines = parse_lcov(report) if report.suffix in (".info", ".lcov") else parse_cobertura(report)
        result = Result()
        # Tests run in full by definition; counting them would inflate coverage of the code under test.
        sources = [f for f in ctx.files if not is_test_file(f)]
        collect(result, lines, set(sources), Path(ctx.coverage_base or report.parent))
        if any(p.endswith(".py") for p in result.coverable_lines):
            add_unreported(result, Path(ctx.root), sources)
        result.metrics.update(summary(result))
        return result


def summary(result):
    coverable = sum(len(v) for v in result.coverable_lines.values())
    covered = sum(len(v) for v in result.covered_lines.values())
    metrics: dict[str, float] = {"lines_to_cover": coverable, "uncovered_lines": coverable - covered}
    if coverable:
        metrics["coverage"] = round(100 * covered / coverable, 1)
    return metrics


def collect(result, lines, tracked, base):
    by_name = {}
    for f in tracked:
        by_name.setdefault(Path(f).name, []).append(f)
    for candidates, hits in lines:
        path = next((p for p in (resolve(c, base) for c in candidates) if p in tracked), None)
        path = path or match_suffix(candidates, by_name)
        if path is None:
            continue
        result.coverable_lines.setdefault(path, set()).update(hits)
        result.covered_lines.setdefault(path, set()).update(n for n, count in hits.items() if count > 0)


def add_unreported(result, root, files):
    """Python files the test run never imported are untested, not unmeasured: count all their statements."""
    for path in files:
        if not path.endswith(".py") or path in result.coverable_lines:
            continue
        try:
            lines = statement_lines((root / path).read_text(errors="replace"))
        except (OSError, SyntaxError, ValueError):
            continue
        if lines:
            result.coverable_lines[path] = lines
            result.covered_lines[path] = set()


def statement_lines(source):
    """Executable lines as coverage.py reports them: statements, decorators and except clauses, not docstrings."""
    tree = ast.parse(source)
    docstrings = docstring_nodes(tree)
    lines = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            lines.add(node.lineno)
        elif isinstance(node, ast.stmt) and not (isinstance(node, ast.Expr) and id(node.value) in docstrings):
            lines.add(node.lineno)
            lines.update(d.lineno for d in getattr(node, "decorator_list", []))
    return lines


def match_suffix(candidates, by_name):
    """Reports from CI or another checkout carry absolute paths from that machine; match on the path tail."""
    for c in candidates:
        options = [f for f in by_name.get(Path(c).name, []) if c.replace("\\", "/").endswith("/" + f) or c == f]
        if options:
            return max(options, key=len)
    return None


def resolve(candidate, base):
    p = Path(candidate)
    if p.is_absolute():
        try:
            return str(p.resolve().relative_to(base.resolve()))
        except ValueError:
            return str(p)
    return str(p).removeprefix("./")


def parse_cobertura(report):
    root = ET.parse(report).getroot()
    if root is None:
        return
    sources = [s.text.strip() for s in root.iter("source") if s.text and s.text.strip()]
    for cls in root.iter("class"):
        filename = cls.get("filename")
        if not filename:
            continue
        hits = {}
        for line in cls.iter("line"):
            n = int(line.get("number", "0"))
            hits[n] = max(hits.get(n, 0), int(line.get("hits", "0")))
        yield [str(Path(s) / filename) for s in sources] + [filename], hits


def parse_lcov(report):
    path, hits = None, {}
    for raw in report.read_text().splitlines():
        if raw.startswith("SF:"):
            path, hits = raw[3:], {}
        elif raw.startswith("DA:") and path:
            line, count = raw[3:].split(",")[:2]
            hits[int(line)] = int(count)
        elif raw == "end_of_record" and path:
            yield [path], hits
            path = None
