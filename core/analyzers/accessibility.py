import json
import re
import shutil
import tempfile
from pathlib import Path

from .base import TOOLS_DIR, Analyzer, Finding, Result, node_tool

TEMPLATES = {".html", ".htm", ".djhtml", ".jinja", ".jinja2", ".j2"}
JSX = {".jsx", ".tsx"}
TAG_DELIMITERS = (("{%", "%}"), ("{#", "#}"), ("{{", "}}"))
# Alpine/Vue fill these at runtime, so an empty element in the template isn't empty on the page.
# Bounded quantifiers keep this linear on hostile input (an unclosed "<" repeated many times).
BOUND_EMPTY = re.compile(
    r"(<(\w{1,40})\b[^<>]{0,2000}\s(?:x-text|x-html|v-text|v-html)\s{0,20}=[^<>]{0,2000}>)(\s{0,200})(</\2>)"
)
AXE_SEVERITY = {"critical": "critical", "serious": "major", "moderate": "minor", "minor": "info"}
HTML_VALIDATE_CONFIG = {
    "extends": ["html-validate:a11y"],
    # The preset alone misses unlabelled inputs, empty headings, duplicate landmarks and focusable hidden content.
    "rules": {
        "input-missing-label": "error",
        "aria-label-misuse": "error",
        "unique-landmark": "error",
        "empty-heading": "error",
        "hidden-focusable": "error",
        "area-alt": "error",
        "no-abstract-role": "error",
        "aria-hidden-body": "error",
        "text-content": "error",
        "valid-autocomplete": "error",
        "no-redundant-role": "warn",
        "prefer-native-element": "warn",
        "no-implicit-button-type": "off",
    },
}


def blank_tag(tag, is_output):
    """Spaces for {% %}/{# #}; for {{ }} keep the variable's letters so different values stay distinct
    (e.g. two headings filled from different variables don't look like duplicates)."""
    if not is_output:
        return "".join(c if c == "\n" else " " for c in tag)
    return "".join(c if c.isalnum() or c == "\n" else "x" for c in tag)


def next_tag(text, start):
    found = [(pos, opener, closer) for opener, closer in TAG_DELIMITERS if (pos := text.find(opener, start)) != -1]
    return min(found) if found else None


def blank_template_syntax(text):
    """Strip Django/Jinja tags so the HTML parses, keeping every line and column where it was.

    Output expressions keep their letters so attributes like alt="{{ caption }}" still count as non-empty.
    A plain scan rather than a regex, so hostile templates can't trigger backtracking.
    """
    out, i = [], 0
    while (tag := next_tag(text, i)) is not None:
        pos, opener, closer = tag
        end = text.find(closer, pos + 2)
        if end == -1:
            break
        end += 2
        out += [text[i:pos], blank_tag(text[pos:end], opener == "{{")]
        i = end
    out.append(text[i:])
    return BOUND_EMPTY.sub(r"\1x\3\4", "".join(out))


class HtmlA11y(Analyzer):
    """Static WCAG checks on HTML and server-side templates (alt text, labels, ARIA, table headers...)."""

    name = "html-a11y"
    executable = "html-validate"
    extensions = TEMPLATES

    def binary(self):
        return node_tool("html-validate")

    def run(self, ctx):
        files = ctx.files_with(TEMPLATES)
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            for f in files:
                target = tmp / f
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(blank_template_syntax((ctx.root / f).read_text(errors="replace")))
            config = tmp / ".codewatch-htmlvalidate.json"
            config.write_text(json.dumps(HTML_VALIDATE_CONFIG))
            # Report to a file: Node truncates large piped stdout when the process exits.
            report_file = tmp / ".codewatch-report.json"
            self.exec(["--config", str(config), "--formatter", f"json={report_file}", *files], ctx,
                      ok_codes=(0, 1), cwd=tmp)
            out = report_file.read_text() if report_file.exists() else "[]"
        result = Result()
        for report in json.loads(out or "[]"):
            path = ctx.rel(Path(report["filePath"]).relative_to(tmp) if Path(report["filePath"]).is_absolute()
                           else report["filePath"])
            for m in report["messages"]:
                rule = m.get("ruleId") or "parser-error"
                severity = "major" if m.get("severity") == 2 else "minor"
                result.findings.append(
                    Finding("html-a11y", rule, severity, "accessibility", m["message"], path, m.get("line"))
                )
        return result


class JsxA11y(Analyzer):
    name = "jsx-a11y"
    executable = "eslint"
    extensions = JSX

    def binary(self):
        return node_tool("eslint")

    def run(self, ctx):
        config = TOOLS_DIR / "eslint-a11y.config.js"
        with tempfile.TemporaryDirectory() as tmp:
            report_file = Path(tmp) / "report.json"
            self.exec(["--config", str(config), "--format", "json", "--output-file", str(report_file),
                       "--no-warn-ignored", *ctx.files_with(JSX)], ctx, ok_codes=(0, 1))
            out = report_file.read_text() if report_file.exists() else "[]"
        result = Result()
        for report in json.loads(out or "[]"):
            for m in report["messages"]:
                rule = m.get("ruleId") or "parser-error"
                result.findings.append(
                    Finding("jsx-a11y", rule, "major" if m.get("severity") == 2 else "minor", "accessibility",
                            m["message"], ctx.rel(report["filePath"]), m.get("line"), m.get("endLine"))
                )
        return result


class Axe(Analyzer):
    """Runtime WCAG 2.2 AA checks (contrast, ARIA, focus, landmarks) with axe-core on live pages."""

    name = "axe"
    executable = "node"

    def applies(self, ctx):
        return bool(ctx.a11y_urls)

    def available(self):
        script = TOOLS_DIR / "axe-scan.mjs"
        return shutil.which("node") is not None and node_tool("playwright") is not None and script.exists()

    def __init__(self, color_scheme="light"):
        self.color_scheme = color_scheme

    def run(self, ctx):
        script = TOOLS_DIR / "axe-scan.mjs"
        with tempfile.NamedTemporaryFile("w", suffix=".json") as spec:
            json.dump({"urls": ctx.a11y_urls, "colorScheme": self.color_scheme}, spec)
            spec.flush()
            out = self.exec([str(script), spec.name], ctx, cwd=TOOLS_DIR)
        result = Result()
        failed = 0
        for page in json.loads(out):
            if page.get("error"):
                failed += 1
                result.findings.append(
                    Finding("axe", "page-load-failed", "major", "accessibility",
                            f"Could not load page: {page['error']}", page["url"])
                )
            for v in page["violations"]:
                for node in v["nodes"]:
                    result.findings.append(
                        Finding("axe", v["id"], AXE_SEVERITY.get(v["impact"], "minor"), "accessibility",
                                f"{v['help']} — {node['target']}. {first_line(node['summary'])} ({v['helpUrl']})",
                                page["url"])
                    )
        result.metrics["a11y_pages_scanned"] = len(ctx.a11y_urls) - failed
        return result


def first_line(text):
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    # failureSummary starts with "Fix any/all of the following:"; the useful part is the next line.
    return lines[1] if len(lines) > 1 else (lines[0] if lines else "")
