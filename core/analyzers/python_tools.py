import json

from .base import PY, Analyzer, Finding, Result, by_prefix

RUFF_RULES = [
    ("E9", "blocker", "bug"),
    ("F82", "critical", "bug"),
    ("F63", "major", "bug"),
    ("F7", "major", "bug"),
    ("PLE", "major", "bug"),
    ("B", "major", "bug"),
    ("S", "major", "vulnerability"),
]

BANDIT_SEVERITY = {"HIGH": "critical", "MEDIUM": "major", "LOW": "minor"}
DOWNGRADE = {"critical": "major", "major": "minor", "minor": "info"}


def complexity_severity(value, threshold):
    return "critical" if value > 2 * threshold else "major"


class Ruff(Analyzer):
    name = executable = "ruff"
    extensions = PY

    def run(self, ctx):
        files = ctx.files_with(PY)
        out = self.exec(
            ["check", "--output-format", "json", "--exit-zero", "--no-cache", "--extend-select", "B", *files], ctx
        )
        result = Result()
        for item in json.loads(out or "[]"):
            code = item.get("code")
            if code is None:
                severity, type_ = "blocker", "bug"
                rule = "syntax-error"
            else:
                severity, type_ = by_prefix(code, RUFF_RULES, ("minor", "code_smell"))
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
            severity = BANDIT_SEVERITY.get(item["issue_severity"], "minor")
            if item["issue_confidence"] == "LOW":
                severity = DOWNGRADE[severity]
            lines = item.get("line_range") or [item["line_number"]]
            result.findings.append(
                Finding(
                    "bandit",
                    f"{item['test_id']}:{item['test_name']}",
                    severity,
                    "vulnerability",
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
        total = 0
        for path, blocks in json.loads(self.exec(["cc", "-j", *files], ctx)).items():
            if not isinstance(blocks, list):
                continue
            for b in blocks:
                if b["type"] not in ("function", "method"):
                    continue
                total += b["complexity"]
                if b["complexity"] > threshold:
                    name = f"{b['classname']}.{b['name']}" if b.get("classname") else b["name"]
                    result.findings.append(
                        Finding(
                            "radon",
                            "cyclomatic-complexity",
                            complexity_severity(b["complexity"], threshold),
                            "code_smell",
                            f"{name} has cyclomatic complexity {b['complexity']} (threshold {threshold})",
                            ctx.rel(path),
                            b["lineno"],
                            b["endline"],
                        )
                    )
        result.metrics["complexity_python"] = total
        mi = [v["mi"] for v in json.loads(self.exec(["mi", "-j", *files], ctx)).values() if "mi" in v]
        if mi:
            result.metrics["maintainability_index"] = round(sum(mi) / len(mi), 1)
        return result
