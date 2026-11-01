import csv
import io
import json
import os
import re
import tempfile
from pathlib import Path

import yaml

from . import summaries as summaries_module
from .base import (
    BUG,
    CODE,
    CODE_SMELL,
    CRITICAL,
    HOTSPOT,
    JS,
    MAJOR,
    MINOR,
    PY,
    VULNERABILITY,
    Analyzer,
    C,
    Finding,
    Result,
    is_test_file,
    isolated_tool,
    node_tool,
)
from .body_models import with_model_sources
from .constant_branches import blank_dead_branches
from .containers import track_slots
from .match_statements import match_as_if
from .python_tools import LineCache, complexity_severity, security_purpose
from .route_converters import scalar_parameters, type_route_converters
from .slices import index_slices

SEMGREP_SEVERITY = {"ERROR": CRITICAL, "WARNING": MAJOR, "INFO": MINOR}
JS_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
RETURNER_MAX_JS_BYTES = 200_000
SEMGREP_TYPE = {"security": VULNERABILITY, "correctness": BUG}

CPPCHECK_SEVERITY = {
    "error": (CRITICAL, BUG),
    "warning": (MAJOR, BUG),
    "portability": (MINOR, BUG),
    "performance": (MINOR, CODE_SMELL),
    "style": (MINOR, CODE_SMELL),
}
CPPCHECK_NOISE = {"missingInclude", "missingIncludeSystem", "checkersReport", "unmatchedSuppression",
                  "toomanyconfigs", "normalCheckLevelMaxBranches", "unknownMacro", "syntaxError"}
# Structs declared in headers often mirror an external layout (SDK, hardware, file format): every field exists
# to match it, so cppcheck's "never read" is expected there. Structs local to a .c/.cpp file are still checked.
HEADER_ONLY_NOISE = {"unusedStructMember"}
HEADERS = {".h", ".hh", ".hpp", ".hxx", ".inl"}

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
                    Finding("lizard", "cyclomatic-complexity", complexity_severity(ccn, threshold), CODE_SMELL,
                            f"{func} has cyclomatic complexity {ccn} (threshold {threshold})",
                            ctx.rel(path), start, end)
                )
        result.metrics["complexity_other"] = total
        return result


class Semgrep(Analyzer):
    name = executable = "semgrep"
    extensions = CODE | {".yml", ".yaml", ".html"}

    def __init__(self):
        self.timeouts = set()

    def binary(self):
        # Own venv: semgrep pins dependencies (e.g. an old mcp) that conflict with codewatch's.
        return isolated_tool("semgrep") or super().binary()

    def run(self, ctx):
        custom_rules = yaml.safe_load(ctx.custom_rules).get("rules", []) if ctx.custom_rules else []
        if not ctx.semgrep_config and not custom_rules:
            return Result()
        custom_rules = with_model_sources(custom_rules, (read_source(ctx.root / f) or "" for f in ctx.files_with({".py"})))
        self.timeouts = set()
        with tempfile.TemporaryDirectory() as work:
            targets, originals = analysis_copies(ctx, ctx.files_with(self.extensions), Path(work) / "copies")
            summaries, hits = self.summarise(ctx, custom_rules, targets, originals, Path(work))
            returners, fields, passes, functions = self.find_returners(ctx, custom_rules, targets, originals,
                                                                       Path(work))
            final = summaries_module.with_pass_through(custom_rules, functions, passes, summaries, returners)
            rules = (final + summaries_module.via_rules(final, summaries)
                     + summaries_module.from_rules(final, returners, summaries)
                     + summaries_module.field_variants(final, fields, summaries))
            configs = ["--config", ctx.semgrep_config] if ctx.semgrep_config else []
            if rules:
                (Path(work) / "custom.yml").write_text(yaml.safe_dump({"rules": rules}, sort_keys=False))
                configs += ["--config", str(Path(work) / "custom.yml")]
            # Every rule in this pass reads one file at a time, so narrowing it to the focus changes nothing
            # in those files; the summaries above still saw every file.
            focus = None if ctx.focus is None else set(ctx.focus)
            main_targets = targets if focus is None else [t for t in targets if ctx.rel(originals.get(t, t)) in focus]
            # Semgrep given no targets scans the working directory.
            data = self.scan(ctx, configs, main_targets) if main_targets else {"results": []}
        result = Result()
        if self.timeouts:
            paths = sorted({ctx.rel(originals.get(p, p)) for p in self.timeouts})
            result.notes.append(f"Semgrep gave up on some rules in {len(paths)} file(s), so they may hide findings: "
                                f"{', '.join(paths[:5])}{' and more' if len(paths) > 5 else ''}.")
        traced = taint_checked(custom_rules)
        source = LineCache(ctx.root)
        custom_ids = [r["id"] for r in custom_rules]
        for item in data["results"]:
            path = ctx.rel(originals.get(item["path"], item["path"]))
            extra = item["extra"]
            metadata = extra.get("metadata", {})
            check_id = item["check_id"].removesuffix(summaries_module.VIA_SUFFIX)
            via = check_id != item["check_id"]
            field = check_id.endswith(summaries_module.FIELD_SUFFIX)
            check_id = check_id.removesuffix(summaries_module.FIELD_SUFFIX).removesuffix(summaries_module.FROM_SUFFIX)
            # Semgrep prefixes rules from a local file with path segments; map them back to codewatch's IDs.
            custom_id = next((cid for cid in custom_ids if check_id.endswith(cid)), None)
            message, callee, keyword = summaries_module.split_keyword(extra["message"].strip())
            if not summaries_module.keyword_summarised(callee, keyword, summaries.get(custom_id, ())):
                continue
            if via and not self.via_visible(ctx, path, message, summaries.get(custom_id, ())):
                continue
            if field:
                if not self.field_stored(path, message, fields.get(custom_id, ())):
                    continue
            elif (check_id != item["check_id"] and not via
                    and not self.from_visible(ctx, path, message, returners.get(custom_id, ()))):
                continue
            kind = semgrep_type(check_id, metadata)
            # codewatch's own taint rule for this weakness already followed the data here; a registry rule that
            # matches the same weakness without seeing guards or sanitizers is left for review, not a verdict.
            if (not custom_id and kind == VULNERABILITY
                    and cwe_numbers(metadata.get("cwe")) & traced.get(Path(path).suffix, set())):
                kind = HOTSPOT
            # Rules for primitives that are only weak when they protect something (MD5 for a Gravatar URL is
            # fine): a vulnerability where the code is about secrets or verification, otherwise for review.
            if (kind == VULNERABILITY and metadata.get("security-purpose") == "required"
                    and not security_purpose(source, path, item["start"]["line"])):
                kind = HOTSPOT
            # Test code isn't served to anyone, so what flows through it is for review, not a verdict.
            if kind == VULNERABILITY and is_test_file(path):
                kind = HOTSPOT
            result.findings.append(
                Finding("codewatch" if custom_id else "semgrep", custom_id or check_id,
                        SEMGREP_SEVERITY.get(extra.get("severity"), MINOR), kind, message,
                        path, item["start"]["line"], item["end"]["line"])
            )
        def derived(f):
            return any(r.search(f.message) for r in (summaries_module.VIA_RE, summaries_module.FROM_RE,
                                                     summaries_module.FIELD_RE))

        direct = {(f.rule, f.path, f.line) for f in result.findings if not derived(f)}
        result.findings = [f for f in result.findings if not (derived(f) and (f.rule, f.path, f.line) in direct)]
        result.findings += self.uncalled_entry_points(ctx, custom_rules, hits, result.findings)
        return result

    def uncalled_entry_points(self, ctx, custom_rules, hits, findings):
        """A parameter that reaches a sink in a function nothing in the project calls: the data comes from
        whoever does (a library user, a framework, a handler registered by name elsewhere), so it is left for
        review rather than claimed as a vulnerability."""
        if not hits:
            return []
        files = [(f, read_source(ctx.root / f) or "") for f in ctx.files_with(self.extensions & CODE)]
        used = summaries_module.referenced_names(files)
        rules = {r["id"]: r for r in custom_rules}
        scalars = {f: scalar_parameters(text) for f, text in files if f.endswith(".py")}
        seen = {(f.rule, f.path, f.line) for f in findings}
        out = []
        for rule_id, path, line, func, param in sorted(hits):
            if func in used or func.startswith("_") or is_test_file(path) or (rule_id, path, line) in seen:
                continue
            if (func, param) in scalars.get(path, ()):
                continue
            if ctx.focus is not None and path not in ctx.focus:
                continue
            seen.add((rule_id, path, line))
            rule = rules[rule_id]
            message = (f"{rule['message'].strip()} [parameter {param} of {func}(), which nothing in the project "
                       f"calls: check what its callers pass]")
            out.append(Finding("codewatch", rule_id, SEMGREP_SEVERITY.get(rule.get("severity"), MINOR), HOTSPOT,
                               message, path, line, line))
        return out

    def scan(self, ctx, configs, targets):
        args = ["scan", *configs, "--json", "--metrics=off", "--quiet", "--disable-version-check", *targets]
        data = json.loads(self.exec(args, ctx, ok_codes=(0, 1)))
        # A timeout skips that rule on that file, silently unless it's reported.
        self.timeouts.update(e["path"] for e in data.get("errors", []) if e.get("type") == "Timeout" and e.get("path"))
        return data

    def summarise(self, ctx, custom_rules, targets, originals, work):
        """Pass 1 of summaries.py: which function parameters reach each taint rule's sinks, directly or through
        functions already summarised."""
        summaries, known, new, hits = {}, None, None, []
        scanned = targets
        for _ in range(summaries_module.MAX_DEPTH):
            # Semi-naive: a deeper pass has only the summaries the last one added as sinks. Whatever reaches an
            # older one was found when it was added, in every file that names it.
            rules = summaries_module.summary_rules(custom_rules, new, base=new is None)
            if not rules or not scanned:
                break
            config = work / "summaries.yml"
            config.write_text(yaml.safe_dump({"rules": rules}, sort_keys=False))
            data = self.scan(ctx, ["--config", str(config)], scanned)
            ids = [r["id"] for r in rules]
            found = [(next((i for i in ids if item["check_id"].endswith(i)), item["check_id"]),
                      ctx.rel(originals.get(item["path"], item["path"])), item["start"]["line"],
                      item["extra"]["message"])
                     for item in data["results"]]
            more = summaries_module.parse_summaries(found, lambda rel: read_source(ctx.root / rel), known, hits)
            merged = summaries_module.merge(summaries, more)
            if merged is None:
                break
            new = summaries_module.added(summaries, merged)
            scanned = mentioning(ctx, targets, added_names(summaries, merged))
            summaries = known = merged
        return summaries, hits

    def find_returners(self, ctx, custom_rules, targets, originals, work):
        """Pass 3 of summaries.py: which functions return request data, directly or from returners found before,
        and (in the first scan) which fields of self/this request data is stored in and which Python functions
        can return a parameter (of those whose result is assigned, also returned)."""
        returners, fields, passes = {}, {}, {}
        # The functions with_pass_through may treat as clean: take a parameter, and their result is assigned.
        functions = summaries_module.python_functions_with_params(
            read_source(ctx.root / f) or "" for f in ctx.files_with({".py"})) & summaries_module.assigned_calls(
            read_source(ctx.root / t) or "" for t in targets if t.endswith(".py"))
        # An unminified library bundled with the app (materialize.js, 366 KB) multiplies this pass's time by ten,
        # and big single-file apps are Python's habit, not JavaScript's.
        targets = [t for t in targets
                   if Path(t).suffix not in JS_SUFFIXES or (ctx.root / t).stat().st_size <= RETURNER_MAX_JS_BYTES]
        scanned, new = targets, {}
        for depth in range(summaries_module.MAX_DEPTH):
            # Semi-naive, as in summarise: a deeper pass's sources are calls to the returners the last one added.
            rules = summaries_module.returner_rules(custom_rules, new, base=depth == 0)
            if depth == 0:
                rules += summaries_module.field_rules(custom_rules) + summaries_module.pass_rules(custom_rules, functions)
            if not rules or not scanned:
                break
            config = work / "returners.yml"
            config.write_text(yaml.safe_dump({"rules": rules}, sort_keys=False))
            data = self.scan(ctx, ["--config", str(config)], scanned)
            ids = [r["id"] for r in rules]
            found = [(next((i for i in ids if item["check_id"].endswith(i)), item["check_id"]),
                      ctx.rel(originals.get(item["path"], item["path"])), item["start"]["line"],
                      item["extra"]["message"].strip())
                     for item in data["results"]]
            stored = [f for f in found if f[0].endswith(summaries_module.FIELDS_SUFFIX)]
            fields = summaries_module.merge(fields, summaries_module.parse_fields(stored)) or fields
            passing = [f for f in found if f[0].endswith(summaries_module.PASSES_SUFFIX)]
            passes = summaries_module.merge(passes, summaries_module.parse_passes(passing)) or passes
            more = summaries_module.parse_returners([f for f in found if f not in stored and f not in passing],
                                                    lambda rel: read_source(ctx.root / rel))
            merged = summaries_module.merge(returners, more)
            if merged is None:
                break
            new = summaries_module.added(returners, merged)
            scanned = mentioning(ctx, targets, added_names(returners, merged))
            returners = merged
        return returners, fields, passes, functions

    @staticmethod
    def field_stored(path, message, fields):
        match = summaries_module.FIELD_RE.search(message.strip())
        return bool(match) and (match.group(1), path) in fields

    @staticmethod
    def from_visible(ctx, path, message, returners):
        match = summaries_module.FROM_RE.search(message.strip())
        if not match:
            return False
        defining = {p for func, p in returners if func == match.group(1)}
        return bool(defining) and summaries_module.visible(path, defining, lambda rel: read_source(ctx.root / rel))

    @staticmethod
    def via_visible(ctx, path, message, summaries):
        match = summaries_module.VIA_RE.search(message.strip())
        if not match:
            return False
        defining = {s[4] for s in summaries if s[0] == match.group(1)}
        return bool(defining) and summaries_module.visible(path, defining, lambda rel: read_source(ctx.root / rel))


LANGUAGE_SUFFIXES = {"python": [".py"], "javascript": [".js", ".jsx", ".mjs", ".cjs"], "typescript": [".ts", ".tsx"]}
CWE_RE = re.compile(r"CWE-(\d+)")


def cwe_numbers(cwes):
    if isinstance(cwes, str):
        cwes = [cwes]
    return {int(m.group(1)) for c in cwes or [] if (m := CWE_RE.search(str(c)))}


def taint_checked(rules):
    """{file suffix: CWEs that codewatch's taint rules check in that language}."""
    checked = {}
    for rule in rules:
        if rule.get("mode") != "taint":
            continue
        for language in rule.get("languages", []):
            for suffix in LANGUAGE_SUFFIXES.get(language, []):
                checked.setdefault(suffix, set()).update(cwe_numbers(rule.get("metadata", {}).get("cwe")))
    return checked


def added_names(before, after):
    """Function names in after's {rule: {(name, ...)}} that before lacks."""
    return {entry[0] for rule, found in after.items() for entry in found - before.get(rule, set())}


def mentioning(ctx, targets, names):
    """The targets whose text uses one of names. A deeper summary pass only adds sinks or sources for calls to the
    functions the last one found, so a file that never names one gives what it gave before."""
    return [t for t in targets if not names.isdisjoint(WORD_RE.findall(read_source(ctx.root / t) or ""))]


WORD_RE = re.compile(r"\w+")


def read_source(path):
    try:
        return Path(path).read_text()
    except (OSError, UnicodeDecodeError):
        return None


def analysis_copy(source):
    """Python source as Semgrep should see it: dead constant branches blanked, slices made indexes, container
    slots tracked one by one, match statements made ifs and Flask converter types written on view parameters. None
    when nothing changes."""
    current = None
    for rewrite in (blank_dead_branches, index_slices, track_slots, match_as_if, type_route_converters):
        current = rewrite(current or source) or current
    return current


def analysis_copies(ctx, files, copies):
    """Targets for Semgrep: Python files that need it are scanned as rewritten copies (see analysis_copy).
    Returns the target list and {copy path: original relative path}."""
    targets, originals = [], {}
    for rel in files:
        # Semgrep refuses a symlink given as a target and fails the whole scan; the file it points to is scanned.
        if (ctx.root / rel).is_symlink():
            continue
        rewritten = None
        if rel.endswith(".py"):
            try:
                rewritten = analysis_copy((ctx.root / rel).read_text())
            except (OSError, UnicodeDecodeError):
                rewritten = None
        if rewritten is None:
            targets.append(rel)
            continue
        copy = copies / rel
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_text(rewritten)
        targets.append(str(copy))
        originals[str(copy)] = rel
    return targets, originals


def semgrep_type(check_id, metadata):
    """Only rules Semgrep marks "vuln" (taint-checked or a definite flaw) are vulnerabilities;
    "audit" and other security rules flag risky code to review, so they're hotspots."""
    category = metadata.get("category", "")
    if category != "security":
        return SEMGREP_TYPE.get(category, CODE_SMELL)
    vuln = "vuln" in (metadata.get("subcategory") or []) and ".audit." not in check_id
    return VULNERABILITY if vuln else HOTSPOT


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
            if rule in HEADER_ONLY_NOISE and Path(path).suffix.lower() in HEADERS:
                continue
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
            for side, path, other_side, other in zip(sides, paths, sides[::-1], paths[::-1], strict=True):
                if path not in tracked:
                    continue
                start, end = side["start"], side["end"]
                result.duplicated_lines.setdefault(path, set()).update(range(start, end + 1))
                result.findings.append(
                    Finding("jscpd", "duplicated-block", MINOR, CODE_SMELL,
                            f"{end - start + 1} duplicated lines, also in {other}:{other_side['start']}",
                            path, start, end)
                )
        dup_lines = sum(len(v) for v in result.duplicated_lines.values())
        total = data.get("statistics", {}).get("total", {}).get("lines") or 0
        result.metrics["duplicated_lines"] = dup_lines
        if total:
            result.metrics["duplicated_lines_percent"] = round(100 * dup_lines / total, 2)
        return result
