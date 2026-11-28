import csv
import io
import json
import os
import re
import tempfile
from pathlib import Path
from typing import NamedTuple

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
    PHP_VIEWS,
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
from .drf_serializers import with_serializer_checks
from .else_branches import rules_for_copies, split_else
from .flask_resources import with_resource_sources
from .inline_scripts import inline_scripts
from .jinja_sandboxes import with_sandbox_sanitizers
from .match_statements import match_as_if
from .php_template_sinks import TEMPLATE_RULE as PHP_TEMPLATE_RULE
from .php_template_sinks import tidy_message as tidy_php_template_message
from .php_template_sinks import with_php_template_sinks
from .project_checks import with_project_checks
from .python_tools import LineCache, complexity_severity, security_purpose
from .route_converters import (
    django_text_parameters,
    mark_url_text,
    mark_viewset_lookups,
    scalar_parameters,
    type_route_converters,
)
from .slices import index_slices
from .starred_targets import unstar_targets
from .stored_fields import with_stored_sources
from .template_sinks import TEMPLATE_EXTENSIONS, with_template_sinks

SEMGREP_SEVERITY = {"ERROR": CRITICAL, "WARNING": MAJOR, "INFO": MINOR}
JS_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
RETURNER_MAX_JS_BYTES = 200_000
# Seconds a rule may take on one focus file in the final scan (Semgrep's default is 5, then skips the file after
# three rules time out).
FOCUS_TIMEOUT = 60
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
    # Templates are scanned as text by the generic template rules (|safe/autoescape off and Flask's non-autoescaped
    # extensions); the Python render calls are scanned by the generated taint rule.
    extensions = CODE | {".yml", ".yaml"} | TEMPLATE_EXTENSIONS | PHP_VIEWS

    def __init__(self):
        self.timeouts = set()
        self.first_rules, self.first_found, self.aliases, self.receivers = [], [], {}, {}

    def binary(self):
        # Own venv: semgrep pins dependencies (e.g. an old mcp) that conflict with codewatch's.
        return isolated_tool("semgrep") or super().binary()

    def exec(self, args, ctx, ok_codes=(0,), stream="stdout", cwd=None):
        # semgrep-core gives each of its workers an io_uring, whose memory counts against the user's locked-memory
        # limit (8 MB by default): a few scans at once failed with "io_uring_queue_init: Cannot allocate memory".
        # Plain POSIX I/O has no such limit.
        os.environ.setdefault("EIO_BACKEND", "posix")
        return super().exec(args, ctx, ok_codes, stream, cwd)

    @staticmethod
    def project_rules(ctx, custom_rules):
        """codewatch's rules with the sources, sinks and sanitizers learnt from this project's own code."""
        python_texts = [read_source(ctx.root / f) or "" for f in ctx.files_with({".py"})]
        for add in (with_model_sources, with_serializer_checks, with_resource_sources, with_sandbox_sanitizers,
                    with_project_checks, with_stored_sources):
            custom_rules = add(custom_rules, python_texts)
        custom_rules = with_template_sinks(custom_rules, {
            f: text for f in ctx.files_with(TEMPLATE_EXTENSIONS) if (text := read_source(ctx.root / f)) is not None})
        php_texts = {f: text for f in ctx.files_with(PHP_TEMPLATE_CANDIDATES)
                     if (text := read_source(ctx.root / f)) is not None}
        return with_php_template_sinks(custom_rules, php_texts,
                                       [t for f, t in php_texts.items() if f.endswith(".php")])

    def learn(self, ctx, custom_rules, copies):
        """The summary rounds of summaries.py over the summary targets: what the final rules are built from."""
        targets, originals, work = copies
        near = self.summary_targets(ctx, targets, originals)
        # The first round of pass_rules shares pass 1's first scan.
        signatures = self.signatures(ctx, near)
        js_functions = self.js_functions(ctx, near)
        self.first_rules = (summaries_module.pass_rules(custom_rules, set(signatures))
                            + summaries_module.js_pass_rules(custom_rules, js_functions))
        summaries, hits = self.summarise(ctx, custom_rules, near, originals, work)
        passes = self.find_passes(ctx, custom_rules, (near, originals, work), signatures)
        summaries, hits = self.resummarise(ctx, custom_rules, (near, originals, work),
                                           (summaries, hits), (signatures, js_functions, passes))
        returners, fields = self.find_returners(
            ctx, summaries_module.with_arguments(custom_rules, signatures, passes), near, originals, work)
        return Learnt(signatures, js_functions, passes, summaries, hits, returners, fields)

    def final_rules(self, custom_rules, known):
        final = summaries_module.with_pass_through(
            summaries_module.with_arguments(custom_rules, known.signatures, known.passes, known.summaries),
            {False: set(known.signatures), True: known.js_functions}, known.passes, known.summaries, known.returners)
        return (final + summaries_module.via_rules(final, known.summaries, self.receivers)
                + summaries_module.from_rules(final, known.returners, known.summaries)
                + summaries_module.field_variants(final, known.fields, known.summaries))

    def main_scan(self, ctx, rules, copies):
        """The scan whose results are reported: the registry config and the final rules."""
        targets, originals, work = copies
        configs = [CONFIG, ctx.semgrep_config] if ctx.semgrep_config else []
        if rules:
            (work / "custom.yml").write_text(yaml.safe_dump({"rules": rules}, sort_keys=False))
            configs += [CONFIG, str(work / "custom.yml")]
        # Every rule in this pass reads one file at a time, so narrowing it to the focus changes nothing
        # in those files; the summaries above still saw every file.
        focus = None if ctx.focus is None else set(ctx.focus)
        main_targets = targets if focus is None else [t for t in targets if ctx.rel(originals.get(t, t)) in focus]
        # Semgrep given no targets scans the working directory. The focus is the only place findings count,
        # and a few files: there each rule gets FOCUS_TIMEOUT and no file is skipped for its timeouts (mlflow
        # GHSA-wqmh's file_store.py and handlers.py were skipped at the default 5 s; PLAN.md step 68). So does a
        # developer's own check (codewatch check, in CI too), where every finding counts: on a busy CI runner the
        # default dropped this repository's 4,300-line tests/test_detection.py now and then (PLAN.md step 125).
        long = focus is not None or ctx.local
        limits = ["--timeout", str(FOCUS_TIMEOUT), "--timeout-threshold", "0"] if long else []
        return self.scan(ctx, configs, main_targets, limits) if main_targets else {"results": []}

    def gave_up_paths(self, ctx, originals):
        """The files some rule timed out on, in any round (summary passes included), relative to the root."""
        return sorted({ctx.rel(originals.get(p, p)) for p in self.timeouts})

    def timeout_notes(self, ctx, originals):
        if not self.timeouts:
            return []
        paths = self.gave_up_paths(ctx, originals)
        listed = f"{', '.join(paths[:5])}{' and more' if len(paths) > 5 else ''}"
        return [f"Semgrep gave up on some rules in {len(paths)} file(s), so they may hide findings: {listed}."]

    def run(self, ctx):
        custom_rules = yaml.safe_load(ctx.custom_rules).get("rules", []) if ctx.custom_rules else []
        if not ctx.semgrep_config and not custom_rules:
            return Result()
        custom_rules = self.project_rules(ctx, rules_for_copies(custom_rules))
        self.timeouts, self.first_found = set(), []
        with tempfile.TemporaryDirectory() as work:
            targets, originals = analysis_copies(ctx, ctx.files_with(self.extensions), Path(work) / "copies")
            copies = (targets, originals, Path(work))
            known = self.learn(ctx, custom_rules, copies)
            data = self.main_scan(ctx, self.final_rules(custom_rules, known), copies)
        result = Result()
        result.notes += self.timeout_notes(ctx, originals)
        result.gave_up = self.gave_up_paths(ctx, originals)
        reading = Reading(ctx, originals, custom_rules, known, taint_checked(custom_rules), LineCache(ctx.root))
        found = [f for item in data["results"] if (f := self.result_finding(reading, item)) is not None]
        result.findings = without_derived_duplicates(found)
        result.findings += self.uncalled_entry_points(ctx, custom_rules, known.hits, result.findings)
        return result

    def result_visible(self, reading, item, check, said):
        """Whether a result stands: a summarised keyword reached, a via/from/field variant whose function is
        visible from the file, and no CSRF token in a form the registry rule flagged."""
        ctx, known = reading.ctx, reading.known
        path, (check_id, via, field, derived), (custom_id, message, callee, keyword) = reading.path(item), check, said
        if not summaries_module.keyword_summarised(callee, keyword, known.summaries.get(custom_id, ())):
            return False
        if not self.variant_visible(ctx, path, (via, field, derived), (custom_id, message, known)):
            return False
        return not (check_id.endswith(CSRF_FORM_RULE) and form_has_csrf_token(
            reading.source.lines(path), item["start"]["line"], item["end"]["line"]))

    def variant_visible(self, ctx, path, variant, said):
        """A via, field or from variant's function (or field) is visible from the result's file."""
        (via, field, derived), (custom_id, message, known) = variant, said
        if via:
            return self.via_visible(ctx, path, message, known.summaries.get(custom_id, ()))
        if field:
            return self.field_stored(path, message, known.fields.get(custom_id, ()))
        return not derived or self.from_visible(ctx, path, message, known.returners.get(custom_id, ()))

    def result_finding(self, reading, item):
        """A Semgrep result as a finding, or None when it doesn't stand (result_visible)."""
        path = reading.path(item)
        extra = item["extra"]
        check = derived_check(item["check_id"])
        # Semgrep prefixes rules from a local file with path segments; map them back to codewatch's IDs.
        custom_id = next((cid for cid in reading.custom_ids if check[0].endswith(cid)), None)
        message, callee, keyword = summaries_module.split_keyword(extra["message"].strip())
        if custom_id == PHP_TEMPLATE_RULE:
            message = tidy_php_template_message(message)
        if not self.result_visible(reading, item, check, (custom_id, message, callee, keyword)):
            return None
        kind = result_kind(reading, item, check[0], custom_id)
        return Finding("codewatch" if custom_id else "semgrep", custom_id or check[0],
                       SEMGREP_SEVERITY.get(extra.get("severity"), MINOR), kind, message,
                       path, item["start"]["line"], item["end"]["line"])

    @staticmethod
    def summary_targets(ctx, targets, originals):
        """The targets the summary rounds scan: with a focus, the focus files and what they import
        (summaries.import_closure; PLAN step 64), otherwise all of them. CODEWATCH_SUMMARY_SCOPE=all scans all
        of them anyway, to compare the two."""
        if ctx.focus is None or os.environ.get("CODEWATCH_SUMMARY_SCOPE") == "all":
            return targets
        rels = {t: ctx.rel(originals.get(t, t)) for t in targets}
        near = summaries_module.import_closure(set(rels.values()), ctx.focus,
                                               lambda rel: read_source(ctx.root / rel))
        return [t for t in targets if rels[t] in near]

    def project_names(self, ctx):
        """(names the project's code uses outside their definitions, {Python file: scalar parameters})."""
        files = [(f, read_source(ctx.root / f) or "") for f in ctx.files_with((self.extensions or set()) & CODE)]
        return (summaries_module.referenced_names(files),
                {f: scalar_parameters(text) for f, text in files if f.endswith(".py")})

    def uncalled_entry_points(self, ctx, custom_rules, hits, findings):
        """A parameter that reaches a sink in a function nothing in the project calls: the data comes from
        whoever does (a library user, a framework, a handler registered by name elsewhere), so it is left for
        review rather than claimed as a vulnerability."""
        if not hits:
            return []
        used, scalars = self.project_names(ctx)
        rules = {r["id"]: r for r in custom_rules}
        seen = {(f.rule, f.path, f.line) for f in findings}
        out = []
        for rule_id, path, line, func, param in sorted(hits):
            if entry_point(func, path, (used, scalars.get(path, ()), ctx.focus), param) and \
                    (rule_id, path, line) not in seen:
                seen.add((rule_id, path, line))
                out.append(entry_point_finding(rules[rule_id], rule_id, (path, line, func, param)))
        return out

    def scan(self, ctx, configs, targets, limits=()):
        # Several scans at once (parallel benchmarks) share the CPUs: Semgrep's default, a job per CPU each,
        # stretched every rule past its timeout and dropped findings without an error.
        jobs = ["--jobs", os.environ["CODEWATCH_SEMGREP_JOBS"]] if os.environ.get("CODEWATCH_SEMGREP_JOBS") else []
        args = ["scan", *configs, *jobs, *limits, "--json", "--metrics=off", "--quiet", "--disable-version-check", *targets]
        data = json.loads(self.exec(args, ctx, ok_codes=(0, 1)))
        # A timeout skips that rule on that file, silently unless it's reported.
        self.timeouts.update(e["path"] for e in data.get("errors", []) if e.get("type") == "Timeout" and e.get("path"))
        return data

    def rule_results(self, ctx, rules, scanned, place):
        """(rule id, original path, line, message) for each result of scanning with rules. place: (config file,
        originals, form). A result's id is the rule's own (Semgrep prefixes a local file's rules with path
        segments), except in the "pass" form, which keeps Semgrep's; "pass" and "returner" strip the message."""
        config, originals, form = place
        strip = form in ("pass", "returner")
        config.write_text(yaml.safe_dump({"rules": rules}, sort_keys=False))
        data = self.scan(ctx, [CONFIG, str(config)], scanned)
        ids = [] if form == "pass" else [r["id"] for r in rules]
        return [(next((i for i in ids if item["check_id"].endswith(i)), item["check_id"]),
                 ctx.rel(originals.get(item["path"], item["path"])), item["start"]["line"],
                 item["extra"]["message"].strip() if strip else item["extra"]["message"])
                for item in data["results"]]

    def summarise(self, ctx, custom_rules, targets, originals, work):
        """Pass 1 of summaries.py: which function parameters reach each taint rule's sinks, directly or through
        functions already summarised. self.first_rules join the first scan, their results kept in
        self.first_found."""
        summaries, known, new, hits = {}, None, None, []
        scanned = targets
        texts = list(python_texts(ctx, targets).values())
        self.aliases = {}
        # Keyed by the original's path, as summaries are: a rewritten file is scanned from its analysis copy.
        self.receivers = summaries_module.typed_receivers(dict(zip(
            [ctx.rel(originals.get(t, t)) for t in python_texts(ctx, targets)], texts, strict=True)))
        for _ in range(summaries_module.MAX_DEPTH):
            # Semi-naive: a deeper pass has only the summaries the last one added as sinks. Whatever reaches an
            # older one was found when it was added, in every file that names it.
            own = summaries_module.summary_rules(custom_rules, new, base=new is None, receivers=self.receivers)
            rules = own + (self.first_rules if new is None else [])
            if not rules or not scanned:
                break
            found = self.rule_results(ctx, rules, scanned, (work / "summaries.yml", originals, "summary"))
            if new is None:
                found = self.keep_first_found(found, rules, own)
            more = summaries_module.parse_summaries(found, lambda rel: read_source(ctx.root / rel), known, hits)
            self.aliases.update(summaries_module.python_aliases(texts, all_names(more)))
            merged = summaries_module.merge(summaries, summaries_module.with_aliases(more, self.aliases))
            if merged is None:
                break
            new = summaries_module.added(summaries, merged)
            scanned = mentioning(ctx, targets, added_names(summaries, merged))
            summaries = known = merged
        return summaries, hits

    def keep_first_found(self, found, rules, own):
        """The first scan's results for the pass rules that joined it, set aside in self.first_found; the rest."""
        theirs = {r["id"] for r in rules} - {r["id"] for r in own}
        self.first_found = [f for f in found if f[0] in theirs]
        return [f for f in found if f[0] not in theirs]

    def resummarise(self, ctx, custom_rules, copies, found, known):
        """Pass 1 again for the summaries that rest on a call the passes now say hands nothing back
        (stale_summaries): only their defining files, with with_pass_through's sanitizers; a function no longer
        summarised makes its summarised callers stale in turn. copies: (targets, originals, work); found:
        (summaries, hits); known: (signatures, js_functions, passes)."""
        targets, originals, work = copies
        summaries, hits = found
        signatures, js_functions, passes = known
        functions = {False: set(signatures), True: js_functions}
        texts = python_texts(ctx, targets)
        stale = summaries_module.stale_summaries(custom_rules, summaries, texts, (functions, passes, signatures))
        # A round scans its stale functions without their summaries as sinks, so one resting on another stale one
        # (SQLBot's preview on exec_sql, CVE-2026-53556) is dropped though its callee comes back: such functions
        # get another round, with the callees this round confirmed.
        for _ in range(summaries_module.MAX_DEPTH + 1):
            if not stale:
                break
            kept = without_stale(summaries, stale)
            rules = self.stale_rules(custom_rules, stale, kept, (signatures, functions, passes))
            scanned = sorted(summaries_module.python_definers(texts, set().union(*stale.values())))
            if not rules or not scanned:
                break
            results = tuple(self.rule_results(ctx, rules, scanned, (work / "resummaries.yml", originals, "summary")))
            again = only_stale(summaries_module.parse_summaries(results, lambda rel: read_source(ctx.root / rel),
                                                                kept), stale)
            updated = summaries_module.merge(kept, again) or kept
            gone = {rule: names_of(summaries.get(rule, set()) - updated.get(rule, set())) for rule in stale}
            summaries = updated
            stale = still_stale(texts, gone, {rule: names_of(entries) for rule, entries in again.items()}, summaries)
        summaries = summaries_module.realiased(summaries, self.aliases)
        return summaries, live_hits(summaries, hits)

    def stale_rules(self, custom_rules, stale, kept, known):
        """Summary rules for the stale functions' rules, with the sanitizers the passes allow."""
        signatures, functions, passes = known
        cleaned = summaries_module.with_pass_through(
            summaries_module.with_arguments(custom_rules, signatures, passes, kept), functions, passes, kept, {})
        return [r for r in summaries_module.summary_rules(cleaned, kept, base=True, receivers=self.receivers)
                if r["id"].removesuffix(summaries_module.SUMMARY_SUFFIX) in stale]

    @staticmethod
    def signatures(ctx, targets):
        """python_signatures of the functions whose result is assigned, returned or passed on to another call: the
        ones pass_rules asks about."""
        calls = summaries_module.assigned_calls(
            (read_source(ctx.root / t) or "" for t in targets if t.endswith(".py")), python=True)
        return {name: defs for name, defs in summaries_module.python_signatures(
            read_source(ctx.root / f) or "" for f in ctx.files_with({".py"})).items() if name in calls}

    @staticmethod
    def js_functions(ctx, targets):
        """js_functions whose result is assigned or returned in a file that reads the request, and not also a Python
        function's name (pass-through rounds after the first replace Python's answers by name). Asking about every
        assigned call made a large app's scan half as long again (actual)."""
        texts = [read_source(ctx.root / t) or "" for t in targets if Path(t).suffix in JS]
        handling = [text for text in texts if summaries_module.JS_REQUEST_RE.search(text)]
        python = {name for text in python_texts(ctx, targets).values() for name in summaries_module.python_functions(text)}
        return summaries_module.js_functions(texts) & summaries_module.assigned_calls(handling) - python

    def find_passes(self, ctx, custom_rules, copies, signatures):
        """Which parameters of signatures' functions can be returned (pass_rules), from the first round's results
        (self.first_found). Later rounds clean the arguments the last one found aren't handed back, asking again only
        about the functions that call one whose answer changed. copies: (targets, originals, work)."""
        targets, originals, work = copies
        js_ids = {rule["id"] for rule in custom_rules if summaries_module.is_js(rule)}
        texts = python_texts(ctx, targets)
        passes = summaries_module.parse_passes([(c, p, line, m.strip()) for c, p, line, m in self.first_found])
        # Before the first round every argument counted as handed back.
        changed = set(signatures)
        for _ in range(summaries_module.PASS_MAX_ROUNDS - 1):
            # Only a function that hands something back and calls one whose answer changed can change, and only
            # the files defining one need a scan.
            asked = set(summaries_module.python_callers(texts, changed)) & all_names(passes)
            found = self.pass_round(ctx, custom_rules, (texts, asked, signatures, passes), (work, originals))
            if found is None:
                break
            kept = kept_passes(passes, js_ids, asked)
            found = summaries_module.merge(kept, found) or kept
            changed = changed_names(found, passes)
            passes = found
        return passes

    def pass_round(self, ctx, custom_rules, asking, place):
        """The passes a round finds for the functions asked about, or None when there is nothing to scan. asking:
        (texts, asked, signatures, passes); place: (work, originals)."""
        texts, asked, signatures, passes = asking
        work, originals = place
        scanned = sorted(summaries_module.python_definers(texts, asked))
        rules = summaries_module.pass_rules(custom_rules, asked, signatures, passes)
        if not rules or not scanned:
            return None
        return summaries_module.parse_passes(
            self.rule_results(ctx, rules, scanned, (work / "passes.yml", originals, "pass")))

    def find_returners(self, ctx, custom_rules, targets, originals, work):
        """Pass 3 of summaries.py: which functions return request data, directly or from returners found before,
        and (in the first scan) which fields of self/this request data is stored in."""
        returners, fields = {}, {}
        # An unminified library bundled with the app (materialize.js, 366 KB) multiplies this pass's time by ten,
        # and big single-file apps are Python's habit, not JavaScript's.
        targets = [t for t in targets if not oversized_js(ctx, t)]
        scanned, new = targets, {}
        for depth in range(summaries_module.MAX_DEPTH):
            # Semi-naive, as in summarise: a deeper pass's sources are calls to the returners the last one added.
            rules = returner_round_rules(custom_rules, new, depth)
            if not rules or not scanned:
                break
            found = self.rule_results(ctx, rules, scanned, (work / "returners.yml", originals, "returner"))
            stored = [f for f in found if f[0].endswith(summaries_module.FIELDS_SUFFIX)]
            fields = summaries_module.merge(fields, summaries_module.parse_fields(stored)) or fields
            more = summaries_module.parse_returners(without(found, stored), lambda rel: read_source(ctx.root / rel))
            merged = summaries_module.merge(returners, more)
            if merged is None:
                break
            new = summaries_module.added(returners, merged)
            scanned = mentioning(ctx, targets, added_names(returners, merged))
            returners = merged
        return returners, fields

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


CONFIG = "--config"


class Learnt(NamedTuple):
    """What the summary rounds found, which the final rules and the results' checks are built from."""
    signatures: dict
    js_functions: set
    passes: dict
    summaries: dict
    hits: list
    returners: dict
    fields: dict


class Reading(NamedTuple):
    """What reading the main scan's results needs."""
    ctx: object
    originals: dict
    custom_rules: list
    known: Learnt
    traced: dict
    source: LineCache

    @property
    def custom_ids(self):
        return [r["id"] for r in self.custom_rules]

    def path(self, item):
        return self.ctx.rel(self.originals.get(item["path"], item["path"]))


def derived_check(check_id):
    """(rule id without variant suffixes, a via variant, a field variant, any variant)."""
    plain = check_id.removesuffix(summaries_module.VIA_SUFFIX)
    via, field = plain != check_id, plain.endswith(summaries_module.FIELD_SUFFIX)
    plain = plain.removesuffix(summaries_module.FIELD_SUFFIX).removesuffix(summaries_module.FROM_SUFFIX)
    return plain, via, field, plain != check_id


def result_kind(reading, item, check_id, custom_id):
    """A result's type: the rule's, made a hotspot where it is left for review."""
    path, metadata = reading.path(item), item["extra"].get("metadata", {})
    kind = semgrep_type(check_id, metadata)
    if kind != VULNERABILITY:
        return kind
    # codewatch's own taint rule for this weakness already followed the data here; a registry rule that matches
    # the same weakness without seeing guards or sanitizers is left for review, not a verdict. A template's
    # inline scripts are scanned as JavaScript, so its findings are judged like a .js file's.
    suffix = ".js" if Path(path).suffix in TEMPLATE_EXTENSIONS else Path(path).suffix
    if not custom_id and cwe_numbers(metadata.get("cwe")) & reading.traced.get(suffix, set()):
        return HOTSPOT
    # Rules for primitives that are only weak when they protect something (MD5 for a Gravatar URL is fine): a
    # vulnerability where the code is about secrets or verification, otherwise for review.
    if (metadata.get("security-purpose") == "required"
            and not security_purpose(reading.source, path, item["start"]["line"])):
        return HOTSPOT
    # Test code isn't served to anyone, so what flows through it is for review, not a verdict.
    return HOTSPOT if is_test_file(path) else kind


def derived(finding):
    return any(r.search(finding.message) for r in (summaries_module.VIA_RE, summaries_module.FROM_RE,
                                                   summaries_module.FIELD_RE))


def without_derived_duplicates(findings):
    """A via/from/field finding on a line a direct finding of the same rule already reports is dropped."""
    direct = {(f.rule, f.path, f.line) for f in findings if not derived(f)}
    return [f for f in findings if not (derived(f) and (f.rule, f.path, f.line) in direct)]


def still_stale(texts, gone, confirmed, summaries):
    """{rule: functions to summarise again}: callers summarised through a function that no longer is, and
    functions this round dropped that call one it kept."""
    stale = {}
    for rule, names_gone in gone.items():
        if not names_gone:
            continue
        callers = ((set(summaries_module.python_callers(texts, names_gone)) & {e[0] for e in summaries.get(rule, ())})
                   | (names_gone & set(summaries_module.python_callers(texts, confirmed.get(rule, set())))))
        if callers:
            stale[rule] = callers
    return stale


def python_texts(ctx, targets):
    """{target: its text} for the Python targets, in order."""
    return {t: read_source(ctx.root / t) or "" for t in targets if t.endswith(".py")}


def names_of(entries):
    return {e[0] for e in entries}


def all_names(found):
    """Every function name in a {rule: {(name, ...)}}."""
    return {e[0] for entries in found.values() for e in entries}


def without_stale(summaries, stale):
    return {rule: {e for e in entries if e[0] not in stale.get(rule, ())} for rule, entries in summaries.items()}


def only_stale(found, stale):
    return {rule: {e for e in entries if e[0] in stale.get(rule, ())} for rule, entries in found.items()}


def live_hits(summaries, hits):
    """The hits of functions still summarised."""
    live = {(rule, e[0], e[4]) for rule, entries in summaries.items() for e in entries}
    return [h for h in hits if (h[0], h[3], h[1]) in live]


def changed_names(found, before):
    """Function names whose answers differ between two {rule: {(name, ...)}}."""
    return {e[0] for rule in set(found) | set(before) for e in found.get(rule, set()) ^ before.get(rule, set())}


def oversized_js(ctx, target):
    return Path(target).suffix in JS_SUFFIXES and (ctx.root / target).stat().st_size > RETURNER_MAX_JS_BYTES


def kept_passes(passes, js_ids, asked):
    """The passes kept into the next round: a JavaScript rule's all, a Python rule's except the functions asked
    about again."""
    return {rule: {e for e in entries if rule in js_ids or e[0] not in asked} for rule, entries in passes.items()}


def returner_round_rules(custom_rules, new, depth):
    """A returner round's rules; the first also asks which self/this fields store request data."""
    rules = summaries_module.returner_rules(custom_rules, new, base=depth == 0)
    return rules + (summaries_module.field_rules(custom_rules) if depth == 0 else [])


def without(items, dropped):
    return [x for x in items if x not in dropped]


def entry_point(func, path, known, param):
    """Whether a summarised parameter is an uncalled entry point to report: a public function nothing calls, not
    in a test, with a parameter that can carry text, in the focus. known: (names used, scalar parameters, focus)."""
    used, scalars, focus = known
    return not (func in used or func.startswith("_") or is_test_file(path) or (func, param) in scalars
                or (focus is not None and path not in focus))


def entry_point_finding(rule, rule_id, hit):
    path, line, func, param = hit
    message = (f"{rule['message'].strip()} [parameter {param} of {func}(), which nothing in the project "
               f"calls: check what its callers pass]")
    return Finding("codewatch", rule_id, SEMGREP_SEVERITY.get(rule.get("severity"), MINOR), HOTSPOT,
                   message, path, line, line)


LANGUAGE_SUFFIXES = {"python": [".py"], "javascript": [".js", ".jsx", ".mjs", ".cjs"], "typescript": [".ts", ".tsx"],
                     "php": [".php"]}
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


def analysis_copy(source, url_views=None):
    """Python source as Semgrep should see it: dead constant branches blanked, slices made indexes, starred targets unstarred, container
    slots tracked one by one, match statements made ifs, else branches made ifs of their own, Flask converter types written on view parameters and
    Django views' free-text URL arguments marked (url_views, from django_text_parameters), and DRF ViewSets'
    lookups. None when nothing changes."""
    current = None
    for rewrite in (blank_dead_branches, index_slices, unstar_targets, track_slots, match_as_if, split_else,
                    type_route_converters, mark_viewset_lookups,
                    lambda text: mark_url_text(text, url_views)):
        current = rewrite(current or source) or current
    return current


def url_routes(ctx, files):
    """django_text_parameters for the project's Django URL modules (urls.py, or a urls package)."""
    return django_text_parameters(
        text for rel in files if "urls" in Path(rel).parts[-1] or "urls" in Path(rel).parts[:-1]
        if (text := read_source(ctx.root / rel)) is not None)


def rewritten_source(ctx, rel, url_views):
    """A PHP or Python file's analysis copy text (see analysis_copy and php_copy_text), or None."""
    if rel.endswith(".php"):
        text = read_source(ctx.root / rel)
        return php_copy_text(text) if text and "compact(" in text else None
    if rel.endswith(".py"):
        try:
            return analysis_copy((ctx.root / rel).read_text(), url_views)
        except (OSError, UnicodeDecodeError):
            return None
    return None


def add_rewritten(rel, rewritten, copies, found):
    """The file as a target: itself, or its rewritten copy mapped back to it. found: (targets, originals)."""
    targets, originals = found
    if rewritten is None:
        targets.append(rel)
        return
    copy = copies / rel
    copy.parent.mkdir(parents=True, exist_ok=True)
    copy.write_text(rewritten)
    targets.append(str(copy))
    originals[str(copy)] = rel


def analysis_copies(ctx, files, copies):
    """Targets for Semgrep: Python files that need it are scanned as rewritten copies (see analysis_copy).
    Returns the target list and {copy path: original relative path}."""
    targets, originals = [], {}
    url_views = url_routes(ctx, [rel for rel in files if rel.endswith(".py")])
    # Semgrep refuses a symlink given as a target and fails the whole scan; the file it points to is scanned.
    for rel in (rel for rel in files if not (ctx.root / rel).is_symlink()):
        rewritten = rewritten_source(ctx, rel, url_views)
        suffix = Path(rel).suffix.lower()
        if suffix in TEMPLATE_EXTENSIONS:
            add_inline_scripts(ctx, rel, copies, targets, originals)
        if suffix in PHP_VIEWS:
            add_php_copy(ctx, rel, copies, targets, originals)
        else:
            add_rewritten(rel, rewritten, copies, (targets, originals))
    return targets, originals


# Files read for PHP templates and their variables (php_template_sinks.py).
PHP_TEMPLATE_CANDIDATES = {".php", ".ctp", ".phtml", ".tpl", ".twig", ".latte"}
PHP_TAG_RE = re.compile(r"<\?(php\b|=)")
COMPACT_RE = re.compile(r"\bcompact\(\s*((?:['\"]\w+['\"]\s*,\s*)*['\"]\w+['\"])\s*\)")


def php_copy_text(text):
    """PHP as Semgrep should see it: compact('a', 'b') written out as ['a' => $a, 'b' => $b], on the same line, so
    the variables it passes to a view are seen (Laravel's view('x', compact('user')), CakePHP's
    $this->set(compact('referer'))). None when nothing changes."""
    def written(match):
        keys = re.findall(r"['\"](\w+)['\"]", match.group(1))
        return "[" + ", ".join(f"'{k}' => ${k}" for k in keys) + "]"
    rewritten = COMPACT_RE.sub(written, text)
    return None if rewritten == text else rewritten


def add_php_copy(ctx, rel, copies, targets, originals):
    """A PHP view or include (base.PHP_VIEWS) as a .php copy, mapped back to it: Semgrep picks a file's language by
    its extension and skips these (MISP's CakePHP 2 views, GHSA-p9m5). A file with no PHP tag (an .inc of another
    language) is left out."""
    text = read_source(ctx.root / rel)
    if not text or not PHP_TAG_RE.search(text):
        return
    copy = copies / f"{rel}.php"
    copy.parent.mkdir(parents=True, exist_ok=True)
    copy.write_text(php_copy_text(text) or text)
    targets.append(str(copy))
    originals[str(copy)] = rel


def add_inline_scripts(ctx, rel, copies, targets, originals):
    """A template's inline scripts as a .js copy beside it (inline_scripts.py), mapped back to the template."""
    text = read_source(ctx.root / rel)
    script = inline_scripts(text) if text else None
    if script is None:
        return
    copy = copies / f"{rel}.inline.js"
    copy.parent.mkdir(parents=True, exist_ok=True)
    copy.write_text(script)
    targets.append(str(copy))
    originals[str(copy)] = rel


CSRF_FORM_RULE = "django-no-csrf-token"
CSRF_TOKEN_RE = re.compile(r"\{%-?\s*csrf_token\s*-?%\}")


def form_has_csrf_token(lines, start, end):
    """Whether the form Semgrep matched (lines start..end) has a {% csrf_token %}. The registry's
    django-no-csrf-token rule checks with `...`, which in generic mode spans about ten lines, so any longer form
    was reported without its token (codewatch's own project settings form, 2026-11-18)."""
    return bool(CSRF_TOKEN_RE.search("\n".join(lines[start - 1:end])))


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
