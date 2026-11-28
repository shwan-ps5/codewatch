# Writing and changing rules

## Where a change goes

- **A new source, sink or sanitizer for a weakness that already has a rule** goes into that rule, in its existing
  file (for example, more Node file APIs go into `javascript-taint.yml`'s `codewatch.js.path-traversal`). Don't
  copy sources into a new rule: two rules reporting one line, and an extra rule for the summary passes to
  multiply, both cost more than they find.
- **A new weakness, or a language with no rules yet**, gets a new file, `catalog/codewatch/rules/<language>-<topic>.yml`.
  Files are loaded automatically. YAML anchors don't cross files, so a new file defines its own sources and
  sanitizers.

## Prefer a general fix over one more exclusion

`python-web.yml` has over a hundred `pattern-not`/`pattern-not-inside` clauses, and many were added for a single
CVE. Each one is cheap on its own, but together they make the rules hard to reason about, and a new exclusion can
silently hide a real finding elsewhere (PLAN.md step 152's `regex` exclusion did). Before adding one, ask:

1. **Is this a shape every rule should understand?** "A check that returns on failure clears the value" is
   true for SQL, paths and redirects alike. Put it in a shared anchor (`&validated-guard`, `&prefix-guard`), or
   in an analysis-copy rewrite in `core/analyzers/` when Semgrep's pattern language can't say it. The `else:` →
   `if E:` split is an example of that kind of rewrite.
2. **Can the exclusion be narrower?** Match the sanitizing call and the variable it returns, not a variable
   name. Step 152's first version excluded every variable named `regex`; the fix kept only `regex.$FUNC(...)`
   calls.
3. **What does it cost?** Run `devtools.py cases` on the CVE pairs for that rule, and look at the nightly's app
   findings, before and after.

## Tests

Every rule change gets a test that fails without it, a vulnerable case and a safe look-alike, in
`tests/test_detection.py` or a topic file, `tests/test_<language>_<topic>.py`. `semgrep_vulnerabilities` from
`tests/test_detection.py` is the helper. Check that the test really fails without the change, by reverting the
rule edit and running it.

Without `tools/semgrep-venv`, every rule test skips itself and passes, which proves nothing. Make sure they run.

## Quick loops

```
venv/bin/python benchmarks/devtools.py copy app/views.py        # what Semgrep sees after the rewrites
venv/bin/python benchmarks/devtools.py rules path-traversal app/ # one Semgrep pass of matching rules, no summaries
venv/bin/python benchmarks/devtools.py repos DIR                 # the full analyzer, summaries included
venv/bin/python benchmarks/devtools.py cases GHSA-...            # re-score named CVE pairs (a minute or two)
venv/bin/python benchmarks/smoke.py                              # the CVE pairs CI re-scores on every push
```

## Ground rules for measuring

- **Blind suites** (`"blind": true` in `benchmarks/suites.json`) are scanned once, at the end of a round, and
  never used to adjust rules. Don't read their diffs.
- **Held-out suites** (SecurityEval's Copilot and InCoder answers, Vulnerable-Code-Snippets) are measured, never
  tuned on.
- Record which case drove a change in `docs/plan-log.md` and in the suite's `about` note in `suites.json`.
