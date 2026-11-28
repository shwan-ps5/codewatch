"""Rules are written against ordinary Python; the copies Semgrep scans split `else:` into `if E:`
(core/analyzers/else_branches.py), so the rules' patterns are rewritten the same way before they run."""
from core.analyzers.else_branches import pattern_for_copies, rules_for_copies, split_else


def test_an_if_statements_else_in_a_pattern_is_written_as_the_copies_have_it():
    pattern = "if $COND:\n  ...\n  if $X:\n    return ...\nelse:\n  return ...\n...\n"
    assert pattern_for_copies(pattern) == "if $COND:\n  ...\n  if $X:\n    return ...\nif E:\n  return ...\n...\n"


def test_the_pattern_matches_the_copy_split_else_makes():
    source = "if a:\n    x = 1\nelse:\n    x = 2\n"
    assert pattern_for_copies(source) == split_else(source)


def test_a_loops_or_trys_else_is_left_alone_as_the_copies_leave_it():
    for opener in ("for $X in $Y:", "while $C:", "try:"):
        pattern = f"{opener}\n  ...\nelse:\n  ...\n"
        assert pattern_for_copies(pattern) == pattern


def test_only_python_rules_and_their_pattern_keys_change():
    rule = {"id": "r", "languages": ["python"], "message": "else:\n",
            "patterns": [{"pattern-inside": "if $C:\n  ...\nelse:\n  ...\n"}, {"pattern": "$X"}]}
    js = {"id": "j", "languages": ["javascript"], "pattern": "if ($C) {} else {}"}
    python, javascript = rules_for_copies([rule, js])
    assert python["patterns"][0]["pattern-inside"] == "if $C:\n  ...\nif E:\n  ...\n"
    assert python["message"] == "else:\n"
    assert javascript == js
