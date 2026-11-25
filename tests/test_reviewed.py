import json

from benchmarks import reviewed


def test_reviewed_finds_advisories_and_fix_commits(tmp_path, capsys):
    (tmp_path / "cve-candidates-x.tsv").write_text(
        "# comment\n\nrepo\tid\tcwe\tdecision\tsuite\treason\n"
        "a/b\tGHSA-rej\t79\treject\t\tlibrary code\n"
        "a/c\tGHSA-acc\t22\taccept\tcve-pairs-python\tflow\n")
    (tmp_path / "suites.json").write_text(json.dumps({"suites": [
        {"name": "owasp", "kind": "owasp-benchmark"},
        {"name": "cve-pairs-python", "kind": "cve-pairs", "cases": [{"id": "GHSA-in", "fix": "abcdef1234" * 4}]},
    ]}))
    assert reviewed.main(["GHSA-new"], root=tmp_path, db=None) == 0
    assert reviewed.main(["GHSA-rej", "abcdef12", "GHSA-acc"], root=tmp_path, db=None) == 1
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "GHSA-new\tnew"
    assert out[1].startswith("GHSA-rej\trejected")
    assert out[2].startswith("abcdef12 (GHSA-in)\tsuite:cve-pairs-python")
    assert out[3].startswith("GHSA-acc\taccepted")


def test_a_rejected_fix_commit_is_found_by_its_hash(tmp_path, capsys):
    (tmp_path / "cve-candidates-x.tsv").write_text(
        "repo\tid\tcwe\tdecision\tsuite\treason\n"
        "a/b\tFIX-a-b-0123456789ab\t79\treject\t\tstricter check\n")
    (tmp_path / "suites.json").write_text(json.dumps({"suites": []}))
    assert reviewed.main(["0123456", "0123456789abcdef0123", "0123457"], root=tmp_path, db=None) == 1
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("0123456 (FIX-a-b-0123456789ab)\trejected")
    assert out[1].startswith("0123456789abcdef0123 (FIX-a-b-0123456789ab)\trejected")
    assert out[2] == "0123457\tnew"


def test_an_advisorys_other_ids_are_known(tmp_path, capsys):
    # Termix GHSA-w3fm was read again as new though its CVE had been rejected an hour before (2026-11-19).
    (tmp_path / "cve-candidates-x.tsv").write_text("repo\tid\tcwe\tdecision\tsuite\treason\n"
                                                   "a/b\tCVE-2026-1\t22\treject\t\trelease commit\n"
                                                   "a/c\tGHSA-acc2\t79\treject\t\tlibrary code\n")
    (tmp_path / "suites.json").write_text(json.dumps({"suites": []}))
    db = tmp_path / "db"
    for ghsa, aliases in {"GHSA-w3fm": ["CVE-2026-1"], "GHSA-acc2": ["CVE-2026-2"], "GHSA-new1": ["CVE-2026-3"],
                          "GHSA-none": []}.items():
        folder = db / "advisories" / "unreviewed" / "2026" / "11" / ghsa
        folder.mkdir(parents=True)
        (folder / f"{ghsa}.json").write_text(json.dumps({"id": ghsa, "aliases": aliases}, indent=2))
    assert reviewed.main(["GHSA-w3fm", "CVE-2026-2", "GHSA-new1", "CVE-2026-3", "GHSA-none"], root=tmp_path, db=db) == 1
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "GHSA-w3fm\trejected\tcve-candidates-x.tsv (as CVE-2026-1)"
    assert out[1] == "CVE-2026-2\trejected\tcve-candidates-x.tsv (as GHSA-acc2)"
    assert out[2:] == ["GHSA-new1\tnew", "CVE-2026-3\tnew", "GHSA-none\tnew"]
    assert reviewed.main(["GHSA-w3fm"], root=tmp_path, db=None) == 0  # without the database, only ids as read
    # The agents' scripts import known() directly; it reads the database unless told not to.
    assert reviewed.known.__defaults__ == (reviewed.HERE, reviewed.ADVISORY_DB)
    assert "GHSA-w3fm" in reviewed.known(tmp_path, db)[0]


def test_split_rule_matches_plan():
    # PLAN.md step 22: blind when int(sha256(id), 16) % 3 == 0.
    assert reviewed.is_blind("GHSA-mxhq-xw3g-rphc")
    assert not reviewed.is_blind("GHSA-wf7x-fh6w-34r6")


def test_measure_ignores_whitespace_tests_and_manifests():
    lines = [
        "diff --git a/app/views.py b/app/views.py", "--- a/app/views.py", "+++ b/app/views.py",
        "-    sql = 'SELECT %s' % x", "+    cursor.execute('SELECT %s', [x])",
        "-        WHERE a = 1", "+            WHERE a = 1", "+",
        "diff --git a/tests/test_views.py b/tests/test_views.py", "+++ b/tests/test_views.py", "+assert 1",
        "diff --git a/package.json b/package.json", "+++ b/package.json", '+"v": 2',
        "diff --git a/src/same.js b/src/same.js", "-a = 1", "+a  =  1",
        "diff --git a/vitest.config.ts b/vitest.config.ts", "+++ b/vitest.config.ts", "+include: []",
        "diff --git a/frontend/src/i18n/en.json b/frontend/src/i18n/en.json", "+++ b/x", '+"k": "v"',
        "diff --git a/app/locale/de/LC_MESSAGES/django.po b/app/locale/de/LC_MESSAGES/django.po", '+msgid "x"',
        "diff --git a/src/lang.ts b/src/lang.ts", "+export const x = 1",
    ]
    assert reviewed.measure("\n".join(lines)) == {"app/views.py": 2, "src/lang.ts": 1}


def _repo(tmp_path):
    import subprocess

    def git(*args):
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)
    git("init", "-q")
    git("config", "user.name", "Shwan")
    git("config", "user.email", "344055753+shwan-ps5@users.noreply.github.com")
    (tmp_path / "benchmarks").mkdir()
    (tmp_path / "README").write_text("x")
    git("add", "-A")
    git("commit", "-qm", "base")
    return git


def test_guard_accepts_clean_batch_and_catches_leaks(tmp_path):
    git = _repo(tmp_path)
    blind, open_ = "GHSA-mxhq-xw3g-rphc", "GHSA-wf7x-fh6w-34r6"
    head = "repo\tid\tcwe\tdecision\tsuite\treason\n"
    tsv = tmp_path / "benchmarks" / "cve-candidates-x.tsv"
    tsv.write_text(head + f"a/b\t{blind}\t79\taccept\tcve-pairs-blind-python-6\t{reviewed.WITHHELD}\n"
                   f"a/c\t{open_}\t22\taccept\tcve-pairs-python\trequest path reaches open()\n")
    (tmp_path / "benchmarks" / "cve-candidates-x.json").write_text(json.dumps({"status": "research only", "accepted": [
        {"id": blind, "suite": "cve-pairs-blind-python-6", "entry": {}},
        {"id": open_, "suite": "cve-pairs-python", "entry": {}, "flow": "f"}]}))
    git("add", "-A")
    git("commit", "-qm", "batch")
    assert reviewed.guard("HEAD~1", repo=tmp_path) == []

    tsv.write_text(head + f"a/b\t{blind}\t79\taccept\tcve-pairs-blind-python-6\tthe flow, leaked\n")
    (tmp_path / "benchmarks" / "cve-candidates-x.json").write_text(json.dumps({"status": "research only", "accepted": [
        {"id": blind, "suite": "cve-pairs-blind-python-6", "entry": {}},
        {"id": open_, "suite": "cve-pairs-python", "entry": {}, "flow": "f2"}]}))
    (tmp_path / "suites.json").write_text("{}")
    git("add", "-A")
    git("commit", "-qm", "leak")
    problems = reviewed.guard("HEAD~1", repo=tmp_path)
    assert any("suites.json" in p for p in problems)
    assert any(f"blind case {blind} has a reason" in p for p in problems)
    assert any(f"{open_} is accepted here but has no accept row" in p for p in problems)


def test_guard_rejects_open_case_sharing_a_blind_fix(tmp_path):
    git = _repo(tmp_path)
    blind, open_, fix = "GHSA-mxhq-xw3g-rphc", "GHSA-wf7x-fh6w-34r6", "ab" * 20
    (tmp_path / "benchmarks" / "cve-candidates-x.tsv").write_text(
        "repo\tid\tcwe\tdecision\tsuite\treason\n"
        f"a/b\t{blind}\t78\taccept\tcve-pairs-blind-javascript-8\t{reviewed.WITHHELD}\n"
        f"a/b\t{open_}\t77\taccept\tcve-pairs-javascript\tflow\n")
    (tmp_path / "benchmarks" / "cve-candidates-x.json").write_text(json.dumps({"status": "research only", "accepted": [
        {"id": blind, "suite": "cve-pairs-blind-javascript-8", "entry": {"fix": fix}},
        {"id": open_, "suite": "cve-pairs-javascript", "entry": {"fix": fix}, "flow": "f"}]}))
    git("add", "-A")
    git("commit", "-qm", "batch")
    assert any(f"open case {open_} has a blind case's fix" in p for p in reviewed.guard("HEAD~1", repo=tmp_path))


def test_pending_counts_unreviewed_batches(tmp_path):
    (tmp_path / "cve-candidates-a.json").write_text(json.dumps({"status": "research only: not reviewed"}))
    (tmp_path / "cve-candidates-b.json").write_text(json.dumps({"status": "reviewed 2026-11-03"}))
    assert reviewed.pending(tmp_path) == ["cve-candidates-a.json"]


def test_guard_takes_gap_notes_about_open_cases_only(tmp_path):
    git = _repo(tmp_path)
    (tmp_path / "benchmarks" / "suites.json").write_text(json.dumps({"suites": [
        {"name": "cve-pairs-python", "kind": "cve-pairs", "cases": [{"id": "GHSA-open"}]},
        {"name": "cve-pairs-blind-python-3", "kind": "cve-pairs", "blind": True, "cases": [{"id": "GHSA-blind"}]},
    ]}))
    git("add", "-A")
    git("commit", "-qm", "suites")
    notes = tmp_path / "benchmarks" / "gap-notes-2026-11-23-1.json"
    notes.write_text(json.dumps({"status": "research only", "notes": [{"id": "GHSA-open", "suite": "cve-pairs-python"}]}))
    git("add", "-A")
    git("commit", "-qm", "notes")
    assert reviewed.guard("HEAD~1", repo=tmp_path) == []
    assert reviewed.pending(tmp_path / "benchmarks", "gap-notes-") == ["gap-notes-2026-11-23-1.json"]

    notes.write_text(json.dumps({"status": "research only", "notes": [
        {"id": "GHSA-blind", "suite": "cve-pairs-blind-python-3"}, {"id": "GHSA-open", "suite": "cve-pairs-php"},
        {"id": "GHSA-unknown", "suite": "cve-pairs-python"}]}))
    git("add", "-A")
    git("commit", "-qm", "leak")
    problems = reviewed.guard("HEAD~1", repo=tmp_path)
    assert any("GHSA-blind is not an open CVE-pair case" in p for p in problems)
    assert any("GHSA-unknown is not an open CVE-pair case" in p for p in problems)
    assert any("GHSA-open is in cve-pairs-python, not cve-pairs-php" in p for p in problems)


def test_guard_takes_gap_notes_of_the_known_tasks_only(tmp_path):
    git = _repo(tmp_path)
    (tmp_path / "benchmarks" / "suites.json").write_text(json.dumps({"suites": [
        {"name": "cve-pairs-python", "kind": "cve-pairs", "cases": [{"id": "GHSA-open"}, {"id": "GHSA-two"}]}]}))
    git("add", "-A")
    git("commit", "-qm", "suites")
    notes = tmp_path / "benchmarks" / "gap-notes-2026-11-25-1.json"
    notes.write_text(json.dumps({"status": "research only", "notes": [
        {"id": "GHSA-open", "suite": "cve-pairs-python", "task": "still-flagged"},
        {"id": "GHSA-two", "suite": "cve-pairs-python", "task": "check-quotes"}]}))
    git("add", "-A")
    git("commit", "-qm", "notes")
    assert reviewed.guard("HEAD~1", repo=tmp_path) == []

    notes.write_text(json.dumps({"status": "research only", "notes": [
        {"id": "GHSA-open", "suite": "cve-pairs-python", "task": "new-rule"}]}))
    git("add", "-A")
    git("commit", "-qm", "unknown task")
    assert any("GHSA-open has task 'new-rule'" in p for p in reviewed.guard("HEAD~1", repo=tmp_path))


def test_a_research_run_cannot_mark_its_own_file_read(tmp_path):
    """gap-notes-2026-11-23-10 came with the status "read 2026-11-23: ...", which hid it from `pending`. The guard
    refuses a run's file that doesn't start "research only", and `pending` lists any file without a review's mark."""
    git = _repo(tmp_path)
    (tmp_path / "benchmarks" / "suites.json").write_text(json.dumps({"suites": [
        {"name": "cve-pairs-python", "kind": "cve-pairs", "cases": [{"id": "GHSA-open"}]}]}))
    git("add", "-A")
    git("commit", "-qm", "suites")
    notes = tmp_path / "benchmarks" / "gap-notes-2026-11-23-10.json"
    notes.write_text(json.dumps({"status": "read 2026-11-23: all located",
                                 "notes": [{"id": "GHSA-open", "suite": "cve-pairs-python"}]}))
    (tmp_path / "benchmarks" / "cve-candidates-2026-11-23-new-9.json").write_text(json.dumps(
        {"status": "reviewed 2026-11-23 (PLAN.md step 1): done", "accepted": []}))
    git("add", "-A")
    git("commit", "-qm", "notes")
    problems = reviewed.guard("HEAD~1", repo=tmp_path)
    assert any("gap-notes-2026-11-23-10.json: status must start with" in p for p in problems)
    assert any("cve-candidates-2026-11-23-new-9.json: status must start with" in p for p in problems)
    assert reviewed.pending(tmp_path / "benchmarks", "gap-notes-") == ["gap-notes-2026-11-23-10.json"]
    (tmp_path / "benchmarks" / "gap-notes-2026-11-23-11.json").write_text(json.dumps(
        {"status": "read 2026-11-23 (PLAN.md step 130): leads", "notes": []}))
    assert reviewed.pending(tmp_path / "benchmarks", "gap-notes-") == ["gap-notes-2026-11-23-10.json"]
