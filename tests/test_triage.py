from benchmarks import triage


def test_triages_only_findings_new_since_the_previous_report(tmp_path, monkeypatch):
    monkeypatch.setattr(triage, "NIGHTLY", tmp_path)
    old, new = tmp_path / "2026-11-02", tmp_path / "2026-11-03"
    old.mkdir()
    new.mkdir()
    (old / "apps.txt").write_text("app a.py 3 xss\n")
    (new / "apps.txt").write_text("app a.py 3 xss\napp b.py 9 sql-injection\n")
    assert triage.findings(new, everything=False) == [("app", "b.py", "9", "sql-injection")]
    assert len(triage.findings(new, everything=True)) == 2


def test_code_around_marks_the_flagged_line(tmp_path):
    (tmp_path / "a.py").write_text("\n".join(f"line{n}" for n in range(1, 101)))
    code = triage.code_around(tmp_path, "a.py", 50)
    assert ">>   50 line50" in code
    assert "   10 line10" in code and "line9\n" not in code and "line91" not in code
