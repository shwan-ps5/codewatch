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
    assert reviewed.main(["GHSA-new"], root=tmp_path) == 0
    assert reviewed.main(["GHSA-rej", "abcdef12", "GHSA-acc"], root=tmp_path) == 1
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "GHSA-new\tnew"
    assert out[1].startswith("GHSA-rej\trejected")
    assert out[2].startswith("abcdef12 (GHSA-in)\tsuite:cve-pairs-python")
    assert out[3].startswith("GHSA-acc\taccepted")


def test_split_rule_matches_plan():
    # PLAN.md step 22: blind when int(sha256(id), 16) % 3 == 0.
    assert reviewed.is_blind("GHSA-mxhq-xw3g-rphc")
    assert not reviewed.is_blind("GHSA-wf7x-fh6w-34r6")
