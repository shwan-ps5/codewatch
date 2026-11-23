"""Front-end JavaScript writing what it fetched into HTML (PLAN.md step 131, from the gap notes; step 42 I)."""
import pytest

from core import catalog
from core.analyzers.base import Context
from core.analyzers.multi_tools import Semgrep
from tests.test_detection import semgrep_vulnerabilities

semgrep = pytest.mark.skipif(not Semgrep().available(), reason="semgrep not installed")


def semgrep_findings(tmp_path, files):
    """{(path, line, rule, type)} of every finding of codewatch's rules, hotspots included."""
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    ctx = Context(root=tmp_path, files=list(files), semgrep_config="", custom_rules=catalog.custom_semgrep_rules())
    return {(f.path, f.line, f.rule.rsplit(".", 1)[1], f.type) for f in Semgrep().run(ctx).findings}


@semgrep
def test_fields_of_a_fetched_answer_written_into_html_are_a_hotspot(tmp_path):
    """weblate GHSA-6wxc (search results, through a helper, into a template string appended), OctoPrint GHSA-x7mf (a
    .done() response field into $("<p>" + ...)), pyLoad GHSA-wcm6 ($.getJSON links, through $.each, into .append).
    Not: a field named for markup, a count, an escaped field, or a whole answer, which is the server's own HTML."""
    found = semgrep_findings(tmp_path, {"static/app.js": (
        "function showResults(results, $preview) {\n"
        "  for (const result of results) {\n"
        "    $preview.append(`<a href=\"/x\"><small>${result.context}</small></a>`);\n"
        "  }\n"
        "}\n\n"
        "function search(q, $preview) {\n"
        "  fetch('/api/units/').then((r) => r.json()).then((data) => {\n"
        "    showResults(data.results, $preview);\n"
        "    document.getElementById('n').innerHTML = data.count;\n"
        "    document.getElementById('h').innerHTML = data.html;\n"
        "  });\n"
        "}\n\n"
        "OctoPrint.util.testUrl(url).done(function (response) {\n"
        "  var content = response.response.content;\n"
        "  showMessageDialog({message: $('<p>Snapshot</p><img src=\"data:image/png;base64,' + content + '\" />')});\n"
        "});\n\n"
        "$.getJSON('/api/links', function (data) {\n"
        "  $.each(data.links, function (key, link) {\n"
        "    $('#children').append(\"<a href='\" + link.url + \"'>\" + link.name + '</a>');\n"
        "    $('#safe').append('<span>' + _.escape(link.name) + '</span>');\n"
        "  });\n"
        "});\n\n"
        "$.ajax({url: '/console', success: function (body) { $('pre.logs').html(body); }});\n"
        "fetch('/frag').then((r) => r.text()).then((html) => { document.getElementById('f').innerHTML = html; });\n")})
    hits = {(line, rule) for _, line, rule, _ in found if rule == "fetched-data-into-html"}
    assert hits == {(9, "fetched-data-into-html"), (17, "fetched-data-into-html"), (22, "fetched-data-into-html")}
    assert all(kind == "security_hotspot" for _, _, rule, kind in found if rule == "fetched-data-into-html")


@semgrep
def test_jquery_builds_html_from_a_tag_string_or_an_html_option(tmp_path):
    """jQuery parses $("<p>" + text) and $('<div>', {html: message}) as markup (OctoPrint GHSA-x7mf, Indico
    GHSA-fmqq); the URL's hash reaching either is XSS. Not a selector, a fixed tag, or the text: option."""
    found = semgrep_vulnerabilities(tmp_path, {"static/ui.js": (
        "const name = location.hash.slice(1);\n"
        "$('#out').before($('<p>' + name + '</p>'));\n"
        "$('#out').before($('<div>', {width: 400, html: 'Remove ' + name + '?'}));\n"
        "$('#out').before($('<div>', {text: 'Remove ' + name + '?'}));\n"
        "$('#' + name).hide();\n"
        "$('<p>Fixed</p>').appendTo('#out');\n")})
    assert found == {("static/ui.js", 2, "xss"), ("static/ui.js", 3, "xss")}
