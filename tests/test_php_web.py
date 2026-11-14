"""codewatch's PHP taint rules (catalog/codewatch/rules/php-web.yml; PLAN.md step 70): request data reaching a
dangerous call in the same function, and the escaped, cast or checked look-alikes that must stay quiet."""
import pytest

from core.analyzers.multi_tools import Semgrep
from tests.test_detection import semgrep_vulnerabilities

pytestmark = pytest.mark.skipif(not Semgrep().available(), reason="semgrep not installed")

VULNERABLE = """<?php
function xss1() { echo "<p>" . $_GET['q'] . "</p>"; }
function xss2() { $n = $_POST['name']; ?><b><?= $n ?></b><?php }
function xss3($request) { echo $request->input('ref'); }
function xss4() { printf("<a href='%s'>", $_SERVER['REQUEST_URI']); }
function xss5() { echo $this->request->getQuery('tab'); }
function sql1($db) { $id = $_GET['id']; $db->query("SELECT * FROM t WHERE id = $id"); }
function sql2($conn) { mysqli_query($conn, "DELETE FROM t WHERE n='" . $_POST['n'] . "'"); }
function sql3() { global $wpdb; $wpdb->get_results("SELECT * FROM x WHERE a = '{$_GET['a']}'"); }
function sql4($request) { DB::select("select * from u where e = '" . $request->input('e') . "'"); }
function path1() { include $_GET['page'] . '.php'; }
function path2() { readfile('/data/' . $_GET['f']); }
function path3() { unlink(UPLOAD_DIR . $_POST['file']); }
function cmd1() { system("ping -c 1 " . $_GET['host']); }
function cmd2() { $o = shell_exec('ls ' . $_REQUEST['d']); }
function code1() { eval('$x = ' . $_POST['expr'] . ';'); }
function ssrf1() { $c = curl_init($_GET['url']); }
function redir1() { header('Location: ' . $_GET['next']); }
function redir2() { wp_redirect($_REQUEST['redirect_to']); }
function redir3() { header("Location: {$_GET['r']}"); }
function deser1() { $o = unserialize($_COOKIE['prefs']); }
function code2() { $f = $_GET['fn']; $f(); }
function redir4($request) { $t = $request->query->get('t'); if (!isLocalUrl($t)) { log_it($t); } return $this->redirect($t); }
function redir5($request) { $t = $request->query->get('t'); if (isLocalUrl($t) || true) { } return $this->redirect($t); }
function xss6() { echo $db->escape($_GET['q']) . htmlspecialchars('x'); }
"""

SAFE = """<?php
function xss1() { echo "<p>" . htmlspecialchars($_GET['q'], ENT_QUOTES) . "</p>"; }
function xss2() { $n = (int) $_POST['n']; echo "<b>$n</b>"; }
function xss3() { echo esc_html($_GET['x']); }
function xss4() { echo intval($_GET['page']); }
function xss5() { echo json_encode(['q' => $_GET['q']]); }
function xss6() { echo isset($_GET['a']) ? 'yes' : 'no'; }
function xss7() { echo $_GET['mode'] === 'full' ? 'Full' : 'Short'; }
function xss8($request) { echo $request->user()->name; }
function sql1($pdo) { $s = $pdo->prepare('SELECT * FROM t WHERE id = ?'); $s->execute([$_GET['id']]); }
function sql2() { global $wpdb; $wpdb->get_results($wpdb->prepare("SELECT * FROM x WHERE a = %s", $_GET['a'])); }
function sql3($db) { $db->query("SELECT * FROM t WHERE id = " . intval($_GET['id'])); }
function sql4($conn) { mysqli_query($conn, "SELECT * FROM t WHERE n='" . mysqli_real_escape_string($conn, $_GET['n']) . "'"); }
function sql5($q) { $q->where(['id' => $_GET['id']])->all(); }
function path1() { readfile('/data/' . basename($_GET['f'])); }
function path2() { include __DIR__ . '/views/' . ($_GET['v'] === 'a' ? 'a' : 'b') . '.php'; }
function cmd1() { system('ping -c 1 ' . escapeshellarg($_GET['host'])); }
function code1($request) { $tab = $request->input('tab'); return view('settings', ['tab' => $tab]); }
function redir1() { wp_safe_redirect($_GET['to']); }
function redir2() { header('Content-Type: text/plain'); header('X-Id: ' . intval($_GET['id'])); }
function deser1() { $o = unserialize($_COOKIE['p'], ['allowed_classes' => false]); }
function deser2() { $o = json_decode($_COOKIE['p'], true); }
function xss9() { echo 'users.php?offset=' . ($_GET['offset'] - 6); }
function xss10() { echo date('Y/m/d', explode('-', $_GET['db'])[0]); }
function xss11() { echo filter_input(INPUT_GET, 'f', FILTER_SANITIZE_FULL_SPECIAL_CHARS); }
function xss12($request) { echo Strings::htmlentities($request->query->get('action')); }
function xss13() { echo escape_input($_SERVER['REQUEST_URI']); }
function xss14() { echo $this->BcForm->create(null, ['url' => $_GET['u']]); }
function redir3($request) { $t = $request->query->get('t'); if ($t && $this->isLocalUrl($request, $t)) { return $this->redirect($t); } }
function redir4($request) { $t = $request->query->get('t'); if (!is_safe_url($t)) { exit; } header('Location: ' . $t); }
"""


def test_request_data_reaching_php_sinks(tmp_path):
    found = semgrep_vulnerabilities(tmp_path, {"app/vuln.php": VULNERABLE})
    expected = {2: "xss", 3: "xss", 4: "xss", 5: "xss", 6: "xss", 7: "sql-injection", 8: "sql-injection",
                9: "sql-injection", 10: "sql-injection", 11: "path-traversal", 12: "path-traversal",
                13: "path-traversal", 14: "command-injection", 15: "command-injection", 16: "code-injection",
                17: "ssrf", 18: "open-redirect", 19: "open-redirect", 20: "open-redirect",
                21: "unsafe-deserialization", 22: "code-injection",
                # A failed check that doesn't end the request, or one in an always-true condition, clears nothing;
                # a database escaper isn't an HTML one.
                23: "open-redirect", 24: "open-redirect", 25: "xss"}
    assert found == {("app/vuln.php", line, rule) for line, rule in expected.items()}


def test_escaped_cast_or_bound_request_data_is_quiet_in_php(tmp_path):
    assert semgrep_vulnerabilities(tmp_path, {"app/safe.php": SAFE}) == set()
