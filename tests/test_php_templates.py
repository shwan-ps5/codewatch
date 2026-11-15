"""PHP templates (core/analyzers/php_template_sinks.py; PLAN.md step 73): request data passed to a variable a Twig,
Blade, Smarty or plain PHP view prints unescaped, and PHP views Semgrep doesn't parse by their extension."""
import pytest

from core.analyzers.multi_tools import Semgrep, php_copy_text
from core.analyzers.php_template_sinks import kind, names, php_raw, printed_variables
from tests.test_detection import semgrep_vulnerabilities

semgrep = pytest.mark.skipif(not Semgrep().available(), reason="semgrep not installed")

TWIG = {
    "templates/admin/msg.html.twig": "<div>{{ message|raw }}</div><p>{{ title }}</p>"
                                     "{% for n in notes %}{{ n|raw }}{% endfor %}<b>{{ safe|e|raw }}</b>",
    "src/Controller/A.php": """<?php
class A {
  function raw($request) { return $this->render('admin/msg.html.twig', ['message' => $request->query->get('m')]); }
  function loop($request) { return $this->render('admin/msg.html.twig', ['notes' => [$request->query->get('n')]]); }
  function escaped($request) { return $this->render('admin/msg.html.twig', ['title' => $request->query->get('t')]); }
  function encoded($request) {
    return $this->render('admin/msg.html.twig', ['message' => htmlspecialchars($request->query->get('m'))]); }
  function other($request) { return $this->render('other.html.twig', ['message' => $request->query->get('m')]); }
  function filtered($request) { return $this->render('admin/msg.html.twig', ['safe' => $request->query->get('s')]); }
}
""",
}

# OpenCart: Twig made with autoescape off prints every value raw, and the controller fills $data before the view.
OPENCART = {
    "system/library/template/twig.php": "<?php\nclass Twig { function render() { $c = ['autoescape' => false]; } }\n",
    "admin/view/template/common/login.twig": '<input type="hidden" name="redirect" value="{{ redirect }}"/>',
    "admin/controller/common/login.php": """<?php
class ControllerCommonLogin extends Controller {
  public function index() {
    if (isset($this->request->get['route'])) {
      $data['redirect'] = $this->url->link($this->request->get['route'], '');
    } else {
      $data['redirect'] = '';
    }
    $this->response->setOutput($this->load->view('common/login', $data));
  }
  public function cast() {
    $data['redirect'] = (int) $this->request->get['id'];
    $this->response->setOutput($this->load->view('common/login', $data));
  }
}
""",
}

BLADE = {
    "resources/views/users/show.blade.php": "<h1>{!! $name !!}</h1><p>{{ $bio }}</p><i>{!! e($other) !!}</i>",
    "app/Http/Controllers/UserController.php": """<?php
class UserController {
  function compacted($request) { $name = $request->input('n'); return view('users.show', compact('name')); }
  function escaped($request) { return view('users.show', ['bio' => $request->input('b')]); }
  function helper($request) { return view('users.show')->with('other', $request->input('o')); }
}
""",
}

SMARTY = {
    "templates/login.tpl": '<input value="{$username}"><input value="{$email|escape}">',
    "login.php": "<?php\n$tpl->assign('username', $_REQUEST['user']);\n$tpl->assign('email', $_REQUEST['email']);\n",
}

# CakePHP: a controller's set() reaches its action's view; a component's reaches any view; an element prints what
# a view passes it.
CAKE = {
    "app/View/Keys/display.ctp": '<a href="<?= $referer ?>">back</a><p><?= h($name) ?></p>',
    "app/View/Keys/index.ctp": "<p><?= h($referer) ?></p>",
    "app/View/AuthKeys/done.ctp": '<a href="<?= $back ?>">back</a>',
    "app/View/Elements/genericForm.ctp": "<?php echo sprintf('<h3>%s</h3>%s', h($data['title']), $data['description']); ?>",
    "app/View/Tags/add.ctp": "<?php echo $this->element('genericForm', ['data' => ['title' => 'x', "
                             "'description' => $this->request->data['T']['name']]]); ?>",
    "app/View/Tags/edit.ctp": "<?php echo $this->element('genericForm', ['data' => ['title' => 'x', "
                              "'description' => h($this->request->data['T']['name'])]]); ?>",
    "app/Controller/KeysController.php": """<?php
class KeysController extends AppController {
  public function display() { $this->set('referer', $this->request->query['r']); $this->set('name', $this->request->query['n']); }
  public function index() { $this->set('referer', $this->request->query['r']); }
}
""",
    "app/Controller/Component/CRUDComponent.php": """<?php
class CRUDComponent extends Component {
  public function done() { $this->Controller->set('back', $this->Controller->referer()); }
  public function leave() { $this->Controller->redirect($this->Controller->referer()); }
}
""",
}


@semgrep
def test_request_data_into_twig_raw_variables(tmp_path):
    found = semgrep_vulnerabilities(tmp_path, TWIG)
    assert found == {("src/Controller/A.php", 3, "xss"), ("src/Controller/A.php", 4, "xss")}


@semgrep
def test_opencart_twig_without_autoescape_and_a_filled_data_array(tmp_path):
    assert semgrep_vulnerabilities(tmp_path, OPENCART) == {("admin/controller/common/login.php", 5, "xss")}


@semgrep
def test_request_data_into_blade_unescaped_output(tmp_path):
    assert semgrep_vulnerabilities(tmp_path, BLADE) == {("app/Http/Controllers/UserController.php", 3, "xss")}


@semgrep
def test_request_data_into_smarty_variables_without_escape(tmp_path):
    assert semgrep_vulnerabilities(tmp_path, SMARTY) == {("login.php", 2, "xss")}


@semgrep
def test_cakephp_set_reaches_its_actions_view_and_elements(tmp_path):
    # KeysController::index sets the same variable, but its view escapes it; the component's referer is a source
    # for XSS and not for its redirect.
    assert semgrep_vulnerabilities(tmp_path, CAKE) == {
        ("app/Controller/KeysController.php", 3, "xss"), ("app/Controller/Component/CRUDComponent.php", 3, "xss"),
        ("app/View/Tags/add.ctp", 1, "xss")}


@semgrep
def test_php_views_with_other_extensions_are_scanned(tmp_path):
    files = {"app/View/X/a.ctp": '<div><?php echo $this->request->data["T"]["name"]; ?></div>',
             "app/View/X/b.phtml": '<a href="<?php echo $this->request->here ?>">x</a>',
             "app/View/X/c.ctp": '<p><?= $this->request->params["controller"] ?></p><p><?= $this->data["T"] ?></p>',
             "lib/x.inc": "int x = 1; /* not PHP */\n"}
    assert semgrep_vulnerabilities(tmp_path, files) == {("app/View/X/a.ctp", 1, "xss"), ("app/View/X/b.phtml", 1, "xss")}


def test_printed_variables_of_a_php_view():
    assert printed_variables("sprintf('%s %s', h($t), $d['x'])") == {"d"}
    assert printed_variables("empty($d) ? '' : $d") == {"d"}
    assert printed_variables("(int)$n . json_encode($j) . $this->Html->link($t)") == set()
    assert printed_variables('"<p>$q</p>"') == {"q"}
    assert printed_variables("__('Tag %s', $tag)") == {"tag"}
    # A variable the view assigns itself is its own, not the controller's.
    assert php_raw("<?php $a = json_encode(h($a)); ?><?= $a ?><?= $b ?>") == {"b"}
    assert php_raw("<?php foreach ($items as $k => $it): ?><?= $it ?><?php endforeach ?>") == {"items"}


def test_template_kinds_and_names():
    assert kind("app/views/x.blade.php", "") == "blade"
    assert kind("tpl/a.tpl", "{$x}") == "smarty"
    assert kind("catalog/view/a.tpl", "<?php echo $x; ?>") == "php"
    assert kind("src/Service/Mailer.php", "<?php class Mailer {}") is None
    assert "users.show" in names("resources/views/users/show.blade.php", "blade")
    assert "common/login" in names("admin/view/template/common/login.twig", "twig")


def test_compact_written_out_for_semgrep():
    assert php_copy_text("<?php return view('x', compact('user', \"posts\"));") == (
        "<?php return view('x', ['user' => $user, 'posts' => $posts]);")
    assert php_copy_text("<?php compact($names);") is None
