from .accessibility import Axe, HtmlA11y, JsxA11y
from .codewatch_checks import CodewatchChecks
from .coverage import Coverage
from .dependencies import PipAudit
from .extra import Checkov, CognitiveComplexity, EslintQuality, Secrets, Stylelint, TypeCheck
from .multi_tools import Cppcheck, Jscpd, Lizard, Semgrep
from .python_tools import Bandit, Radon, Ruff

ANALYZERS = [
    Ruff(), Bandit(), Radon(), CognitiveComplexity(), TypeCheck(), Lizard(), EslintQuality(), Stylelint(), Semgrep(),
    Cppcheck(), Jscpd(), CodewatchChecks(), Secrets(), Checkov(), PipAudit(), HtmlA11y(), JsxA11y(), Axe(), Coverage(),
]
