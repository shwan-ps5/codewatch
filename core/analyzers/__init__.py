import warnings

from .accessibility import Axe, HtmlA11y, JsxA11y
from .codewatch_checks import CodewatchChecks
from .coverage import Coverage
from .dependencies import OsvLockfiles, PipAudit
from .extra import Checkov, CognitiveComplexity, EslintQuality, Secrets, Stylelint, TypeCheck
from .multi_tools import Cppcheck, Jscpd, Lizard, Semgrep
from .python_tools import Bandit, Radon, Ruff

# ast.parse() of scanned code reports that code's invalid escapes ("\\d") as SyntaxWarnings from "<unknown>";
# they're the scanned project's business, not codewatch's.
warnings.filterwarnings("ignore", category=SyntaxWarning, module="<unknown>")

ANALYZERS = [
    Ruff(), Bandit(), Radon(), CognitiveComplexity(), TypeCheck(), Lizard(), EslintQuality(), Stylelint(), Semgrep(),
    Cppcheck(), Jscpd(), CodewatchChecks(), Secrets(), Checkov(), PipAudit(), OsvLockfiles(), HtmlA11y(), JsxA11y(),
    Axe(), Coverage(),
]
