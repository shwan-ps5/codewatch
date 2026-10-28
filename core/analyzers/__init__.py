from .coverage import Coverage
from .dependencies import PipAudit
from .multi_tools import Cppcheck, Jscpd, Lizard, Semgrep
from .python_tools import Bandit, Radon, Ruff

ANALYZERS = [Ruff(), Bandit(), Radon(), Lizard(), Semgrep(), Cppcheck(), Jscpd(), PipAudit(), Coverage()]
