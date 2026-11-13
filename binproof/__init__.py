"""BinProof: AI-assisted, evidence-checked reverse engineering on top of Ghidra.

Milestone 2: load, validate and query the JSON exported by
ghidra_scripts/ExportBinaryJSON.py.

    from binproof import Analysis
    a = Analysis.open("output/target.exe-95d4e0ba3b1c")
    a.get_callers("0x401100")
"""

from .addresses import normalize_address
from .analysis import Analysis
from .errors import *  # noqa: F401,F403  (exception hierarchy is public API)
from .models import *  # noqa: F401,F403  (data models are public API)

__version__ = "0.3.0"
