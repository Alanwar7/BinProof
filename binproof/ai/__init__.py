"""AI-assisted analysis for BinProof (requires `pip install "binproof[ai]"`).

Names are imported lazily, so `from binproof.ai.models import ...` (used by the
validation package) does not load any provider code.
"""

import importlib

_EXPORTS = {
    "FunctionAnalyzer": ".analyzer",
    "AIConfig": ".config",
    "ContextLimits": ".context",
    "FunctionContext": ".context",
    "build_function_context": ".context",
    "FunctionAnalysis": ".models",
    "FunctionAnalysisRecord": ".models",
    "create_provider": ".providers",
    "register_provider": ".providers",
}
__all__ = sorted(_EXPORTS)


def __getattr__(name):
    if name in _EXPORTS:
        return getattr(importlib.import_module(_EXPORTS[name], __name__), name)
    raise AttributeError("module %r has no attribute %r" % (__name__, name))
