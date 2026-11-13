"""Model text -> validated FunctionAnalysis."""

import json
import re
from typing import Any

from pydantic import ValidationError

from .errors import MalformedAIResponseError
from .models import FunctionAnalysis

_FENCE = re.compile(r"```(?:json|JSON)?\s*(.*?)```", re.DOTALL)


def extract_json_object(text: str) -> Any:
    """Return the first JSON object in `text` (tolerates code fences and surrounding prose)."""
    candidates = [text]
    fenced = _FENCE.search(text)
    if fenced:
        candidates.insert(0, fenced.group(1))
    decoder = json.JSONDecoder()
    for candidate in candidates:
        start = candidate.find("{")
        while start != -1:
            try:
                obj, _ = decoder.raw_decode(candidate[start:])
            except ValueError:
                start = candidate.find("{", start + 1)
                continue
            if isinstance(obj, dict):
                return obj
            start = candidate.find("{", start + 1)
    raise ValueError("no JSON object found")


def summarize_validation_error(exc: ValidationError, limit: int = 8) -> str:
    lines = []
    for err in exc.errors()[:limit]:
        loc = ".".join(str(p) for p in err["loc"]) or "(root)"
        lines.append("%s: %s" % (loc, err["msg"]))
    extra = len(exc.errors()) - limit
    if extra > 0:
        lines.append("... and %d more problems" % extra)
    return "; ".join(lines)


def parse_function_analysis(text: str, *, truncated: bool = False) -> FunctionAnalysis:
    """Parse and validate. Raises MalformedAIResponseError (with the raw text attached)."""
    try:
        obj = extract_json_object(text)
    except ValueError:
        if truncated:
            raise MalformedAIResponseError(
                "the response was cut off by the output token limit before the JSON was complete; "
                "raise --max-tokens / BINPROOF_MAX_TOKENS", text, truncated=True) from None
        raise MalformedAIResponseError("the response did not contain a JSON object", text) from None
    try:
        return FunctionAnalysis.model_validate(obj)
    except ValidationError as exc:
        raise MalformedAIResponseError(
            "the JSON did not match the required schema: " + summarize_validation_error(exc),
            text, truncated=truncated) from None
