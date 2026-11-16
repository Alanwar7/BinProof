from pathlib import Path

from pydantic import ValidationError

from ..ai.models import FunctionAnalysisRecord
from ..ai.parsing import summarize_validation_error
from .errors import ValidationInputError


def load_record(path) -> FunctionAnalysisRecord:
    """Read a saved `analyze --output` result. Raises ValidationInputError with a clear message."""
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValidationInputError("cannot read %s: %s" % (p, exc.strerror or exc)) from None
    except UnicodeDecodeError:
        raise ValidationInputError("%s is not valid UTF-8 text" % p) from None
    try:
        return FunctionAnalysisRecord.model_validate_json(raw)
    except ValidationError as exc:
        raise ValidationInputError("%s is not a valid BinProof analysis result: %s"
                                   % (p, summarize_validation_error(exc))) from None
