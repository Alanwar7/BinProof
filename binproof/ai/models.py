"""Pydantic schema for AI output.

Two layers, kept apart on purpose:

  FunctionAnalysis        what the MODEL claims (validated, untrusted until verified)
  FunctionAnalysisRecord  the saved envelope: identity and provenance come from
                          our own tooling, never from the model

Every finding must carry at least one Evidence item. Evidence is an address
plus an exact quote, so a later milestone can check it mechanically against
the Analysis. A claim the model cannot support belongs in `uncertainties`.
"""

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..addresses import normalize_address

SCHEMA_VERSION = "1"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class EvidenceKind(str, Enum):
    INSTRUCTION = "instruction"
    DECOMPILED = "decompiled_code"
    STRING = "string"
    CALL = "call"
    IMPORT = "import"
    XREF = "xref"
    PARAMETER = "parameter"
    METADATA = "metadata"


_ADDRESS_REQUIRED = {EvidenceKind.INSTRUCTION, EvidenceKind.CALL, EvidenceKind.STRING, EvidenceKind.XREF}


def _lower(value):
    return value.strip().lower() if isinstance(value, str) else value


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)


class Evidence(_Model):
    kind: EvidenceKind
    address: Optional[str] = None   # one canonical address, e.g. 0x00401110
    quote: str = Field(min_length=1)  # exact instruction/code/string/name as it appeared in the data
    note: Optional[str] = None

    @field_validator("kind", mode="before")
    @classmethod
    def _kind_lower(cls, v):
        return _lower(v)

    @field_validator("address", mode="before")
    @classmethod
    def _address(cls, v):
        if v is None or (isinstance(v, str) and not v.strip()):
            return None
        if not isinstance(v, str):
            raise ValueError("address must be a string such as 0x00401110")
        try:
            return normalize_address(v)
        except ValueError:
            raise ValueError("address must be a single hex address such as 0x00401110") from None

    @model_validator(mode="after")
    def _address_when_needed(self):
        if self.kind in _ADDRESS_REQUIRED and self.address is None:
            raise ValueError("evidence of kind %r needs an address" % self.kind.value)
        return self


class _Claimed(_Model):
    evidence: List[Evidence] = Field(min_length=1)
    confidence: Confidence

    @field_validator("confidence", mode="before")
    @classmethod
    def _conf_lower(cls, v):
        return _lower(v)


class Finding(_Claimed):
    statement: str = Field(min_length=1)


class DataItem(_Claimed):
    """An input or output of the function (parameter, return value, global, buffer...)."""
    name: str = Field(min_length=1)
    type: Optional[str] = None
    description: str = Field(min_length=1)


class Uncertainty(_Model):
    description: str = Field(min_length=1)
    missing_information: Optional[str] = None


class FunctionAnalysis(_Model):
    purpose: Finding
    behavior: List[Finding] = Field(min_length=1)
    inputs: List[DataItem] = Field(default_factory=list)
    outputs: List[DataItem] = Field(default_factory=list)
    side_effects: List[Finding] = Field(default_factory=list)
    confidence: Confidence
    confidence_rationale: str = Field(min_length=1)
    uncertainties: List[Uncertainty] = Field(default_factory=list)

    @field_validator("confidence", mode="before")
    @classmethod
    def _conf_lower(cls, v):
        return _lower(v)


# ---- saved record (facts come from our tooling) -----------------------------------

class FunctionIdentity(_Model):
    address: str
    name: str
    signature: Optional[str] = None


class Provenance(_Model):
    provider: str
    model: str
    created_at: str
    prompt_version: str
    context_sha256: str
    attempts: int = 1
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    program_name: Optional[str] = None
    program_sha256: Optional[str] = None


class FunctionAnalysisRecord(_Model):
    schema_version: str = SCHEMA_VERSION
    function: FunctionIdentity
    analysis: FunctionAnalysis
    context_notes: List[str] = Field(default_factory=list)  # what was missing/truncated in the input
    provenance: Provenance
