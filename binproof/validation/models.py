"""Schema of the validation report (Pydantic, JSON-exportable).

Three layers are reported separately so nothing is hidden by averaging:
  evidence_status  layer 1: do the cited items exist and match the extracted data?
  findings         layer 2: heuristic claim-level grounding/relationship checks
  semantic         layer 3: deeper judgement (not run unless a SemanticVerifier is plugged in)
`status` is the worst of the three. VERIFIED never means "the interpretation is proven".
"""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from ..ai.models import Confidence, EvidenceKind, FunctionIdentity

REPORT_SCHEMA_VERSION = "1"


class EvidenceStatus(str, Enum):
    CONFIRMED = "confirmed"        # exists and the quote matches
    PARTIAL = "partial"            # exists, but the quote/relationship could only be matched loosely
    NOT_FOUND = "not_found"        # cited address/item does not exist (in this function)
    MISMATCH = "mismatch"          # item exists but contradicts what was cited
    UNCHECKABLE = "uncheckable"    # cannot be checked with the available data


class ClaimStatus(str, Enum):
    VERIFIED = "VERIFIED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    INVALID_EVIDENCE = "INVALID_EVIDENCE"
    CONTRADICTED = "CONTRADICTED"  # extracted data actively refutes the claim


_SEVERITY = {ClaimStatus.VERIFIED: 0, ClaimStatus.PARTIALLY_VERIFIED: 1, ClaimStatus.UNVERIFIED: 2,
             ClaimStatus.INVALID_EVIDENCE: 3, ClaimStatus.CONTRADICTED: 4}


def severity(status: ClaimStatus) -> int:
    return _SEVERITY[status]


def worst(*statuses: ClaimStatus) -> ClaimStatus:
    return max(statuses, key=severity)


class FindingSeverity(str, Enum):
    INFO = "info"
    WEAK = "weak"                  # claim is not clearly supported
    CONTRADICTION = "contradiction"


class SemanticStatus(str, Enum):
    NOT_ASSESSED = "not_assessed"
    SUPPORTED = "supported"
    WEAK = "weak"
    UNSUPPORTED = "unsupported"


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore")


class EvidenceCheck(_Model):
    kind: EvidenceKind
    address: Optional[str] = None
    quote: str
    note: Optional[str] = None            # the model's own comment; never verified
    status: EvidenceStatus
    code: str                             # machine-readable reason, e.g. quote_mismatch
    reason: str                           # human-readable explanation
    actual: Optional[str] = None          # what the extracted data really says, when relevant
    missing_information: Optional[str] = None
    # coordinates for evidence that carries no address of its own (decompiled code):
    location: Optional[str] = None                 # e.g. "decompiled code line 9"
    occurrences: Optional[int] = None              # how many times the quote appears in the code
    corroborating_addresses: List[str] = Field(default_factory=list)  # assembly that matches the fragment


class SupportFinding(_Model):
    code: str
    severity: FindingSeverity
    message: str
    heuristic: bool = True


class SemanticAssessment(_Model):
    status: SemanticStatus = SemanticStatus.NOT_ASSESSED
    method: str = "none"
    rationale: Optional[str] = "semantic verification was not run"


class ClaimResult(_Model):
    id: str                                # purpose, behavior[1], inputs[0], ...
    section: str
    statement: str
    claimed_confidence: Confidence
    original_claim: Dict[str, Any]         # the claim exactly as the model produced it
    evidence: List[EvidenceCheck]
    evidence_status: ClaimStatus           # layer 1 result
    findings: List[SupportFinding] = Field(default_factory=list)   # layer 2
    semantic: SemanticAssessment = Field(default_factory=SemanticAssessment)  # layer 3
    status: ClaimStatus                    # worst of the layers
    reasons: List[str] = Field(default_factory=list)
    missing_information: List[str] = Field(default_factory=list)
    overconfident: bool = False            # claimed "high" but not VERIFIED


class AnalysisInfo(_Model):
    provider: str
    model: str
    created_at: str
    prompt_version: str


class Integrity(_Model):
    ok: bool = True                             # False if the result cannot belong to this export
    binary_matches: Optional[bool] = None       # result's program sha256 equals the export's
    context_reproduced: Optional[bool] = None   # model input can be rebuilt byte-for-byte
    notes: List[str] = Field(default_factory=list)


class ValidationSummary(_Model):
    total_claims: int
    claims_by_status: Dict[str, int]
    total_evidence: int
    evidence_by_status: Dict[str, int]
    overconfident_claims: int
    overall_confidence_claimed: Confidence
    overall_confidence_note: Optional[str] = None


class ValidationReport(_Model):
    schema_version: str = REPORT_SCHEMA_VERSION
    validated_at: str
    function: FunctionIdentity
    analysis_info: AnalysisInfo
    integrity: Integrity
    summary: ValidationSummary
    claims: List[ClaimResult]
    limitations: List[str]
