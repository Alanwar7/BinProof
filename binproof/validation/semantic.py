"""LAYER 3: semantic verification (extension point; not run by default).

Deterministic checks can show that evidence is real. They cannot show that the
evidence MEANS what the claim says. A SemanticVerifier answers that, for example by
asking a second model to judge claim vs evidence, or by symbolic analysis. It is
given the claim, the layer-1 results and the ground-truth facts, and returns a
SemanticAssessment. Any verifier plugs into RecordValidator(semantic_verifier=...);
nothing else changes, and a verifier that fails is reported, never fatal.
"""

from __future__ import annotations

from typing import Protocol, Sequence

from .claims import ClaimRef
from .facts import FunctionFacts
from .models import ClaimStatus, EvidenceCheck, SemanticAssessment, SemanticStatus


class SemanticVerifier(Protocol):
    name: str

    def assess(self, claim: ClaimRef, checks: Sequence[EvidenceCheck],
               facts: FunctionFacts) -> SemanticAssessment: ...


def semantic_floor(assessment: SemanticAssessment) -> ClaimStatus:
    """The least-bad claim status a semantic verdict allows."""
    if assessment.status is SemanticStatus.WEAK:
        return ClaimStatus.PARTIALLY_VERIFIED
    if assessment.status is SemanticStatus.UNSUPPORTED:
        return ClaimStatus.UNVERIFIED
    return ClaimStatus.VERIFIED
