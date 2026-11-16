"""Link each AI claim to its supporting evidence."""

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from ..ai.models import Evidence, FunctionAnalysis


@dataclass(frozen=True)
class ClaimRef:
    id: str
    section: str
    statement: str
    confidence: Any                   # Confidence
    evidence: Tuple[Evidence, ...]
    original: Dict[str, Any]


def extract_claims(analysis: FunctionAnalysis) -> List[ClaimRef]:
    """purpose, behavior[i], inputs[i], outputs[i], side_effects[i], in report order."""
    claims: List[ClaimRef] = []

    def add(claim_id, section, statement, item):
        claims.append(ClaimRef(claim_id, section, statement, item.confidence,
                               tuple(item.evidence or ()), item.model_dump(mode="json")))

    add("purpose", "purpose", analysis.purpose.statement, analysis.purpose)
    for i, item in enumerate(analysis.behavior):
        add("behavior[%d]" % i, "behavior", item.statement, item)
    for section in ("inputs", "outputs"):
        for i, item in enumerate(getattr(analysis, section)):
            label = "%s (%s): %s" % (item.name, item.type, item.description) if item.type \
                else "%s: %s" % (item.name, item.description)
            add("%s[%d]" % (section, i), section, label, item)
    for i, item in enumerate(analysis.side_effects):
        add("side_effects[%d]" % i, "side_effects", item.statement, item)
    return claims
