"""RecordValidator: runs the three layers and builds the report. No LLM, no provider."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Callable, List, Optional, Sequence, Tuple

from ..ai.models import Confidence, FunctionAnalysisRecord
from ..analysis import Analysis
from ..errors import BinProofError
from .claims import ClaimRef, extract_claims
from .evidence import EvidenceChecker
from .facts import FunctionFacts
from .models import (
    AnalysisInfo, ClaimResult, ClaimStatus as C, EvidenceCheck, EvidenceStatus as S,
    FindingSeverity, Integrity, SemanticAssessment, SemanticStatus, ValidationReport,
    ValidationSummary, severity, worst,
)
from .semantic import SemanticVerifier, semantic_floor
from .support import SupportChecker

LIMITATIONS = [
    "Deterministic checks show that cited evidence exists in the extracted data and that quotes match it. "
    "They do not prove that the interpretation of that evidence is correct.",
    "VERIFIED means: every cited item exists, matches the data, and passed basic grounding checks. "
    "It is not a guarantee that the claim is true.",
    "Claim-level checks (layer 2) are text heuristics and can miss problems or, rarely, flag harmless wording.",
    "The extracted data covers direct calls only; indirect calls Ghidra could not resolve are unknown, so "
    "callee and caller claims are only contradicted when the call data is complete.",
    "Notes written by the model next to evidence are never verified.",
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def aggregate_evidence(checks: Sequence[EvidenceCheck]) -> Tuple[C, List[str], List[str]]:
    """Layer-1 claim status from its evidence checks: (status, reasons, missing information)."""
    if not checks:
        return C.UNVERIFIED, ["no supporting evidence was provided"], ["supporting evidence for this claim"]
    reasons, missing = [], []
    for i, c in enumerate(checks):
        if c.status is not S.CONFIRMED:
            where = " @ %s" % c.address if c.address else ""
            reasons.append("evidence[%d] (%s%s) is %s: %s" % (i, c.kind.value, where, c.status.value, c.reason))
        if c.missing_information:
            missing.append(c.missing_information)
    bad = [c for c in checks if c.status in (S.NOT_FOUND, S.MISMATCH)]
    confirmed = sum(c.status is S.CONFIRMED for c in checks)
    partial = sum(c.status is S.PARTIAL for c in checks)
    if len(bad) == len(checks):
        status = C.INVALID_EVIDENCE
    elif bad:
        status = C.PARTIALLY_VERIFIED
        reasons.insert(0, "%d of %d evidence items are invalid" % (len(bad), len(checks)))
    elif confirmed == len(checks):
        status = C.VERIFIED
    elif confirmed or partial:
        status = C.PARTIALLY_VERIFIED
    else:
        status = C.UNVERIFIED
        reasons.insert(0, "none of the evidence could be checked with the available data")
    return status, reasons, missing


class RecordValidator:
    def __init__(self, analysis: Analysis, *, semantic_verifier: Optional[SemanticVerifier] = None,
                 clock: Callable[[], str] = _utc_now):
        self._analysis = analysis
        self._semantic = semantic_verifier
        self._clock = clock

    def validate(self, record: FunctionAnalysisRecord) -> ValidationReport:
        """Raises FunctionNotFoundError if the export lacks the function, ValidationInputError if its data
        cannot be loaded. Everything else is reported inside the returned report."""
        facts = FunctionFacts.load(self._analysis, record.function.address)
        integrity = self._integrity(record, facts)
        checker, support = EvidenceChecker(facts), SupportChecker(facts)
        results = [self._claim(c, checker, support, facts) for c in extract_claims(record.analysis)]
        return ValidationReport(
            validated_at=self._clock(), function=record.function,
            analysis_info=AnalysisInfo(provider=record.provenance.provider, model=record.provenance.model,
                                       created_at=record.provenance.created_at,
                                       prompt_version=record.provenance.prompt_version),
            integrity=integrity, summary=self._summary(record, results), claims=results,
            limitations=list(LIMITATIONS) + (
                [] if self._semantic else ["Semantic verification (layer 3) was not run."]))

    # ---- one claim -----------------------------------------------------------------------------

    def _claim(self, claim: ClaimRef, checker: EvidenceChecker, support: SupportChecker,
               facts: FunctionFacts) -> ClaimResult:
        checks = [checker.check(ev) for ev in claim.evidence]
        evidence_status, reasons, missing = aggregate_evidence(checks)
        findings = support.check(claim, checks)
        support_status = C.VERIFIED
        for fnd in findings:
            if fnd.severity is FindingSeverity.CONTRADICTION:
                support_status = worst(support_status, C.CONTRADICTED)
                reasons.append("contradicted by extracted data: " + fnd.message)
            elif fnd.severity is FindingSeverity.WEAK:
                support_status = worst(support_status, C.PARTIALLY_VERIFIED)
                reasons.append("not clearly supported: " + fnd.message)
        semantic = self._run_semantic(claim, checks, facts)
        if semantic.status in (SemanticStatus.WEAK, SemanticStatus.UNSUPPORTED):
            reasons.append("semantic verifier (%s): %s" % (semantic.method, semantic.rationale or semantic.status.value))
        status = worst(evidence_status, support_status, semantic_floor(semantic))
        return ClaimResult(
            id=claim.id, section=claim.section, statement=claim.statement, claimed_confidence=claim.confidence,
            original_claim=claim.original, evidence=checks, evidence_status=evidence_status, findings=findings,
            semantic=semantic, status=status, reasons=reasons, missing_information=list(dict.fromkeys(missing)),
            overconfident=(claim.confidence == Confidence.HIGH and severity(status) >= severity(C.UNVERIFIED)))

    def _run_semantic(self, claim, checks, facts) -> SemanticAssessment:
        if self._semantic is None:
            return SemanticAssessment()
        try:
            return self._semantic.assess(claim, checks, facts)
        except Exception as exc:  # a broken verifier must never take down validation
            return SemanticAssessment(status=SemanticStatus.NOT_ASSESSED,
                                      method=getattr(self._semantic, "name", "custom"),
                                      rationale="semantic verifier failed: %s" % type(exc).__name__)

    # ---- integrity ---------------------------------------------------------------------------------

    def _integrity(self, record: FunctionAnalysisRecord, facts: FunctionFacts) -> Integrity:
        notes: List[str] = []
        matches: Optional[bool] = None
        try:
            export_sha = self._analysis.metadata.sha256
        except BinProofError:
            export_sha = None
        result_sha = record.provenance.program_sha256
        if result_sha and export_sha:
            matches = result_sha.lower() == export_sha.lower()
            if not matches:
                notes.append("ERROR: this result was produced from a different binary (sha256 differs from the "
                             "export); every check below is against the wrong data")
        else:
            notes.append("binary identity could not be confirmed (a sha256 is missing from the result or export)")
        if record.function.name != facts.summary.name:
            notes.append("function name differs: the result says %r, the export says %r"
                         % (record.function.name, facts.summary.name))
        reproduced: Optional[bool] = None
        try:
            from ..ai.context import ContextLimits, build_function_context
            reproduced = (build_function_context(self._analysis, facts.address, ContextLimits()).sha256()
                          == record.provenance.context_sha256)
        except Exception:
            reproduced = None
        if reproduced is False:
            notes.append("the exact input the model saw cannot be reproduced (the export changed, or non-default "
                         "context limits were used); evidence is checked against the current export")
        return Integrity(binary_matches=matches, context_reproduced=reproduced, notes=notes)

    # ---- summary ---------------------------------------------------------------------------------------

    def _summary(self, record: FunctionAnalysisRecord, results: List[ClaimResult]) -> ValidationSummary:
        by_status = Counter(r.status.value for r in results)
        by_evidence = Counter(e.status.value for r in results for e in r.evidence)
        overall = record.analysis.confidence
        not_verified = sum(r.status is not C.VERIFIED for r in results)
        note = None
        if overall == Confidence.HIGH and not_verified:
            note = ("overall confidence 'high' is not supported: %d of %d claims are not fully verified"
                    % (not_verified, len(results)))
        return ValidationSummary(
            total_claims=len(results), claims_by_status={s.value: by_status.get(s.value, 0) for s in C},
            total_evidence=sum(by_evidence.values()),
            evidence_by_status={s.value: by_evidence.get(s.value, 0) for s in S},
            overconfident_claims=sum(r.overconfident for r in results),
            overall_confidence_claimed=overall, overall_confidence_note=note)
