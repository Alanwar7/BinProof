"""Plain-text rendering of a ValidationReport."""

from __future__ import annotations

from typing import List

from .models import ClaimStatus as C, EvidenceStatus as S, ValidationReport

_MARK = {S.CONFIRMED: "[ok]", S.PARTIAL: "[~~]", S.NOT_FOUND: "[XX]", S.MISMATCH: "[XX]", S.UNCHECKABLE: "[??]"}


def render_report(r: ValidationReport) -> str:
    out: List[str] = ["Validation of %s  %s" % (r.function.address, r.function.name), "=" * 72]
    out.append("Analysis by %s / %s at %s" % (r.analysis_info.provider, r.analysis_info.model,
                                              r.analysis_info.created_at))
    for note in r.integrity.notes:
        out.append("  ! " + note)
    s = r.summary
    out.append("\nSUMMARY: %d claims | %s" % (s.total_claims, " | ".join(
        "%s %d" % (k, v) for k, v in s.claims_by_status.items() if v)))
    out.append("Evidence: %d items | %s" % (s.total_evidence, " | ".join(
        "%s %d" % (k, v) for k, v in s.evidence_by_status.items() if v)))
    if s.overconfident_claims:
        out.append("Overconfident claims (claimed high confidence, not verified): %d" % s.overconfident_claims)
    if s.overall_confidence_note:
        out.append("Note: " + s.overall_confidence_note)

    for c in r.claims:
        flag = "  (claimed high confidence)" if c.overconfident else ""
        out.append("\n[%s] %s%s" % (c.status.value, c.id, flag))
        out.append("  " + c.statement)
        for e in c.evidence:
            where = " @ %s" % e.address if e.address else ""
            out.append("    %s %s%s  %r" % (_MARK[e.status], e.kind.value, where, e.quote[:70]))
            if e.status is not S.CONFIRMED:
                out.append("         -> %s" % e.reason)
        if not c.evidence:
            out.append("    (no evidence provided)")
        for f in c.findings:
            if f.severity.value != "info":
                out.append("    ! %s: %s" % (f.severity.value, f.message))
        for m in c.missing_information:
            out.append("    missing: " + m)
    out.append("\nSTATUS KEY: VERIFIED = evidence real and grounded (not proof of correctness) | "
               "PARTIALLY_VERIFIED = some evidence weak or invalid | UNVERIFIED = cannot be checked or "
               "no evidence | INVALID_EVIDENCE = cited evidence does not exist or does not match | "
               "CONTRADICTED = extracted data refutes the claim")
    out.append("\nLimitations:")
    out += ["  - " + l for l in r.limitations]
    return "\n".join(out)
