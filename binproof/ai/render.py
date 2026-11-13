"""Readable terminal rendering of a FunctionAnalysisRecord (plain text)."""

from __future__ import annotations

from typing import List

from .models import Evidence, FunctionAnalysisRecord


def _evidence(items: List[Evidence], indent: str) -> List[str]:
    lines = []
    for e in items:
        where = " @ %s" % e.address if e.address else ""
        note = "  (%s)" % e.note if e.note else ""
        lines.append("%s[%s%s] %s%s" % (indent, e.kind.value, where, e.quote, note))
    return lines


def render_text(record: FunctionAnalysisRecord) -> str:
    a, f, p = record.analysis, record.function, record.provenance
    out: List[str] = []
    out.append("Function %s  %s" % (f.address, f.signature or f.name))
    out.append("=" * 72)
    out.append("\nPURPOSE  (confidence: %s)" % a.purpose.confidence.value)
    out.append("  " + a.purpose.statement)
    out += _evidence(a.purpose.evidence, "    ")

    out.append("\nBEHAVIOR")
    for i, b in enumerate(a.behavior, 1):
        out.append("  %d. %s  (%s)" % (i, b.statement, b.confidence.value))
        out += _evidence(b.evidence, "       ")

    for title, items in (("INPUTS", a.inputs), ("OUTPUTS", a.outputs)):
        out.append("\n" + title)
        if not items:
            out.append("  (none identified)")
        for d in items:
            out.append("  - %s%s: %s  (%s)" % (d.name, " : " + d.type if d.type else "", d.description,
                                                d.confidence.value))
            out += _evidence(d.evidence, "      ")

    out.append("\nSIDE EFFECTS")
    if not a.side_effects:
        out.append("  (none identified)")
    for s in a.side_effects:
        out.append("  - %s  (%s)" % (s.statement, s.confidence.value))
        out += _evidence(s.evidence, "      ")

    out.append("\nOVERALL CONFIDENCE: %s" % a.confidence.value)
    out.append("  " + a.confidence_rationale)

    out.append("\nUNCERTAINTIES")
    if not a.uncertainties:
        out.append("  (none stated)")
    for u in a.uncertainties:
        out.append("  - %s" % u.description + (" [missing: %s]" % u.missing_information
                                                if u.missing_information else ""))

    if record.context_notes:
        out.append("\nLIMITS OF THE INPUT DATA")
        out += ["  - " + n for n in record.context_notes]

    tokens = ""
    if p.input_tokens is not None or p.output_tokens is not None:
        tokens = ", tokens in/out: %s/%s" % (p.input_tokens, p.output_tokens)
    out.append("\n[%s / %s, %d attempt(s)%s]" % (p.provider, p.model, p.attempts, tokens))
    out.append("Note: evidence has not been verified against the binary yet.")
    return "\n".join(out)
