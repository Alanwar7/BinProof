"""LAYER 2: heuristic claim-level checks (still no model involved).

Layer 1 asks "is the cited evidence real?". This layer asks "are the specifics of
the claim grounded in anything?":
  * constants / addresses in the claim text must appear in the cited evidence or the function
  * "calls X" / "called by X" must match the real callee / caller sets
  * known functions or imports mentioned in passing should be related to this function
These are text heuristics, so findings are marked heuristic. Contradictions are only
raised when the call data is complete enough to trust a negative.
"""

from __future__ import annotations

import re
from typing import List, Sequence, Set

from .claims import ClaimRef
from .facts import FunctionFacts
from .models import EvidenceCheck, FindingSeverity as Sev, SupportFinding
from .text import extract_numbers, number_in, number_keys

_NAME = r"[`'\"]?([A-Za-z_][\w@.$:]*)"
_CALL_RE = re.compile(r"\b(?:calls?|invokes?|invoked|invoking|calling|call\s+to|makes\s+a\s+call\s+to)\s+"
                      r"(?:the\s+|a\s+)?(?:(?:thunked|library|external|imported)\s+)*(?:function\s+)?" + _NAME, re.I)
_CALLED_BY_RE = re.compile(r"\b(?:called|invoked|referenced)\s+by\s+(?:the\s+)?(?:function\s+)?" + _NAME, re.I)
_BACKTICK = re.compile(r"`([A-Za-z_][\w@.$:]*)(?:\(\))?`")
_PAREN = re.compile(r"\b([A-Za-z_][\w@.$:]*)\(\)")
_WORD = re.compile(r"[A-Za-z_][\w@.$:]*")
_BIT_WIDTH = re.compile(r"\b\d+[- ]?bits?\b", re.I)


def _clean(name: str) -> str:
    return name.strip("`'\"").rstrip(".:,;")


class SupportChecker:
    def __init__(self, facts: FunctionFacts):
        self.f = facts

    def check(self, claim: ClaimRef, checks: Sequence[EvidenceCheck]) -> List[SupportFinding]:
        evidence_text = " ".join(" ".join(filter(None, (c.quote, c.note, c.actual))) for c in checks)
        return self._constants(claim, evidence_text) + self._relationships(claim, evidence_text)

    # ---- constants and addresses ------------------------------------------------------

    def _constants(self, claim: ClaimRef, evidence_text: str) -> List[SupportFinding]:
        findings: List[SupportFinding] = []
        evidence_keys: Set[int] = set()
        for v in extract_numbers(evidence_text):
            evidence_keys |= number_keys(v)
        code_keys = self.f.code_number_keys()
        text = _BIT_WIDTH.sub(" ", claim.statement)   # "64-bit" describes a size, not a constant
        for v in dict.fromkeys(extract_numbers(text)):
            if number_in(v, frozenset(evidence_keys)):
                continue
            if number_in(v, code_keys):
                findings.append(SupportFinding(
                    code="constant_not_cited", severity=Sev.INFO,
                    message="the claim mentions %s, which appears in the function's code but not in the cited "
                            "evidence" % hex(v) if v > 9 else
                            "the claim mentions %d, which appears in the function's code but not in the cited "
                            "evidence" % v))
            elif v >= 0x1000 and self.f.is_known_address("0x%08x" % v):
                findings.append(SupportFinding(
                    code="address_not_cited", severity=Sev.INFO,
                    message="the claim mentions address %s, which exists in the binary but is not cited" % hex(v)))
            else:
                findings.append(SupportFinding(
                    code="value_not_in_data", severity=Sev.WEAK,
                    message="the claim mentions %s, which appears neither in the cited evidence nor anywhere in "
                            "this function's code or the binary's addresses" % (hex(v) if v > 9 else v)))
        return findings

    # ---- function relationships ----------------------------------------------------------

    def _relationships(self, claim: ClaimRef, evidence_text: str) -> List[SupportFinding]:
        f, stmt = self.f, claim.statement
        known = f.known_names()
        own = f.summary.name
        explicit_calls = {n for n in (_clean(m.group(1)) for m in _CALL_RE.finditer(stmt)) if n in known and n != own}
        called_by = {n for n in (_clean(m.group(1)) for m in _CALLED_BY_RE.finditer(stmt)) if n in known and n != own}
        imports = f.import_names()
        mentioned = {_clean(m.group(1)) for rx in (_BACKTICK, _PAREN) for m in rx.finditer(stmt)}
        mentioned |= {_clean(w) for w in _WORD.findall(stmt) if _clean(w) in imports}
        mentioned = (mentioned & known) - explicit_calls - called_by - {own}

        callees, callers = f.callee_names(), f.caller_names()
        callee_gap = f.data_may_be_incomplete
        caller_gap = ("the extraction was truncated, so caller data may be incomplete" if f.analysis.is_truncated
                      else ("caller data is unavailable" if f.callers is None else None))
        out: List[SupportFinding] = []

        for n in sorted(explicit_calls):
            if n in callees:
                continue
            if callee_gap:
                out.append(SupportFinding(
                    code="claimed_callee_unverifiable", severity=Sev.WEAK,
                    message="the claim says this function calls %s, which is a known name, but no such call was "
                            "found and this cannot be ruled out because %s" % (n, callee_gap)))
            else:
                out.append(SupportFinding(
                    code="claimed_callee_not_called", severity=Sev.CONTRADICTION,
                    message="the claim says this function calls %s, but %s is not among its extracted callees"
                            % (n, n)))
        for n in sorted(called_by):
            if n in callers:
                continue
            if caller_gap:
                out.append(SupportFinding(
                    code="claimed_caller_unverifiable", severity=Sev.WEAK,
                    message="the claim says this function is called by %s; not found, and %s" % (n, caller_gap)))
            else:
                out.append(SupportFinding(
                    code="claimed_caller_not_found", severity=Sev.CONTRADICTION,
                    message="the claim says this function is called by %s, but %s is not among its callers or "
                            "referencing functions" % (n, n)))
        for n in sorted(mentioned):
            if n in callees or n in callers or re.search(r"\b%s\b" % re.escape(n), evidence_text):
                continue
            out.append(SupportFinding(
                code="function_mentioned_without_relationship", severity=Sev.WEAK,
                message="the claim mentions %s, which exists in the binary but is neither a caller nor a callee of "
                        "this function and is not cited in the evidence" % n))
        return out
