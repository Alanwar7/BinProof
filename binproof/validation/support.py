"""LAYER 2: heuristic claim-level checks (still no model involved).

Layer 1 asks "is the cited evidence real?". This layer asks "does the claim stand on it?":
  * grounding   constants, quoted text and function names in the claim must be backed by
                VERIFIED evidence or by the function's own data. The model's own notes and
                quotes from invalid evidence never count.
  * relevance   a claim whose specifics appear in none of its verified evidence is not supported
                by that evidence, and prologue/epilogue boilerplate supports no behavior claim
  * relations   "calls X", "does not call X", "called by X" are checked against the real callee
                and caller sets; unknown identifier-like callees are flagged
These are text heuristics (see docs/VALIDATION.md for what they cannot see), so findings are
marked heuristic. Contradictions are only raised when the call data is complete enough to trust.
"""

from __future__ import annotations

import re
from typing import List, Sequence, Set, Tuple

from ..ai.models import EvidenceKind
from .claims import ClaimRef
from .facts import FunctionFacts
from .models import EvidenceCheck, EvidenceStatus as S, FindingSeverity as Sev, SupportFinding
from .text import (
    compact, extract_numbers, identifier_like, is_boilerplate_instruction, number_in, number_keys,
)

_NAME = r"[`'\"]?([A-Za-z_][\w@.$:]*)"
_CALL_VERBS = (r"(?:calls?|invokes?|invoked|invoking|calling|call\s+to|makes\s+a\s+call\s+to|"
               r"delegat(?:es|ed|ing)\s+(?:[\w-]+\s+){0,8}?to|forwards?\s+(?:[\w-]+\s+){0,6}?to|"
               r"dispatch(?:es|ed|ing)?\s+to|hands?\s+off\s+to)")
_CALL_RE = re.compile(r"\b" + _CALL_VERBS + r"\s+(?:the\s+|a\s+)?(?:(?:thunked|library|external|imported)\s+)*"
                      r"(?:function\s+)?" + _NAME, re.I)
_CALLED_BY_RE = re.compile(r"\b(?:(?:called|invoked|referenced)\s+(?:by|from)|its\s+callers?\s+(?:is|are|include))\s+"
                           r"(?:the\s+)?(?:function\s+)?" + _NAME, re.I)
_NEGATION = re.compile(r"\b(?:not|never|no|without|neither|nor|cannot)\b|n't\b", re.I)
_BACKTICK = re.compile(r"`([A-Za-z_][\w@.$:]*)(?:\(\))?`")
_PAREN = re.compile(r"\b([A-Za-z_][\w@.$:]*)\(\)")
_WORD = re.compile(r"[A-Za-z_][\w@.$:]*")
_BIT_WIDTH = re.compile(r"\b\d+[- ]?bits?\b", re.I)
_LITERAL = re.compile(r'"([^"\n]{3,80})"')


def _clean(name: str) -> str:
    return name.strip("`'\"").rstrip(".:,;")


def _negated(statement: str, start: int) -> bool:
    return bool(_NEGATION.search(statement[max(0, start - 24):start]))


class SupportChecker:
    def __init__(self, facts: FunctionFacts):
        self.f = facts

    def check(self, claim: ClaimRef, checks: Sequence[EvidenceCheck]) -> List[SupportFinding]:
        verified = [c for c in checks if c.status in (S.CONFIRMED, S.PARTIAL)]
        pool = self._pool(verified)
        pool_keys: Set[int] = set()
        for v in extract_numbers(pool):
            pool_keys |= number_keys(v)

        findings = self._duplicates(claim) + self._boilerplate(verified)
        const_findings, numbers = self._constants(claim, pool_keys)
        rel_findings, names = self._relationships(claim, pool)
        findings += const_findings + rel_findings + self._literals(claim, pool)
        if verified:
            findings += self._relevance(numbers, names, pool, pool_keys)
        return findings

    # ---- what counts as grounding --------------------------------------------------

    def _pool(self, verified: Sequence[EvidenceCheck]) -> str:
        """Text of VERIFIED evidence only: the real data when we have it, never the model's notes."""
        parts: List[str] = []
        for c in verified:
            parts.append(c.actual or c.quote)
            if c.kind is EvidenceKind.CALL and c.address:
                site = next((s for s in self.f.detail.call_sites if s.site == c.address), None)
                if site:
                    parts += [n for n in (site.target_name, site.thunk_target) if n]
        return " ".join(parts)

    # ---- duplicates and boilerplate ----------------------------------------------------

    def _duplicates(self, claim: ClaimRef) -> List[SupportFinding]:
        seen, dups = set(), 0
        for ev in claim.evidence:
            key = (ev.kind, ev.address, compact(ev.quote))
            dups += key in seen
            seen.add(key)
        if not dups:
            return []
        return [SupportFinding(code="duplicate_evidence", severity=Sev.INFO,
                               message="%d evidence item(s) repeat another one and were counted once" % dups)]

    def _boilerplate(self, verified: Sequence[EvidenceCheck]) -> List[SupportFinding]:
        flags = [c.kind is EvidenceKind.INSTRUCTION and is_boilerplate_instruction(c.actual or c.quote)
                 for c in verified]
        if flags and all(flags):
            return [SupportFinding(
                code="evidence_is_boilerplate", severity=Sev.WEAK,
                message="the only verified evidence is prologue/epilogue-style instructions (push/pop rbp, ret, "
                        "leave, ...), which say nothing about what the function does")]
        if any(flags):
            return [SupportFinding(code="some_evidence_is_boilerplate", severity=Sev.INFO,
                                   message="some cited instructions are prologue/epilogue boilerplate")]
        return []

    # ---- constants -----------------------------------------------------------------------

    def _constants(self, claim: ClaimRef, pool_keys: Set[int]) -> Tuple[List[SupportFinding], List[int]]:
        findings: List[SupportFinding] = []
        code_keys = self.f.code_number_keys()
        text = _BIT_WIDTH.sub(" ", claim.statement)   # "64-bit" describes a size, not a constant
        numbers = list(dict.fromkeys(extract_numbers(text)))
        for v in numbers:
            shown = hex(v) if v > 9 else str(v)
            if number_in(v, frozenset(pool_keys)):
                continue
            if number_in(v, code_keys):
                findings.append(SupportFinding(
                    code="constant_not_cited", severity=Sev.INFO,
                    message="the claim mentions %s, which appears in the function's code but not in the verified "
                            "evidence" % shown))
            elif v >= 0x1000 and self.f.is_known_address("0x%08x" % v):
                findings.append(SupportFinding(
                    code="address_not_cited", severity=Sev.INFO,
                    message="the claim mentions address %s, which exists in the binary but is not cited" % shown))
            else:
                findings.append(SupportFinding(
                    code="value_not_in_data", severity=Sev.WEAK,
                    message="the claim mentions %s, which appears neither in the verified evidence nor anywhere in "
                            "this function's code or the binary's addresses" % shown))
        return findings, numbers

    # ---- quoted text -----------------------------------------------------------------------

    def _literals(self, claim: ClaimRef, pool: str) -> List[SupportFinding]:
        if self.f.strings_used is None:
            return []
        known = [s.value for s in self.f.strings_used]
        out = []
        for lit in dict.fromkeys(m.group(1) for m in _LITERAL.finditer(claim.statement)):
            if lit in pool or any(lit in v for v in known) or lit in (self.f.code_text or ""):
                continue
            out.append(SupportFinding(
                code="quoted_text_not_in_function", severity=Sev.WEAK,
                message="the claim quotes %r, which is not a string this function references and not in its "
                        "decompiled code" % lit))
        return out

    # ---- relevance ---------------------------------------------------------------------------

    def _relevance(self, numbers: List[int], names: Set[str], pool: str, pool_keys: Set[int]) -> List[SupportFinding]:
        if not numbers and not names:
            return []
        keys = frozenset(pool_keys)
        cited = [v for v in numbers if number_in(v, keys)] + \
                [n for n in names if re.search(r"\b%s\b" % re.escape(n), pool)]
        if cited:
            return []
        listing = ", ".join([hex(v) if v > 9 else str(v) for v in numbers] + sorted(names))
        return [SupportFinding(
            code="evidence_does_not_cover_claim_specifics", severity=Sev.WEAK,
            message="none of the claim's specifics (%s) appear in its verified evidence, so the evidence does not "
                    "show what the claim says" % listing)]

    # ---- function relationships ------------------------------------------------------------------

    def _relationships(self, claim: ClaimRef, pool: str) -> Tuple[List[SupportFinding], Set[str]]:
        f, stmt = self.f, claim.statement
        known, own, imports = f.known_names(), f.summary.name, f.import_names()
        callees, callers = f.callee_names(), f.caller_names()
        callee_gap = f.data_may_be_incomplete
        caller_gap = ("the extraction was truncated, so caller data may be incomplete" if f.analysis.is_truncated
                      else ("caller data is unavailable" if f.callers is None else None))
        out: List[SupportFinding] = []
        anchors: Set[str] = set()
        explicit: Set[str] = set()

        for m in _CALL_RE.finditer(stmt):
            n = _clean(m.group(1))
            if n == own:
                continue
            negated = _negated(stmt, m.start())
            marked = "`" in stmt[m.start():m.end()] or stmt[m.end():m.end() + 1] == "("
            if n in known:
                explicit.add(n)
                if negated:
                    anchors.add(n)
                    if n in callees:
                        out.append(SupportFinding(
                            code="claimed_absence_but_called", severity=Sev.CONTRADICTION,
                            message="the claim says this function does not call %s, but it does" % n))
                    continue
                anchors.add(n)
                if n in callees:
                    continue
                if callee_gap:
                    out.append(SupportFinding(
                        code="claimed_callee_unverifiable", severity=Sev.WEAK,
                        message="the claim says this function calls %s, a known name, but no such call was found "
                                "and this cannot be ruled out because %s" % (n, callee_gap)))
                else:
                    out.append(SupportFinding(
                        code="claimed_callee_not_called", severity=Sev.CONTRADICTION,
                        message="the claim says this function calls %s, but %s is not among its extracted callees"
                                % (n, n)))
            elif not negated and (marked or identifier_like(n)):
                out.append(SupportFinding(
                    code="claimed_callee_unknown",
                    severity=Sev.WEAK if callee_gap else Sev.CONTRADICTION,
                    message="the claim says this function calls %s, but no function or import named %s exists in "
                            "the extracted binary data%s" % (n, n, "; " + callee_gap if callee_gap else "")))

        called_by: Set[str] = set()
        for m in _CALLED_BY_RE.finditer(stmt):
            n = _clean(m.group(1))
            if n not in known or n == own:
                continue
            called_by.add(n)
            anchors.add(n)
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

        mentioned = {_clean(m.group(1)) for rx in (_BACKTICK, _PAREN) for m in rx.finditer(stmt)}
        mentioned |= {_clean(w) for w in _WORD.findall(stmt)
                      if _clean(w) in imports or identifier_like(_clean(w))}
        mentioned = (mentioned & known) - explicit - called_by - {own}
        anchors |= mentioned
        for n in sorted(mentioned):
            if n in callees or n in callers or re.search(r"\b%s\b" % re.escape(n), pool):
                continue
            out.append(SupportFinding(
                code="function_mentioned_without_relationship", severity=Sev.WEAK,
                message="the claim mentions %s, which exists in the binary but is neither a caller nor a callee of "
                        "this function and is not cited in the verified evidence" % n))
        return out, anchors
