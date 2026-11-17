"""LAYER 1: deterministic per-evidence checks against the extracted data.

Each evidence item (address + exact quote) is checked for:
  * existence      does the cited address / string / import / reference exist?
  * scope          does it belong to the analyzed function?
  * quote match    does the quote really say what the binary data says?
  * strength       is the quote specific enough to mean anything?
It never judges whether the *interpretation* of the evidence is right.

Decompiled code has no addresses, so those checks report a location (line numbers), how
many times the quote occurs, and which assembly instructions/call sites match the
fragment's constants and callees (corroborating_addresses).
"""

from __future__ import annotations

import json
import re
from typing import List, Optional, Tuple

from ..ai.models import Evidence
from ..errors import BinProofError, LookupFailedError
from .facts import FunctionFacts
from .models import EvidenceCheck, EvidenceStatus as S
from .text import (
    compact, compact_with_map, extract_numbers, find_all, line_of, number_keys, split_elisions,
    strip_leading_address,
)

_MIN_FRAGMENT = 5          # compacted characters: instruction/call fragments
_MIN_STRING_FRAGMENT = 4   # characters: string fragments
_MIN_CODE_FRAGMENT = 6     # compacted characters: decompiled fragments
_GENERIC_CODE = re.compile(r"^(?:[a-z_]\w*|0x[0-9a-f]+|\d+)$")   # a bare identifier or number
_NOT_CALLS = {"if", "while", "for", "switch", "return", "sizeof", "else", "do"}
_C_WORDS = {"char", "int", "void", "const", "unsigned", "signed", "long", "short", "struct", "undefined",
            "undefined1", "undefined2", "undefined4", "undefined8", "uint", "ulong", "byte", "bool",
            "size_t", "param", "parameter", "pointer", "ptr", "to", "the", "a", "of", "first", "second"}


def _clip(text: Optional[str], n: int = 120) -> Optional[str]:
    return None if text is None else (text if len(text) <= n else text[:n] + "...")


class EvidenceChecker:
    def __init__(self, facts: FunctionFacts):
        self.f = facts

    def check(self, ev: Evidence) -> EvidenceCheck:
        handler = getattr(self, "_check_" + ev.kind.value)
        try:
            return handler(ev)
        except BinProofError as exc:
            return self._make(ev, S.UNCHECKABLE, "data_unavailable",
                              "the data needed to check this evidence could not be loaded",
                              missing="%s (%s)" % (ev.kind.value, type(exc).__name__))

    # ---- helpers ------------------------------------------------------------------

    def _make(self, ev: Evidence, status: S, code: str, reason: str, actual: Optional[str] = None,
              missing: Optional[str] = None, **extra) -> EvidenceCheck:
        return EvidenceCheck(kind=ev.kind, address=ev.address, quote=ev.quote, note=ev.note, status=status,
                             code=code, reason=reason, actual=_clip(actual), missing_information=missing, **extra)

    def _address_not_found(self, ev: Evidence) -> EvidenceCheck:
        owner = self.f.function_containing(ev.address)
        if owner is not None and owner.address == self.f.address:
            return self._make(ev, S.NOT_FOUND, "address_not_an_instruction_start",
                              "address %s is inside the analyzed function but is not the start of an instruction"
                              % ev.address)
        if owner is not None:
            return self._make(ev, S.NOT_FOUND, "address_in_other_function",
                              "address %s belongs to function %s (%s), not to the analyzed function %s"
                              % (ev.address, owner.name, owner.address, self.f.summary.name))
        return self._make(ev, S.NOT_FOUND, "address_not_in_data",
                          "no function in the extracted data contains address %s" % ev.address)

    def _soft_address(self, ev: Evidence, result: EvidenceCheck) -> EvidenceCheck:
        """For kinds where an address is optional: if one is given it must be inside the function."""
        if (not ev.address or result.status is not S.CONFIRMED or ev.address == self.f.address
                or self.f.detail.instruction_at(ev.address) is not None):
            return result
        return result.model_copy(update={
            "status": S.PARTIAL, "code": "address_not_in_function",
            "reason": result.reason + "; however the cited address %s is not part of this function" % ev.address})

    def _compare_instruction_text(self, ev: Evidence, actual: str, what: str = "instruction") -> EvidenceCheck:
        q = strip_leading_address(ev.quote, ev.address)
        cq, ca = compact(q), compact(actual)
        if cq == ca:
            return self._make(ev, S.CONFIRMED, "quote_matches", "quote matches the %s at this address" % what,
                              actual=actual)
        if len(cq) < _MIN_FRAGMENT:
            return self._make(ev, S.PARTIAL, "quote_too_short",
                              "quote %r is too short to prove anything about this %s" % (_clip(q, 40), what),
                              actual=actual)
        if cq in ca:
            return self._make(ev, S.CONFIRMED, "quote_is_fragment",
                              "quote is a fragment of the %s at this address" % what, actual=actual)
        return self._make(ev, S.MISMATCH, "quote_mismatch",
                          "the %s at %s is %r, which does not match the quote %r"
                          % (what, ev.address, actual, _clip(q, 80)), actual=actual)

    # ---- instruction ------------------------------------------------------------------

    def _check_instruction(self, ev: Evidence) -> EvidenceCheck:
        ins = self.f.detail.instruction_at(ev.address)
        if ins is None:
            return self._address_not_found(ev)
        return self._compare_instruction_text(ev, ins.text)

    # ---- call (a call site inside the analyzed function) ----------------------------------

    def _check_call(self, ev: Evidence) -> EvidenceCheck:
        ins = self.f.detail.instruction_at(ev.address)
        if ins is None:
            return self._address_not_found(ev)
        site = next((s for s in self.f.detail.call_sites if s.site == ev.address), None)
        if site is None and not compact(ins.text).startswith("call"):
            return self._make(ev, S.MISMATCH, "not_a_call",
                              "the instruction at %s is %r, which is not a call" % (ev.address, ins.text),
                              actual=ins.text)
        q = strip_leading_address(ev.quote, ev.address)
        cq = compact(q)
        names = [n for n in ((site.target_name, site.thunk_target, site.target) if site else ()) if n]
        text_ok = len(cq) >= _MIN_FRAGMENT and cq in compact(ins.text)
        name_ok = any(n.lower() in q.lower() for n in names)
        if site is None:
            if text_ok:
                return self._make(ev, S.CONFIRMED, "indirect_call",
                                  "a call instruction exists here; Ghidra did not resolve its target",
                                  actual=ins.text)
        elif text_ok or name_ok:
            target = site.thunk_target or site.target_name or site.target
            return self._make(ev, S.CONFIRMED, "call_site_confirmed",
                              "call site confirmed; it calls %s" % target, actual=ins.text)
        if len(cq) < _MIN_FRAGMENT and cq in compact(ins.text):
            return self._make(ev, S.PARTIAL, "quote_too_short",
                              "a call exists at %s, but the quote %r is too short to say which one"
                              % (ev.address, _clip(q, 40)), actual=ins.text)
        known = ", ".join(names) if names else "an unresolved target"
        return self._make(ev, S.MISMATCH, "call_quote_mismatch",
                          "the call at %s is %r (target: %s), which does not match the quote %r"
                          % (ev.address, ins.text, known, _clip(q, 80)), actual=ins.text)

    # ---- string -------------------------------------------------------------------------------

    def _check_string(self, ev: Evidence) -> EvidenceCheck:
        entry = None
        try:
            entry = self.f.analysis.get_string_at(ev.address)
        except LookupFailedError:
            for s in self.f.strings_used or []:
                if any(r.from_address == ev.address for r in s.referenced_from):
                    entry = s   # address given was the referencing instruction, not the string itself
                    break
        if entry is None:
            hint = " (the address is an instruction inside this function, not a string)" \
                if self.f.detail.instruction_at(ev.address) else ""
            return self._make(ev, S.NOT_FOUND, "string_not_found",
                              "no string exists at %s%s" % (ev.address, hint))
        q = ev.quote.strip()
        if len(q) >= 2 and q[0] == q[-1] and q[0] in "\"'":
            q = q[1:-1]
        escaped = json.dumps(entry.value)[1:-1]
        exact = q == entry.value or q == escaped
        fragment = len(q) >= _MIN_STRING_FRAGMENT and (q in entry.value or q in escaped)
        if not (exact or fragment):
            if q and (q in entry.value or q in escaped):
                return self._make(ev, S.PARTIAL, "quote_too_short",
                                  "quote %r occurs in the string at %s but is too short to prove anything"
                                  % (_clip(q, 40), entry.address), actual=entry.value)
            return self._make(ev, S.MISMATCH, "string_value_mismatch",
                              "the string at %s is %r, which does not match the quote %r"
                              % (entry.address, _clip(entry.value, 80), _clip(q, 80)), actual=entry.value)
        if self.f.strings_used is None:
            return self._make(ev, S.PARTIAL, "string_usage_unchecked",
                              "string exists and matches, but whether this function uses it cannot be checked",
                              actual=entry.value, missing=self.f.missing("strings"))
        if not any(s.address == entry.address for s in self.f.strings_used):
            if entry.references_truncated:
                return self._make(ev, S.PARTIAL, "reference_list_truncated",
                                  "string exists and matches; the extractor kept only part of its reference "
                                  "list, so use by this function cannot be confirmed", actual=entry.value)
            return self._make(ev, S.MISMATCH, "string_not_referenced_by_function",
                              "the string exists at %s but nothing in this function references it" % entry.address,
                              actual=entry.value)
        return self._make(ev, S.CONFIRMED, "string_confirmed",
                          "string exists, matches the quote and is referenced by this function",
                          actual=entry.value)

    # ---- import --------------------------------------------------------------------------------

    def _check_import(self, ev: Evidence) -> EvidenceCheck:
        q = ev.quote.strip().strip("`'\"").rstrip("()").strip()
        lib: Optional[str] = None
        name = q
        if "!" in q:
            lib, name = q.split("!", 1)
        elif "::" in q:
            lib, name = q.rsplit("::", 1)
        imports = self.f.analysis.get_imports()
        matches = [i for i in imports if i.name == name] or [i for i in imports if i.name.lower() == name.lower()]
        if not matches:
            internal = any(f.name == name for f in self.f.analysis.iter_functions())
            return self._make(ev, S.NOT_FOUND, "not_an_import" if internal else "import_not_found",
                              ("%r is an internal function, not an import" if internal
                               else "no import named %r exists in the extracted data") % name)
        if lib:
            by_lib = [i for i in matches if i.library.lower() == lib.lower()]
            if not by_lib:
                return self._make(ev, S.MISMATCH, "import_library_mismatch",
                                  "%r is imported from %s, not %s"
                                  % (name, ", ".join(sorted({i.library for i in matches})), lib))
            matches = by_lib
        if self.f.imports_used is None:
            return self._make(ev, S.PARTIAL, "import_usage_unchecked",
                              "import exists, but whether this function uses it cannot be checked",
                              missing=self.f.missing("imports"))
        used = [i for i in matches if any(u.name == i.name and u.library == i.library
                                          for u in self.f.imports_used)]
        if not used:
            return self._make(ev, S.MISMATCH, "import_not_used_by_function",
                              "%r is imported by the binary but this function neither calls nor references it" % name)
        if ev.address:
            sites = {r.from_address for i in used for r in i.call_sites + i.other_references
                     if r.from_function and r.from_function.address == self.f.address}
            sites |= {t for i in used for t in i.thunks}
            sites |= {i.address for i in used if i.address}
            if ev.address not in sites:
                return self._make(ev, S.PARTIAL, "address_not_a_use_site",
                                  "import exists and is used by this function, but %s is not one of its use sites"
                                  % ev.address)
        return self._make(ev, S.CONFIRMED, "import_confirmed", "import exists and is used by this function")

    # ---- xref (a reference TO the analyzed function) -------------------------------------------

    def _check_xref(self, ev: Evidence) -> EvidenceCheck:
        if self.f.xrefs is None:
            return self._make(ev, S.UNCHECKABLE, "xrefs_unavailable", "cross-reference data is unavailable",
                              missing=self.f.missing("xrefs"))
        matches = [r for r in self.f.xrefs if r.from_address == ev.address]
        if not matches:
            inside = self.f.detail.instruction_at(ev.address) is not None
            return self._make(ev, S.NOT_FOUND, "no_reference_at_address",
                              ("%s is inside the analyzed function; it is not a reference to it" if inside
                               else "no reference to this function originates at %s") % ev.address)
        q = compact(ev.quote)
        call_to_me = re.search(r"\b(?:call|jmp|jump)\b.*\b%s\b" % re.escape(self.f.summary.name), ev.quote, re.I)
        for r in matches:
            tokens = [r.type, r.from_function.name if r.from_function else None, r.from_address]
            if call_to_me or any(t and compact(t) in q for t in tokens):
                who = r.from_function.name if r.from_function else "outside any known function"
                return self._make(ev, S.CONFIRMED, "xref_confirmed",
                                  "%s reference to this function exists at %s (from %s)" % (r.type, ev.address, who))
        return self._make(ev, S.PARTIAL, "xref_quote_unmatched",
                          "a reference to this function exists at %s, but the quote could not be matched to it"
                          % ev.address)

    # ---- decompiled code ---------------------------------------------------------------------------

    def _corroborate(self, fragment: str) -> Tuple[List[str], bool]:
        """Assembly that matches a C fragment's constants and callees (addresses, had_features)."""
        numbers = [v for v in extract_numbers(fragment) if abs(v) > 1]   # 0 and 1 appear everywhere
        names = [n for n in re.findall(r"\b([A-Za-z_]\w*)\s*\(", fragment) if n not in _NOT_CALLS]
        found = set()
        for ins in self.f.detail.assembly:
            ikeys = set()
            for v in extract_numbers(ins.text):
                ikeys |= number_keys(v)
            if any(number_keys(v) & ikeys for v in numbers):
                found.add(ins.address)
        for site in self.f.detail.call_sites:
            if any(n in (site.target_name, site.thunk_target) for n in names):
                found.add(site.site)
        return sorted(found)[:8], bool(numbers or names)

    def _wrong_kind(self, ev: Evidence) -> Optional[EvidenceCheck]:
        cq = compact(strip_leading_address(ev.quote, None))
        if len(cq) < _MIN_FRAGMENT:
            return None
        for ins in self.f.detail.assembly:
            if cq == compact(ins.text) or cq in compact(ins.text):
                return self._make(ev, S.PARTIAL, "wrong_evidence_kind",
                                  "this quote is an assembly instruction (at %s), not decompiled code; it should "
                                  "be cited as kind 'instruction'" % ins.address, actual=ins.text,
                                  corroborating_addresses=[ins.address])
        return None

    def _check_decompiled_code(self, ev: Evidence) -> EvidenceCheck:
        code = self.f.code_text
        if code is None:
            return self._make(ev, S.UNCHECKABLE, "no_decompiled_code",
                              "there is no decompiled code to check this quote against",
                              missing="decompiled code is unavailable (%s)"
                              % (self.f.detail.decompilation.error or "decompiler failed"))
        parts = split_elisions(ev.quote) or [ev.quote]
        ccode, idx = compact_with_map(code)
        pos, first, last = 0, None, 0
        for part in parts:
            c = compact(part)
            i = ccode.find(c, pos) if c else -1
            if i < 0:
                return self._wrong_kind(ev) or self._make(
                    ev, S.NOT_FOUND, "fragment_not_in_decompiled_code",
                    "this fragment does not appear in the decompiled code: %r" % _clip(part, 80))
            first = i if first is None else first
            last, pos = i + len(c) - 1, i + len(c)

        if len(parts) == 1:
            positions = find_all(ccode, compact(parts[0]))
            lines = sorted({line_of(code, idx[p]) for p in positions})
            occurrences = len(positions)
            location = "decompiled code line%s %s" % ("s" if len(lines) > 1 else "", ", ".join(map(str, lines)))
        else:
            occurrences = None
            lo, hi = line_of(code, idx[first]), line_of(code, idx[last])
            location = "decompiled code lines %d-%d (segments in order)" % (lo, hi)
        addresses, had_features = self._corroborate(" ".join(parts))

        if any(len(compact(p)) < _MIN_CODE_FRAGMENT for p in parts):
            status, rcode, reason = S.PARTIAL, "fragment_too_short", "fragment is too short to be meaningful evidence"
        elif all(_GENERIC_CODE.match(compact(p)) for p in parts):
            status, rcode, reason = (S.PARTIAL, "fragment_too_generic",
                                     "a bare identifier or number says almost nothing about where or why")
        else:
            status, rcode, reason = S.CONFIRMED, "fragment_confirmed", "fragment found at %s" % location
            if occurrences and occurrences > 1:
                reason += "; it occurs %d times, so the evidence does not say which occurrence is meant" % occurrences
            if addresses:
                reason += "; matching assembly at %s" % ", ".join(addresses)
            elif had_features:
                reason += "; no assembly instruction or call site matches its constants or callees"
        result = self._make(ev, status, rcode, reason, location=location, occurrences=occurrences,
                            corroborating_addresses=addresses)
        return self._soft_address(ev, result)

    # ---- parameter ---------------------------------------------------------------------------------

    def _check_parameter(self, ev: Evidence) -> EvidenceCheck:
        q = ev.quote.strip()
        params = self.f.detail.parameters
        for p in params:
            if (p.name and p.name in q) or (p.storage and p.storage == q):
                return self._soft_address(ev, self._make(ev, S.CONFIRMED, "parameter_confirmed",
                                                         "matches a parameter recorded by Ghidra (%s)" % p.name))
        ids = [w for w in re.findall(r"[A-Za-z_]\w*", q) if w.lower() not in _C_WORDS]
        code = self.f.code_text
        if code is not None and any(re.search(r"\b%s\b" % re.escape(w), code) for w in ids):
            note = "Ghidra recorded no parameter list for this function" if not params \
                else "it is not in Ghidra's recorded parameter list"
            return self._soft_address(ev, self._make(
                ev, S.CONFIRMED, "parameter_in_code",
                "the name appears in the decompiled code (%s)" % note))
        if not params and code is None:
            return self._make(ev, S.UNCHECKABLE, "parameter_unverifiable",
                              "no parameter list and no decompiled code to check against",
                              missing="parameter information is unavailable")
        return self._make(ev, S.NOT_FOUND, "parameter_not_found",
                          "no parameter matching %r is recorded or used in the decompiled code" % _clip(q, 60))

    # ---- metadata ------------------------------------------------------------------------------------

    def _check_metadata(self, ev: Evidence) -> EvidenceCheck:
        d, s = self.f.detail, self.f.summary
        values: List[Optional[str]] = [d.name, d.signature, d.return_type, d.calling_convention, d.namespace,
                                       s.address, str(d.size_bytes), str(d.instruction_count)]
        try:
            m = self.f.analysis.metadata
            values += [m.executable_format, m.language_id, m.compiler_spec]
        except BinProofError:
            pass
        cq = compact(ev.quote)

        def matches(v: str) -> bool:
            cv = compact(v)
            return cq in cv or (len(cv) >= 4 and cv in cq)   # short values (like "8") prove nothing

        if len(cq) >= 3 and any(matches(v) for v in values if v):
            return self._soft_address(ev, self._make(ev, S.CONFIRMED, "metadata_confirmed",
                                                     "matches recorded function or program metadata"))
        return self._make(ev, S.UNCHECKABLE, "metadata_not_checkable",
                          "free-form metadata claim; it does not match any recorded metadata value",
                          missing="no recorded metadata corresponds to this quote")
