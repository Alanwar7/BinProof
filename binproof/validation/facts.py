"""FunctionFacts: the ground truth for the analyzed function, loaded through Analysis.

Parts that cannot be loaded (for example because an extraction step failed) are
recorded in `unavailable` with a reason instead of raising, so checks that
depend on them report UNCHECKABLE rather than guessing.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, List, Optional, Set, Tuple, TypeVar

from ..addresses import normalize_address
from ..analysis import Analysis
from ..errors import (
    ArtifactUnavailableError, BinProofError, MalformedJSONError, MissingArtifactError,
    SchemaError,
)
from ..models import (
    CallRelation, FunctionDetail, FunctionSummary, ImportEntry, Reference, StringEntry,
)
from .errors import ValidationInputError
from .text import extract_numbers, number_keys

T = TypeVar("T")


def _reason(exc: BaseException) -> str:
    if isinstance(exc, ArtifactUnavailableError):
        return "its extraction step failed"
    if isinstance(exc, MissingArtifactError):
        return "the file is missing"
    if isinstance(exc, (MalformedJSONError, SchemaError)):
        return "the file could not be parsed"
    return type(exc).__name__


@dataclass
class FunctionFacts:
    analysis: Analysis
    summary: FunctionSummary
    detail: FunctionDetail
    callees: Optional[List[CallRelation]]
    callers: Optional[List[CallRelation]]
    imports_used: Optional[List[ImportEntry]]
    strings_used: Optional[List[StringEntry]]
    xrefs: Optional[List[Reference]]
    unavailable: Dict[str, str] = field(default_factory=dict)
    _locator: Optional[Tuple[List[int], List[Tuple[int, FunctionSummary]]]] = field(default=None, repr=False)
    _known: Optional[Set[str]] = field(default=None, repr=False)
    _numbers: Optional[FrozenSet[int]] = field(default=None, repr=False)

    # ---- loading -------------------------------------------------------------

    @classmethod
    def load(cls, analysis: Analysis, address: str) -> "FunctionFacts":
        summary = analysis.get_function(address)  # FunctionNotFoundError if the export lacks it
        try:
            detail = analysis.load_function(summary.address)
        except BinProofError as exc:
            raise ValidationInputError(
                "cannot validate: the per-function record for %s cannot be loaded (%s)"
                % (summary.address, _reason(exc))) from exc
        unavailable: Dict[str, str] = {}

        def part(name: str, fn: Callable[[], T]) -> Optional[T]:
            try:
                return fn()
            except BinProofError as exc:
                unavailable[name] = _reason(exc)
                return None

        a = summary.address
        return cls(
            analysis=analysis, summary=summary, detail=detail,
            callees=part("callees", lambda: analysis.get_callees(a)),
            callers=part("callers", lambda: analysis.get_callers(a)),
            imports_used=part("imports", lambda: analysis.get_imports_for_function(a)),
            strings_used=part("strings", lambda: analysis.get_strings_for_function(a)),
            xrefs=part("xrefs", lambda: analysis.get_references_to(a)),
            unavailable=unavailable,
        )

    @property
    def address(self) -> str:
        return self.summary.address

    @property
    def code_text(self) -> Optional[str]:
        d = self.detail.decompilation
        return d.c if d.ok else None

    def missing(self, part: str) -> str:
        return "%s data is unavailable (%s)" % (part, self.unavailable.get(part, "unknown reason"))

    # ---- address knowledge ----------------------------------------------------

    def function_containing(self, address: str) -> Optional[FunctionSummary]:
        """The function whose address range contains `address`, if any (from the index)."""
        if self._locator is None:
            entries = sorted((int(f.address.split("0x", 1)[1], 16), f) for f in self.analysis.iter_functions()
                             if not f.address.startswith("EXTERNAL"))
            self._locator = ([e[0] for e in entries], entries)
        starts, entries = self._locator
        try:
            value = int(address.split("0x", 1)[1], 16)
        except (IndexError, ValueError):
            return None
        i = bisect.bisect_right(starts, value) - 1
        if i < 0:
            return None
        start, func = entries[i]
        return func if value < start + max(func.size_bytes, 1) else None

    def is_known_address(self, address: str) -> bool:
        if self.detail.instruction_at(address) is not None:
            return True
        for finder in (self.analysis.get_function, self.analysis.get_string_at):
            try:
                finder(address)
                return True
            except BinProofError:
                pass
        return any(r.function.address == address for r in (self.callees or []))

    # ---- names -------------------------------------------------------------------

    def known_names(self) -> Set[str]:
        """Every function and import name in the binary."""
        if self._known is None:
            names = {f.name for f in self.analysis.iter_functions()}
            try:
                for imp in self.analysis.get_imports():
                    names.add(imp.name)
            except BinProofError:
                pass
            self._known = names
        return self._known

    def import_names(self) -> Set[str]:
        try:
            return {i.name for i in self.analysis.get_imports()}
        except BinProofError:
            return set()

    def callee_names(self) -> Set[str]:
        names = {i.name for i in (self.imports_used or [])}
        for r in self.callees or []:
            if r.function.name:
                names.add(r.function.name)
            if r.thunk_target:
                names.add(r.thunk_target)
        return names

    def caller_names(self) -> Set[str]:
        names = {r.function.name for r in (self.callers or []) if r.function.name}
        names |= {x.from_function.name for x in (self.xrefs or []) if x.from_function and x.from_function.name}
        return names

    # ---- numbers ---------------------------------------------------------------------

    def code_number_keys(self) -> FrozenSet[int]:
        """Equivalent forms of every constant appearing in this function's code."""
        if self._numbers is None:
            keys: Set[int] = set()
            texts = [i.text for i in self.detail.assembly]
            if self.code_text:
                texts.append(self.code_text)
            for t in texts:
                for v in extract_numbers(t):
                    keys |= number_keys(v)
            self._numbers = frozenset(keys)
        return self._numbers

    @property
    def data_may_be_incomplete(self) -> Optional[str]:
        """Why 'X is not a callee/caller' cannot be trusted as a contradiction, if so."""
        if self.detail.indirect_call_sites:
            return "the function makes indirect calls Ghidra could not resolve"
        if self.analysis.is_truncated:
            return "the extraction was truncated, so call data may be incomplete"
        if self.unavailable.get("callees") or self.unavailable.get("callers"):
            return "call data is unavailable"
        return None
