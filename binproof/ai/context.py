"""FunctionContext: everything the model is allowed to know about one function.

Built only through the existing Analysis API. Anything missing, failed or cut
for size is recorded in `notes`, so the model is told what it cannot see and
the saved record keeps that history. Nothing is ever filled in by guesswork.
No local file paths are included (the context is sent to an API).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Callable, List, Optional, Tuple, TypeVar

from ..addresses import AddressLike
from ..analysis import Analysis
from ..errors import (
    ArtifactUnavailableError, BinProofError, MalformedJSONError,
    MissingArtifactError, SchemaError,
)
from ..models import Instruction, Parameter
from .errors import InsufficientContextError

T = TypeVar("T")


@dataclass(frozen=True)
class ContextLimits:
    max_instructions: int = 600
    max_decompiled_chars: int = 24000
    max_strings: int = 40
    max_string_chars: int = 200
    max_related: int = 30      # callers, callees
    max_xrefs: int = 30


@dataclass(frozen=True)
class ProgramFacts:
    executable_format: Optional[str] = None
    language_id: Optional[str] = None
    compiler_spec: Optional[str] = None
    pointer_size_bytes: Optional[int] = None


@dataclass(frozen=True)
class RelatedFunction:
    address: str
    name: Optional[str]
    call_sites: Tuple[str, ...]
    is_external: bool = False
    thunk_target: Optional[str] = None
    signature: Optional[str] = None


@dataclass(frozen=True)
class ImportUse:
    library: str
    name: str
    sites: Tuple[str, ...]  # addresses inside this function that use the import


@dataclass(frozen=True)
class StringUse:
    address: str
    value: str
    total_length: int
    sites: Tuple[str, ...]  # addresses inside this function that reference the string


@dataclass(frozen=True)
class XrefItem:
    from_address: str
    type: str
    from_function: Optional[str]
    from_function_address: Optional[str]


@dataclass(frozen=True)
class FunctionContext:
    address: str
    name: str
    signature: Optional[str]
    return_type: Optional[str]
    calling_convention: Optional[str]
    namespace: Optional[str]
    size_bytes: int
    instruction_count: int
    is_thunk: bool
    program: ProgramFacts
    parameters: Tuple[Parameter, ...]
    decompiled_c: Optional[str]
    assembly: Tuple[Instruction, ...]
    assembly_total: int
    callers: Tuple[RelatedFunction, ...]
    callees: Tuple[RelatedFunction, ...]
    callers_total: int
    callees_total: int
    imports: Tuple[ImportUse, ...]
    strings: Tuple[StringUse, ...]
    strings_total: int
    xrefs: Tuple[XrefItem, ...]
    xrefs_total: int
    indirect_call_sites: Tuple[str, ...]
    notes: Tuple[str, ...]

    def sha256(self) -> str:
        blob = json.dumps(asdict(self), sort_keys=True, default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _reason(exc: BaseException) -> str:
    """Short, path-free explanation of why data could not be loaded."""
    if isinstance(exc, ArtifactUnavailableError):
        return "its extraction step failed"
    if isinstance(exc, MissingArtifactError):
        return "the file is missing"
    if isinstance(exc, (MalformedJSONError, SchemaError)):
        return "the file could not be parsed"
    return type(exc).__name__


def _safe(label: str, fn: Callable[[], T], notes: List[str], default: T) -> T:
    try:
        return fn()
    except BinProofError as exc:
        notes.append("%s are unavailable (%s)." % (label, _reason(exc)))
        return default


def build_function_context(analysis: Analysis, address: AddressLike,
                           limits: Optional[ContextLimits] = None) -> FunctionContext:
    """Collect one function's data through Analysis. Raises FunctionNotFoundError if it
    does not exist, InsufficientContextError if there is no code to analyze."""
    limits = limits or ContextLimits()
    notes: List[str] = []

    summary = analysis.get_function(address)
    addr = summary.address
    try:
        detail = analysis.load_function(addr)
    except BinProofError as exc:
        raise InsufficientContextError(
            "the per-function record for %s cannot be loaded (%s), so there is no code to analyze"
            % (addr, _reason(exc))) from exc

    decompiled = detail.decompilation.c if detail.decompilation.ok else None
    if decompiled is None:
        notes.append("Decompiled code is unavailable (%s)." % (detail.decompilation.error or "decompiler failed"))
    elif len(decompiled) > limits.max_decompiled_chars:
        notes.append("Decompiled code was truncated to the first %d of %d characters."
                     % (limits.max_decompiled_chars, len(decompiled)))
        decompiled = decompiled[: limits.max_decompiled_chars]

    assembly = detail.assembly
    if not assembly:
        notes.append("No assembly instructions are available.")
    elif len(assembly) > limits.max_instructions:
        notes.append("Assembly was truncated to the first %d of %d instructions."
                     % (limits.max_instructions, len(assembly)))
    if decompiled is None and not assembly:
        raise InsufficientContextError(
            "function %s has neither decompiled code nor assembly; nothing to analyze" % addr)

    meta = _safe("Program details", lambda: analysis.metadata, [], None)
    program = ProgramFacts(
        executable_format=meta.executable_format, language_id=meta.language_id,
        compiler_spec=meta.compiler_spec, pointer_size_bytes=meta.pointer_size_bytes,
    ) if meta else ProgramFacts()

    def related(rels) -> Tuple[RelatedFunction, ...]:
        out = []
        for r in rels[: limits.max_related]:
            sig = None
            try:
                sig = analysis.get_function(r.function.address).signature
            except BinProofError:
                pass
            out.append(RelatedFunction(r.function.address, r.function.name, r.call_sites,
                                       r.is_external, r.thunk_target, sig))
        return tuple(out)

    callers_all = _safe("Callers", lambda: analysis.get_callers(addr), notes, [])
    callees_all = _safe("Callees", lambda: analysis.get_callees(addr), notes, [])
    callers, callees = related(callers_all), related(callees_all)
    if len(callers_all) > limits.max_related or len(callees_all) > limits.max_related:
        notes.append("Caller/callee lists were truncated to %d entries each." % limits.max_related)
    if analysis.is_truncated:
        notes.append("The extraction was truncated, so caller and callee lists may be incomplete.")
    if detail.indirect_call_sites:
        notes.append("%d call(s) use computed targets that Ghidra could not resolve; "
                     "their callees are unknown." % len(detail.indirect_call_sites))

    imports = []
    for imp in _safe("Imports", lambda: analysis.get_imports_for_function(addr), notes, []):
        sites = tuple(sorted({r.from_address for r in imp.call_sites + imp.other_references
                              if r.from_function and r.from_function.address == addr}))
        imports.append(ImportUse(imp.library, imp.name, sites))

    strings_all = _safe("Referenced strings", lambda: analysis.get_strings_for_function(addr), notes, [])
    strings = []
    for s in strings_all[: limits.max_strings]:
        sites = tuple(sorted(r.from_address for r in s.referenced_from
                             if r.from_function and r.from_function.address == addr))
        strings.append(StringUse(s.address, s.value[: limits.max_string_chars], len(s.value), sites))
    if len(strings_all) > limits.max_strings:
        notes.append("Referenced strings were truncated to %d of %d." % (limits.max_strings, len(strings_all)))

    refs = _safe("Cross-references", lambda: analysis.get_references_to(addr), notes, [])
    refs = [r for r in refs if not r.is_call or r.from_function is None]  # calls are in `callers`
    xrefs = tuple(XrefItem(r.from_address, r.type,
                           r.from_function.name if r.from_function else None,
                           r.from_function.address if r.from_function else None)
                  for r in refs[: limits.max_xrefs])
    if len(refs) > limits.max_xrefs:
        notes.append("Cross-references were truncated to %d of %d." % (limits.max_xrefs, len(refs)))

    return FunctionContext(
        address=addr, name=summary.name, signature=detail.signature or summary.signature,
        return_type=detail.return_type, calling_convention=detail.calling_convention,
        namespace=detail.namespace, size_bytes=detail.size_bytes,
        instruction_count=detail.instruction_count, is_thunk=detail.is_thunk, program=program,
        parameters=detail.parameters, decompiled_c=decompiled,
        assembly=tuple(assembly[: limits.max_instructions]), assembly_total=len(assembly),
        callers=callers, callees=callees,
        callers_total=len(callers_all), callees_total=len(callees_all),
        imports=tuple(imports), strings=tuple(strings), strings_total=len(strings_all),
        xrefs=xrefs, xrefs_total=len(refs),
        indirect_call_sites=tuple(detail.indirect_call_sites), notes=tuple(notes),
    )
