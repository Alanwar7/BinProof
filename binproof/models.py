"""Immutable data models for a BinProof analysis.

These are plain data: no I/O, no behaviour that depends on files. Every record
carries the address it came from, so later stages (AI explanations, evidence
validation, reports) can cite coordinates.

NOTE: strings, symbol names and decompiled code originate from the analyzed
binary and must be treated as untrusted text. They can contain text aimed at
an AI model; never treat them as instructions.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from typing import Dict, List, Mapping, Optional, Tuple


@dataclass(frozen=True)
class Problem:
    """A non-fatal issue found while loading (skipped record, missing file...)."""
    severity: str  # "warning" | "error"
    source: str    # file the problem relates to
    message: str

    def __str__(self) -> str:
        return "[%s] %s: %s" % (self.severity, self.source, self.message)


# ---- manifest / metadata ---------------------------------------------------

@dataclass(frozen=True)
class ExportError:
    step: str
    traceback: str = ""

    @property
    def summary(self) -> str:
        lines = [l for l in self.traceback.strip().splitlines() if l.strip()]
        return lines[-1] if lines else "(no traceback recorded)"


@dataclass(frozen=True)
class Manifest:
    schema_version: str
    complete: bool
    program_name: Optional[str] = None
    counts: Mapping[str, int] = None  # type: ignore[assignment]
    max_functions: int = 0
    errors: Tuple[ExportError, ...] = ()
    elapsed_seconds: Optional[float] = None
    files: Tuple[str, ...] = ()

    @property
    def failed_steps(self) -> frozenset:
        return frozenset(e.step for e in self.errors)

    @property
    def truncated(self) -> bool:
        return bool((self.counts or {}).get("functions_truncated", False))


@dataclass(frozen=True)
class MemoryBlock:
    name: str
    start: str
    end: str
    size: int = 0
    read: bool = False
    write: bool = False
    execute: bool = False
    initialized: bool = False


@dataclass(frozen=True)
class ProgramMetadata:
    program_name: Optional[str] = None
    schema_version: Optional[str] = None
    executable_path: Optional[str] = None
    executable_format: Optional[str] = None
    md5: Optional[str] = None
    sha256: Optional[str] = None
    language_id: Optional[str] = None
    processor: Optional[str] = None
    big_endian: Optional[bool] = None
    pointer_size_bytes: Optional[int] = None
    compiler_spec: Optional[str] = None
    image_base: Optional[str] = None
    entry_points: Tuple[str, ...] = ()
    memory_blocks: Tuple[MemoryBlock, ...] = ()
    ghidra_version: Optional[str] = None


# ---- functions -------------------------------------------------------------

@dataclass(frozen=True)
class FunctionRef:
    """A pointer to a function; name can be unknown."""
    address: str
    name: Optional[str] = None


@dataclass(frozen=True)
class FunctionSummary:
    """One row of functions.json. Cheap: no assembly or decompiled code."""
    address: str
    name: str
    size_bytes: int = 0
    instruction_count: int = 0
    signature: Optional[str] = None
    is_thunk: bool = False
    caller_count: int = 0
    callee_count: int = 0
    decompile_status: str = "unknown"
    file: Optional[str] = None


@dataclass(frozen=True)
class Parameter:
    name: str
    type: Optional[str] = None
    storage: Optional[str] = None


@dataclass(frozen=True)
class Instruction:
    address: str
    bytes: str
    text: str


@dataclass(frozen=True)
class CallSite:
    """An outgoing call made from inside a function, with its site address."""
    site: str
    target: str
    target_name: Optional[str] = None
    target_is_external: bool = False
    target_is_thunk: bool = False
    thunk_target: Optional[str] = None
    thunk_target_is_external: Optional[bool] = None


@dataclass(frozen=True)
class Decompilation:
    status: str = "failed"
    c: Optional[str] = None
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status == "ok" and self.c is not None


@dataclass(frozen=True)
class FunctionDetail:
    """The full per-function record (functions/<addr>.json)."""
    address: str
    name: str
    end_address: Optional[str] = None
    size_bytes: int = 0
    instruction_count: int = 0
    signature: Optional[str] = None
    return_type: Optional[str] = None
    parameters: Tuple[Parameter, ...] = ()
    calling_convention: Optional[str] = None
    namespace: Optional[str] = None
    is_thunk: bool = False
    callers: Tuple[FunctionRef, ...] = ()
    call_sites: Tuple[CallSite, ...] = ()
    indirect_call_sites: Tuple[str, ...] = ()
    decompilation: Decompilation = Decompilation()
    assembly: Tuple[Instruction, ...] = ()

    def assembly_text(self) -> str:
        return "\n".join("%s  %s" % (i.address, i.text) for i in self.assembly)

    @cached_property
    def _instructions_by_address(self) -> Dict[str, Instruction]:
        return {i.address: i for i in self.assembly}

    def instruction_at(self, address: str) -> Optional[Instruction]:
        """Look up an instruction by canonical address (used for evidence checks)."""
        return self._instructions_by_address.get(address)


# ---- graph, references -------------------------------------------------------

@dataclass(frozen=True)
class CallEdge:
    from_function: str
    call_site: str
    to: str
    from_name: Optional[str] = None
    to_name: Optional[str] = None
    to_is_external: bool = False
    thunk_target: Optional[str] = None


@dataclass(frozen=True)
class CallGraph:
    edges: Tuple[CallEdge, ...]
    node_count: int = 0

    @cached_property
    def by_caller(self) -> Dict[str, Tuple[CallEdge, ...]]:
        out: Dict[str, List[CallEdge]] = {}
        for e in self.edges:
            out.setdefault(e.from_function, []).append(e)
        return {k: tuple(v) for k, v in out.items()}

    @cached_property
    def by_callee(self) -> Dict[str, Tuple[CallEdge, ...]]:
        out: Dict[str, List[CallEdge]] = {}
        for e in self.edges:
            out.setdefault(e.to, []).append(e)
        return {k: tuple(v) for k, v in out.items()}


@dataclass(frozen=True)
class CallRelation:
    """One related function plus every call site that links it to the query function."""
    function: FunctionRef
    call_sites: Tuple[str, ...]
    is_external: bool = False
    thunk_target: Optional[str] = None


@dataclass(frozen=True)
class Reference:
    """An incoming reference (xref): where it comes from and what kind it is."""
    from_address: str
    type: str = ""
    is_call: bool = False
    from_function: Optional[FunctionRef] = None


# ---- strings, imports ----------------------------------------------------------

@dataclass(frozen=True)
class StringRef:
    from_address: str
    from_function: Optional[FunctionRef] = None


@dataclass(frozen=True)
class StringEntry:
    address: str
    value: str
    length: int = 0
    data_type: str = ""
    reference_count: int = 0
    referenced_from: Tuple[StringRef, ...] = ()

    @property
    def references_truncated(self) -> bool:
        """True if the extractor capped the reference list (reference_count is the truth)."""
        return self.reference_count > len(self.referenced_from)


@dataclass(frozen=True)
class ImportEntry:
    library: str
    name: str
    original_name: Optional[str] = None
    address: Optional[str] = None
    thunks: Tuple[str, ...] = ()
    call_sites: Tuple[Reference, ...] = ()
    other_references: Tuple[Reference, ...] = ()


__all__ = [n for n, v in list(globals().items()) if isinstance(v, type) and v.__module__ == __name__]
