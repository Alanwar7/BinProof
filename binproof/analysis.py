"""Analysis: the read-only query API the rest of BinProof builds on.

AI providers, the evidence validator and report generators should depend on
this class only. It knows nothing about files; the AnalysisStore handles that.

Addresses can be passed as "0x401000", "401000" or an int. Returned records
always carry canonical addresses ("0x00401000").
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .addresses import AddressLike, normalize_address
from .errors import LookupFailedError
from .models import (
    CallRelation, FunctionDetail, FunctionRef, FunctionSummary, ImportEntry,
    Manifest, Problem, ProgramMetadata, Reference, StringEntry,
)
from .store import (
    DEFAULT_FUNCTION_CACHE_SIZE, DEFAULT_MAX_FILE_BYTES, AnalysisStore,
)


class Analysis:
    def __init__(self, store: AnalysisStore):
        self._store = store
        self._strings_by_address: Optional[Dict[str, StringEntry]] = None
        self._strings_by_function: Optional[Dict[str, List[StringEntry]]] = None
        self._imports_by_function: Optional[Dict[str, List[ImportEntry]]] = None
        self._functions_by_name: Optional[Dict[str, List[FunctionSummary]]] = None

    @classmethod
    def open(cls, root, *, strict: bool = False, allow_incomplete: bool = False,
             max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
             function_cache_size: int = DEFAULT_FUNCTION_CACHE_SIZE) -> "Analysis":
        """Open an export directory produced by run_analysis.py.

        strict            raise on any malformed record instead of skipping it
        allow_incomplete  open exports whose manifest says complete=false; data
                          from the failed step(s) raises ArtifactUnavailableError
        """
        return cls(AnalysisStore.open(
            root, strict=strict, allow_incomplete=allow_incomplete,
            max_file_bytes=max_file_bytes, function_cache_size=function_cache_size))

    def __repr__(self) -> str:
        return "<Analysis %s complete=%s truncated=%s>" % (
            self._store.root, self.is_complete, self.is_truncated)

    # ---- state ---------------------------------------------------------------

    @property
    def root(self):
        return self._store.root

    @property
    def manifest(self) -> Manifest:
        return self._store.manifest

    @property
    def metadata(self) -> ProgramMetadata:
        return self._store.metadata

    @property
    def is_complete(self) -> bool:
        return self._store.is_complete

    @property
    def is_truncated(self) -> bool:
        return self._store.is_truncated

    @property
    def problems(self) -> Tuple[Problem, ...]:
        """Non-fatal issues found so far (grows as more files are loaded)."""
        return self._store.problems

    def describe(self) -> dict:
        m = self.manifest
        return {
            "path": str(self.root),
            "program": m.program_name,
            "schema_version": m.schema_version,
            "complete": m.complete,
            "truncated": self.is_truncated,
            "failed_steps": sorted(m.failed_steps),
            "counts": dict(m.counts or {}),
            "problems": len(self.problems),
        }

    # ---- functions ------------------------------------------------------------------

    @property
    def function_count(self) -> int:
        return len(self._store.function_index)

    def iter_functions(self):
        """Summaries in address order (cheap; no assembly or decompiled code)."""
        index = self._store.function_index
        for address in sorted(index):
            yield index[address]

    def get_function(self, address: AddressLike) -> FunctionSummary:
        """Summary for one function. Raises FunctionNotFoundError."""
        return self._store.get_summary(address)

    def find_functions(self, *, name_contains: Optional[str] = None,
                       include_thunks: bool = True) -> List[FunctionSummary]:
        needle = name_contains.lower() if name_contains else None
        return [f for f in self.iter_functions()
                if (include_thunks or not f.is_thunk) and (needle is None or needle in f.name.lower())]

    def get_functions_by_name(self, name: str) -> List[FunctionSummary]:
        """Exact-name lookup (names are not unique, so this returns a list)."""
        if self._functions_by_name is None:
            by_name: Dict[str, List[FunctionSummary]] = {}
            for f in self.iter_functions():
                by_name.setdefault(f.name, []).append(f)
            self._functions_by_name = by_name
        return list(self._functions_by_name.get(name, []))

    def load_function(self, address: AddressLike) -> FunctionDetail:
        """Full record (assembly, decompiled code, call sites). Loaded on demand."""
        return self._store.load_function(address)

    def get_decompiled_code(self, address: AddressLike) -> Optional[str]:
        """Decompiled C, or None if Ghidra's decompiler failed for this function."""
        detail = self.load_function(address)
        return detail.decompilation.c if detail.decompilation.ok else None

    def get_assembly_text(self, address: AddressLike) -> str:
        return self.load_function(address).assembly_text()

    # ---- call graph ------------------------------------------------------------------

    def get_callers(self, address: AddressLike) -> List[CallRelation]:
        """Functions that call this one, grouped, each with its call-site addresses."""
        key = self._store.get_summary(address).address
        edges = self._store.call_graph.by_callee.get(key, ())
        grouped: Dict[str, List] = {}
        for e in edges:
            grouped.setdefault(e.from_function, []).append(e)
        return [CallRelation(function=FunctionRef(addr, es[0].from_name),
                             call_sites=tuple(e.call_site for e in es))
                for addr, es in grouped.items()]

    def get_callees(self, address: AddressLike) -> List[CallRelation]:
        """Functions this one calls (direct calls only), grouped, with call sites.

        Indirect calls Ghidra could not resolve are in
        load_function(address).indirect_call_sites.
        """
        key = self._store.get_summary(address).address
        edges = self._store.call_graph.by_caller.get(key, ())
        grouped: Dict[str, List] = {}
        for e in edges:
            grouped.setdefault(e.to, []).append(e)
        return [CallRelation(function=FunctionRef(addr, es[0].to_name),
                             call_sites=tuple(e.call_site for e in es),
                             is_external=es[0].to_is_external,
                             thunk_target=es[0].thunk_target)
                for addr, es in grouped.items()]

    # ---- references -------------------------------------------------------------------

    def get_references_to(self, address: AddressLike, *, calls_only: bool = False) -> List[Reference]:
        """Incoming references (xrefs) to a function entry point.

        The extractor records xrefs for function entries only. For data such as
        strings use get_string_at(address).referenced_from.
        """
        key = self._store.get_summary(address).address
        refs = self._store.xrefs.get(key, ())
        return [r for r in refs if r.is_call or not calls_only]

    # ---- strings -----------------------------------------------------------------------

    def get_strings(self, *, contains: Optional[str] = None, min_length: Optional[int] = None,
                    limit: Optional[int] = None) -> List[StringEntry]:
        """Filter strings (case-insensitive substring), ordered by address."""
        needle = contains.lower() if contains else None
        out: List[StringEntry] = []
        for s in sorted(self._store.strings, key=lambda s: s.address):
            if needle is not None and needle not in s.value.lower():
                continue
            if min_length is not None and len(s.value) < min_length:
                continue
            out.append(s)
            if limit is not None and len(out) >= limit:
                break
        return out

    def get_string_at(self, address: AddressLike) -> StringEntry:
        if self._strings_by_address is None:
            self._strings_by_address = {s.address: s for s in self._store.strings}
        key = normalize_address(address)
        try:
            return self._strings_by_address[key]
        except KeyError:
            raise LookupFailedError("no string at %s in this analysis" % key) from None

    def get_strings_for_function(self, address: AddressLike) -> List[StringEntry]:
        """Strings referenced from inside a function.

        Check StringEntry.references_truncated: the extractor keeps at most 50
        references per string, so a heavily used string may be missing here.
        """
        key = self._store.get_summary(address).address
        if self._strings_by_function is None:
            index: Dict[str, List[StringEntry]] = {}
            for s in sorted(self._store.strings, key=lambda s: s.address):
                seen = set()
                for ref in s.referenced_from:
                    if ref.from_function and ref.from_function.address not in seen:
                        seen.add(ref.from_function.address)
                        index.setdefault(ref.from_function.address, []).append(s)
            self._strings_by_function = index
        return list(self._strings_by_function.get(key, []))

    # ---- imports ------------------------------------------------------------------------

    def get_imports(self, *, library: Optional[str] = None,
                    name_contains: Optional[str] = None) -> List[ImportEntry]:
        lib = library.lower() if library else None
        needle = name_contains.lower() if name_contains else None
        out = [i for i in self._store.imports
               if (lib is None or i.library.lower() == lib)
               and (needle is None or needle in i.name.lower())]
        return sorted(out, key=lambda i: (i.library.lower(), i.name))

    def get_imports_for_function(self, address: AddressLike) -> List[ImportEntry]:
        """Imports a function calls or otherwise references (via thunks or IAT refs)."""
        key = self._store.get_summary(address).address
        if self._imports_by_function is None:
            index: Dict[str, List[ImportEntry]] = {}
            for imp in self.get_imports():
                seen = set()
                for ref in imp.call_sites + imp.other_references:
                    if ref.from_function and ref.from_function.address not in seen:
                        seen.add(ref.from_function.address)
                        index.setdefault(ref.from_function.address, []).append(imp)
            self._imports_by_function = index
        return list(self._imports_by_function.get(key, []))
