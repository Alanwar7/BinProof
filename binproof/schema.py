"""Pure parsers: raw JSON (already decoded) -> immutable models.

No file access here. Each parser validates structure and types and reports
problems with a field path ("functions[3].address") so a bad record is easy to
find. Per-record problems go through ParseContext.skip(): in lenient mode the
record is dropped and logged, in strict mode the error is raised.

The expected layout is the schema written by ghidra_scripts/ExportBinaryJSON.py
(schema_version "0.1").
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .addresses import normalize_address
from .errors import InvalidAddressError, SchemaError, UnsupportedSchemaError
from .models import (
    CallEdge, CallGraph, CallSite, Decompilation, ExportError, FunctionDetail,
    FunctionRef, FunctionSummary, ImportEntry, Instruction, Manifest,
    MemoryBlock, Parameter, Problem, ProgramMetadata, Reference, StringEntry,
    StringRef,
)

SUPPORTED_SCHEMA_VERSIONS = frozenset({"0.1"})


class ParseContext:
    """Carries the file being parsed, strictness and the shared problem log."""

    def __init__(self, path, strict: bool, problems: List[Problem]):
        self.path = Path(path)
        self.strict = strict
        self.problems = problems

    def error(self, where: str, message: str) -> SchemaError:
        return SchemaError(self.path, where, message)

    def skip(self, exc: SchemaError) -> None:
        if self.strict:
            raise exc
        problem = Problem("error", self.path.name, "skipped malformed entry: %s" % exc.detail)
        if problem not in self.problems:
            self.problems.append(problem)

    def warn(self, message: str) -> None:
        problem = Problem("warning", self.path.name, message)
        if problem not in self.problems:
            self.problems.append(problem)


# ---- field helpers -----------------------------------------------------------

def _join(where: str, key: str) -> str:
    return "%s.%s" % (where, key) if where else key


def _obj(value: Any, ctx: ParseContext, where: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ctx.error(where, "expected an object, got %s" % type(value).__name__)
    return value


def _typed(value: Any, kind: type, ctx: ParseContext, path: str):
    if kind is int:
        ok = isinstance(value, int) and not isinstance(value, bool)
    elif kind is float:
        ok = isinstance(value, (int, float)) and not isinstance(value, bool)
        if ok:
            return float(value)
    else:
        ok = isinstance(value, kind)
    if not ok:
        raise ctx.error(path, "expected %s, got %s" % (kind.__name__, type(value).__name__))
    return value


def req(obj, key, kind, ctx, where):
    path = _join(where, key)
    if key not in obj or obj[key] is None:
        raise ctx.error(path, "required field is missing")
    return _typed(obj[key], kind, ctx, path)


def opt(obj, key, kind, ctx, where, default=None):
    value = obj.get(key)
    if value is None:
        return default
    return _typed(value, kind, ctx, _join(where, key))


def _addr(raw: Any, ctx: ParseContext, path: str) -> str:
    if not isinstance(raw, str):
        raise ctx.error(path, "expected an address string, got %s" % type(raw).__name__)
    try:
        return normalize_address(raw)
    except InvalidAddressError:
        raise ctx.error(path, "invalid address %r" % raw) from None


def req_addr(obj, key, ctx, where) -> str:
    path = _join(where, key)
    if key not in obj or obj[key] is None:
        raise ctx.error(path, "required field is missing")
    return _addr(obj[key], ctx, path)


def opt_addr(obj, key, ctx, where) -> Optional[str]:
    if obj.get(key) is None:
        return None
    return _addr(obj[key], ctx, _join(where, key))


def _list(obj, key, ctx, where, required=False) -> list:
    if required:
        return req(obj, key, list, ctx, where)
    return opt(obj, key, list, ctx, where, [])


def parse_items(items: list, parser: Callable, ctx: ParseContext, where: str) -> tuple:
    """Parse a list of records; bad ones are skipped (lenient) or raise (strict)."""
    out = []
    for i, item in enumerate(items):
        try:
            out.append(parser(item, ctx, "%s[%d]" % (where, i)))
        except SchemaError as exc:
            ctx.skip(exc)
    return tuple(out)


def _addr_list(obj, key, ctx, where) -> Tuple[str, ...]:
    out = []
    for i, raw in enumerate(_list(obj, key, ctx, where)):
        try:
            out.append(_addr(raw, ctx, "%s[%d]" % (_join(where, key), i)))
        except SchemaError as exc:
            ctx.skip(exc)
    return tuple(out)


# ---- shared sub-records ----------------------------------------------------------

def _func_ref(value: Any, ctx: ParseContext, where: str) -> Optional[FunctionRef]:
    if value is None:
        return None
    obj = _obj(value, ctx, where)
    return FunctionRef(address=req_addr(obj, "address", ctx, where),
                       name=opt(obj, "name", str, ctx, where))


def _reference(value: Any, ctx: ParseContext, where: str) -> Reference:
    obj = _obj(value, ctx, where)
    return Reference(
        from_address=req_addr(obj, "from", ctx, where),
        type=opt(obj, "type", str, ctx, where, ""),
        is_call=opt(obj, "is_call", bool, ctx, where, False),
        from_function=_func_ref(obj.get("from_function"), ctx, _join(where, "from_function")),
    )


# ---- manifest / metadata -----------------------------------------------------------

def parse_manifest(data: Any, ctx: ParseContext) -> Manifest:
    obj = _obj(data, ctx, "")
    version = req(obj, "schema_version", str, ctx, "")
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        raise UnsupportedSchemaError(
            "%s: schema version %r is not supported (supported: %s)"
            % (ctx.path, version, ", ".join(sorted(SUPPORTED_SCHEMA_VERSIONS))))
    complete = req(obj, "complete", bool, ctx, "")

    counts: Dict[str, int] = {}
    for key, value in opt(obj, "counts", dict, ctx, "", {}).items():
        if isinstance(value, bool) or (isinstance(value, int)):
            counts[str(key)] = value  # functions_truncated is a bool
        else:
            raise ctx.error("counts.%s" % key, "expected a number or boolean")

    errors = []
    for i, item in enumerate(_list(obj, "errors", ctx, "")):
        eo = _obj(item, ctx, "errors[%d]" % i)
        errors.append(ExportError(step=req(eo, "step", str, ctx, "errors[%d]" % i),
                                  traceback=opt(eo, "traceback", str, ctx, "errors[%d]" % i, "")))
    files = tuple(f for f in _list(obj, "files", ctx, "") if isinstance(f, str))

    manifest = Manifest(
        schema_version=version, complete=complete,
        program_name=opt(obj, "program_name", str, ctx, ""),
        counts=counts,
        max_functions=opt(obj, "max_functions", int, ctx, "", 0),
        errors=tuple(errors),
        elapsed_seconds=opt(obj, "elapsed_seconds", float, ctx, ""),
        files=files,
    )
    if complete and errors:
        ctx.warn("manifest says complete=true but lists %d export error(s)" % len(errors))
    return manifest


def _memory_block(value: Any, ctx: ParseContext, where: str) -> MemoryBlock:
    obj = _obj(value, ctx, where)
    return MemoryBlock(
        name=req(obj, "name", str, ctx, where),
        start=req_addr(obj, "start", ctx, where),
        end=req_addr(obj, "end", ctx, where),
        size=opt(obj, "size", int, ctx, where, 0),
        read=opt(obj, "read", bool, ctx, where, False),
        write=opt(obj, "write", bool, ctx, where, False),
        execute=opt(obj, "execute", bool, ctx, where, False),
        initialized=opt(obj, "initialized", bool, ctx, where, False),
    )


def parse_metadata(data: Any, ctx: ParseContext) -> ProgramMetadata:
    obj = _obj(data, ctx, "")
    hashes = opt(obj, "hashes", dict, ctx, "", {})
    return ProgramMetadata(
        program_name=opt(obj, "program_name", str, ctx, ""),
        schema_version=opt(obj, "schema_version", str, ctx, ""),
        executable_path=opt(obj, "executable_path", str, ctx, ""),
        executable_format=opt(obj, "executable_format", str, ctx, ""),
        md5=hashes.get("md5") if isinstance(hashes.get("md5"), str) else None,
        sha256=hashes.get("sha256") if isinstance(hashes.get("sha256"), str) else None,
        language_id=opt(obj, "language_id", str, ctx, ""),
        processor=opt(obj, "processor", str, ctx, ""),
        big_endian=opt(obj, "big_endian", bool, ctx, ""),
        pointer_size_bytes=opt(obj, "pointer_size_bytes", int, ctx, ""),
        compiler_spec=opt(obj, "compiler_spec", str, ctx, ""),
        image_base=opt_addr(obj, "image_base", ctx, ""),
        entry_points=_addr_list(obj, "entry_points", ctx, ""),
        memory_blocks=parse_items(_list(obj, "memory_blocks", ctx, ""), _memory_block, ctx, "memory_blocks"),
        ghidra_version=opt(obj, "ghidra_version", str, ctx, ""),
    )


# ---- functions -------------------------------------------------------------------

def _function_summary(value: Any, ctx: ParseContext, where: str) -> FunctionSummary:
    obj = _obj(value, ctx, where)
    return FunctionSummary(
        address=req_addr(obj, "address", ctx, where),
        name=req(obj, "name", str, ctx, where),
        size_bytes=opt(obj, "size_bytes", int, ctx, where, 0),
        instruction_count=opt(obj, "instruction_count", int, ctx, where, 0),
        signature=opt(obj, "signature", str, ctx, where),
        is_thunk=opt(obj, "is_thunk", bool, ctx, where, False),
        caller_count=opt(obj, "caller_count", int, ctx, where, 0),
        callee_count=opt(obj, "callee_count", int, ctx, where, 0),
        decompile_status=opt(obj, "decompile_status", str, ctx, where, "unknown"),
        file=opt(obj, "file", str, ctx, where),
    )


def parse_function_index(data: Any, ctx: ParseContext) -> Tuple[bool, Tuple[FunctionSummary, ...]]:
    """-> (truncated, summaries) from functions.json."""
    obj = _obj(data, ctx, "")
    funcs = parse_items(_list(obj, "functions", ctx, "", required=True),
                        _function_summary, ctx, "functions")
    return opt(obj, "truncated", bool, ctx, "", False), funcs


def _parameter(value: Any, ctx: ParseContext, where: str) -> Parameter:
    obj = _obj(value, ctx, where)
    return Parameter(name=req(obj, "name", str, ctx, where),
                     type=opt(obj, "type", str, ctx, where),
                     storage=opt(obj, "storage", str, ctx, where))


def _instruction(value: Any, ctx: ParseContext, where: str) -> Instruction:
    obj = _obj(value, ctx, where)
    return Instruction(address=req_addr(obj, "address", ctx, where),
                       bytes=opt(obj, "bytes", str, ctx, where, ""),
                       text=req(obj, "text", str, ctx, where))


def _call_site(value: Any, ctx: ParseContext, where: str) -> CallSite:
    obj = _obj(value, ctx, where)
    return CallSite(
        site=req_addr(obj, "site", ctx, where),
        target=req_addr(obj, "target", ctx, where),
        target_name=opt(obj, "target_name", str, ctx, where),
        target_is_external=opt(obj, "target_is_external", bool, ctx, where, False),
        target_is_thunk=opt(obj, "target_is_thunk", bool, ctx, where, False),
        thunk_target=opt(obj, "thunk_target", str, ctx, where),
        thunk_target_is_external=opt(obj, "thunk_target_is_external", bool, ctx, where),
    )


def _caller_ref(value: Any, ctx: ParseContext, where: str) -> FunctionRef:
    ref = _func_ref(value, ctx, where)
    if ref is None:
        raise ctx.error(where, "expected an object, got null")
    return ref


def parse_function_detail(data: Any, ctx: ParseContext) -> FunctionDetail:
    obj = _obj(data, ctx, "")
    dec = opt(obj, "decompiled", dict, ctx, "", {})
    decompilation = Decompilation(
        status=opt(dec, "status", str, ctx, "decompiled", "failed"),
        c=opt(dec, "c", str, ctx, "decompiled"),
        error=opt(dec, "error", str, ctx, "decompiled"),
    )
    return FunctionDetail(
        address=req_addr(obj, "address", ctx, ""),
        name=req(obj, "name", str, ctx, ""),
        end_address=opt_addr(obj, "end_address", ctx, ""),
        size_bytes=opt(obj, "size_bytes", int, ctx, "", 0),
        instruction_count=opt(obj, "instruction_count", int, ctx, "", 0),
        signature=opt(obj, "signature", str, ctx, ""),
        return_type=opt(obj, "return_type", str, ctx, ""),
        parameters=parse_items(_list(obj, "parameters", ctx, ""), _parameter, ctx, "parameters"),
        calling_convention=opt(obj, "calling_convention", str, ctx, ""),
        namespace=opt(obj, "namespace", str, ctx, ""),
        is_thunk=opt(obj, "is_thunk", bool, ctx, "", False),
        callers=parse_items(_list(obj, "callers", ctx, ""), _caller_ref, ctx, "callers"),
        call_sites=parse_items(_list(obj, "call_sites", ctx, ""), _call_site, ctx, "call_sites"),
        indirect_call_sites=_addr_list(obj, "indirect_call_sites", ctx, ""),
        decompilation=decompilation,
        assembly=parse_items(_list(obj, "assembly", ctx, ""), _instruction, ctx, "assembly"),
    )


# ---- call graph, xrefs ---------------------------------------------------------------

def _call_edge(value: Any, ctx: ParseContext, where: str) -> CallEdge:
    obj = _obj(value, ctx, where)
    return CallEdge(
        from_function=req_addr(obj, "from_function", ctx, where),
        call_site=req_addr(obj, "call_site", ctx, where),
        to=req_addr(obj, "to", ctx, where),
        from_name=opt(obj, "from_name", str, ctx, where),
        to_name=opt(obj, "to_name", str, ctx, where),
        to_is_external=opt(obj, "to_is_external", bool, ctx, where, False),
        thunk_target=opt(obj, "thunk_target", str, ctx, where),
    )


def parse_call_graph(data: Any, ctx: ParseContext) -> Tuple[bool, CallGraph]:
    obj = _obj(data, ctx, "")
    nodes = _list(obj, "nodes", ctx, "")
    edges = parse_items(_list(obj, "edges", ctx, "", required=True), _call_edge, ctx, "edges")
    return (opt(obj, "truncated", bool, ctx, "", False),
            CallGraph(edges=edges, node_count=len(nodes)))


def parse_xrefs(data: Any, ctx: ParseContext) -> Tuple[bool, Dict[str, Tuple[Reference, ...]]]:
    obj = _obj(data, ctx, "")
    raw = req(obj, "xrefs", dict, ctx, "")
    out: Dict[str, Tuple[Reference, ...]] = {}
    for key, entry in raw.items():
        where = "xrefs[%r]" % key
        try:
            address = _addr(key, ctx, where)
            eo = _obj(entry, ctx, where)
            refs = parse_items(_list(eo, "references_to", ctx, where),
                               _reference, ctx, where + ".references_to")
            out[address] = refs
        except SchemaError as exc:
            ctx.skip(exc)
    return opt(obj, "truncated", bool, ctx, "", False), out


# ---- strings, imports -----------------------------------------------------------------

def _string_ref(value: Any, ctx: ParseContext, where: str) -> StringRef:
    obj = _obj(value, ctx, where)
    return StringRef(from_address=req_addr(obj, "from", ctx, where),
                     from_function=_func_ref(obj.get("from_function"), ctx, _join(where, "from_function")))


def _string_entry(value: Any, ctx: ParseContext, where: str) -> StringEntry:
    obj = _obj(value, ctx, where)
    return StringEntry(
        address=req_addr(obj, "address", ctx, where),
        value=opt(obj, "value", str, ctx, where, ""),
        length=opt(obj, "length", int, ctx, where, 0),
        data_type=opt(obj, "data_type", str, ctx, where, ""),
        reference_count=opt(obj, "reference_count", int, ctx, where, 0),
        referenced_from=parse_items(_list(obj, "referenced_from", ctx, where),
                                    _string_ref, ctx, _join(where, "referenced_from")),
    )


def parse_strings(data: Any, ctx: ParseContext) -> Tuple[StringEntry, ...]:
    obj = _obj(data, ctx, "")
    return parse_items(_list(obj, "strings", ctx, "", required=True), _string_entry, ctx, "strings")


def _import_entry(value: Any, ctx: ParseContext, where: str) -> ImportEntry:
    obj = _obj(value, ctx, where)
    return ImportEntry(
        library=opt(obj, "library", str, ctx, where, ""),
        name=req(obj, "name", str, ctx, where),
        original_name=opt(obj, "original_name", str, ctx, where),
        address=opt_addr(obj, "address", ctx, where),
        thunks=_addr_list(obj, "thunks", ctx, where),
        call_sites=parse_items(_list(obj, "call_sites", ctx, where), _reference, ctx, _join(where, "call_sites")),
        other_references=parse_items(_list(obj, "other_references", ctx, where),
                                     _reference, ctx, _join(where, "other_references")),
    )


def parse_imports(data: Any, ctx: ParseContext) -> Tuple[ImportEntry, ...]:
    obj = _obj(data, ctx, "")
    return parse_items(_list(obj, "imports", ctx, "", required=True), _import_entry, ctx, "imports")
