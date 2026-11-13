"""AnalysisStore: everything that touches files.

Responsibilities: open and validate manifest.json, enforce the completeness
policy, read and parse artifacts lazily (each file at most once), and keep a
small LRU cache of per-function records so a 50,000-function export never has
to fit in memory. Query logic lives in analysis.py, not here.

Not thread-safe (caches are plain dicts).
"""

from __future__ import annotations

import json
from collections import OrderedDict
from pathlib import Path, PurePosixPath
from typing import Callable, Dict, List, Optional, Tuple, TypeVar

from . import schema
from .addresses import AddressLike, normalize_address
from .errors import (
    AnalysisNotFoundError, ArtifactError, ArtifactTooLargeError,
    ArtifactUnavailableError, FunctionNotFoundError, IncompleteAnalysisError,
    ManifestError, MalformedJSONError, MissingArtifactError, SchemaError,
    UnsafePathError,
)
from .models import (
    CallGraph, FunctionDetail, FunctionSummary, Manifest, Problem,
    ProgramMetadata, Reference, StringEntry, ImportEntry,
)

T = TypeVar("T")

DEFAULT_MAX_FILE_BYTES = 256 * 1024 * 1024
DEFAULT_FUNCTION_CACHE_SIZE = 64
_MANIFEST_MAX_BYTES = 8 * 1024 * 1024

# Which extractor step produces each top-level artifact. If a step failed
# (manifest.errors), its artifacts are not trusted even if the files exist.
ARTIFACT_STEPS = {
    "metadata.json": "metadata",
    "functions.json": "functions",
    "xrefs.json": "functions",
    "call_graph.json": "functions",
    "strings.json": "strings",
    "imports.json": "imports",
}


def read_json(path: Path, max_bytes: int):
    """Read and decode one JSON file, raising typed errors instead of raw ones."""
    path = Path(path)
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        raise MissingArtifactError(path, "file not found") from None
    except OSError as exc:
        raise ArtifactError(path, "cannot stat file: %s" % exc) from None
    if not path.is_file():
        raise MissingArtifactError(path, "not a regular file")
    if size > max_bytes:
        raise ArtifactTooLargeError(
            path, "%d bytes exceeds the limit of %d bytes" % (size, max_bytes))
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ArtifactError(path, "cannot read file: %s" % exc) from None
    try:
        return json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise MalformedJSONError(path, "not valid UTF-8: %s" % exc) from None
    except json.JSONDecodeError as exc:
        raise MalformedJSONError(
            path, "invalid JSON at line %d, column %d: %s" % (exc.lineno, exc.colno, exc.msg)) from None
    except RecursionError:
        raise MalformedJSONError(path, "JSON nesting is too deep") from None


class AnalysisStore:
    def __init__(self, root: Path, manifest: Manifest, *, strict: bool,
                 max_file_bytes: int, function_cache_size: int):
        self.root = root
        self.manifest = manifest
        self.strict = strict
        self.max_file_bytes = max_file_bytes
        self._cache_size = max(1, function_cache_size)
        self._problems: List[Problem] = []
        self._loaded: Dict[str, object] = {}
        self._functions: "OrderedDict[str, FunctionDetail]" = OrderedDict()
        self._truncated_flags: Dict[str, bool] = {}

    # ---- opening ---------------------------------------------------------

    @classmethod
    def open(cls, root, *, strict: bool = False, allow_incomplete: bool = False,
             max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
             function_cache_size: int = DEFAULT_FUNCTION_CACHE_SIZE) -> "AnalysisStore":
        root = Path(root)
        if not root.is_dir():
            raise AnalysisNotFoundError("analysis directory not found: %s" % root)

        manifest_path = root / "manifest.json"
        problems: List[Problem] = []
        try:
            data = read_json(manifest_path, _MANIFEST_MAX_BYTES)
            manifest = schema.parse_manifest(data, schema.ParseContext(manifest_path, True, problems))
        except MissingArtifactError:
            raise ManifestError(manifest_path, (
                "manifest.json not found: the extraction did not finish. Ghidra exits 0 even "
                "when the export script fails, so check the log and re-run run_analysis.py")) from None
        except (MalformedJSONError, SchemaError, ArtifactError) as exc:
            raise ManifestError(manifest_path, exc.detail) from exc

        if not manifest.complete and not allow_incomplete:
            steps = sorted(manifest.failed_steps)
            reasons = "; ".join("%s: %s" % (e.step, e.summary) for e in manifest.errors)
            raise IncompleteAnalysisError(
                "extraction is incomplete (failed steps: %s). %s. "
                "Pass allow_incomplete=True to use the parts that succeeded."
                % (", ".join(steps) or "unknown", reasons or "no error details recorded"), steps)

        store = cls(root, manifest, strict=strict, max_file_bytes=max_file_bytes,
                    function_cache_size=function_cache_size)
        store._problems.extend(problems)
        for err in manifest.errors:
            store._problem("warning", "manifest.json",
                           "export step %r failed: %s" % (err.step, err.summary))
        store._check_layout()
        return store

    def _check_layout(self) -> None:
        names = [n for n, step in ARTIFACT_STEPS.items() if step not in self.manifest.failed_steps]
        missing = [n for n in names if not (self.root / n).is_file()]
        if ("functions" not in self.manifest.failed_steps
                and (self.manifest.counts or {}).get("functions", 0)
                and not (self.root / "functions").is_dir()):
            missing.append("functions/")
        for name in missing:
            if self.strict:
                raise MissingArtifactError(self.root / name, "expected by the manifest but not found")
            self._problem("error", name, "file is missing")

    # ---- problems / state --------------------------------------------------------

    def _problem(self, severity: str, source: str, message: str) -> None:
        problem = Problem(severity, source, message)
        if problem not in self._problems:
            self._problems.append(problem)

    @property
    def problems(self) -> Tuple[Problem, ...]:
        return tuple(self._problems)

    @property
    def is_complete(self) -> bool:
        return self.manifest.complete

    @property
    def is_truncated(self) -> bool:
        """True if the export stopped at max_functions (data covers only part of the binary)."""
        return self.manifest.truncated or any(self._truncated_flags.values())

    # ---- generic artifact loading ----------------------------------------------------

    def _load(self, name: str, parse: Callable[[object, schema.ParseContext], T]) -> T:
        if name in self._loaded:
            return self._loaded[name]  # type: ignore[return-value]
        step = ARTIFACT_STEPS[name]
        path = self.root / name
        if step in self.manifest.failed_steps:
            raise ArtifactUnavailableError(
                path, "export step %r failed, so this file is not trusted" % step)
        data = read_json(path, self.max_file_bytes)
        result = parse(data, schema.ParseContext(path, self.strict, self._problems))
        self._loaded[name] = result
        return result

    # ---- top-level artifacts -------------------------------------------------------------

    @property
    def metadata(self) -> ProgramMetadata:
        meta = self._load("metadata.json", schema.parse_metadata)
        if meta.schema_version and meta.schema_version != self.manifest.schema_version:
            self._problem("warning", "metadata.json", "schema_version %r differs from manifest %r"
                          % (meta.schema_version, self.manifest.schema_version))
        return meta

    @property
    def function_index(self) -> Dict[str, FunctionSummary]:
        """address -> FunctionSummary (light; no assembly or decompiled code)."""
        def parse(data, ctx):
            truncated, funcs = schema.parse_function_index(data, ctx)
            self._truncated_flags["functions.json"] = truncated
            index: Dict[str, FunctionSummary] = {}
            for f in funcs:
                if f.address in index:
                    ctx.warn("duplicate function address %s; keeping the first" % f.address)
                    continue
                index[f.address] = f
            expected = (self.manifest.counts or {}).get("functions")
            if expected is not None and not truncated and expected != len(index):
                ctx.warn("manifest reports %s functions but functions.json has %d usable"
                         % (expected, len(index)))
            return index
        return self._load("functions.json", parse)

    @property
    def call_graph(self) -> CallGraph:
        def parse(data, ctx):
            truncated, graph = schema.parse_call_graph(data, ctx)
            self._truncated_flags["call_graph.json"] = truncated
            return graph
        return self._load("call_graph.json", parse)

    @property
    def xrefs(self) -> Dict[str, Tuple[Reference, ...]]:
        """function entry address -> incoming references."""
        def parse(data, ctx):
            truncated, refs = schema.parse_xrefs(data, ctx)
            self._truncated_flags["xrefs.json"] = truncated
            return refs
        return self._load("xrefs.json", parse)

    @property
    def strings(self) -> Tuple[StringEntry, ...]:
        return self._load("strings.json", schema.parse_strings)

    @property
    def imports(self) -> Tuple[ImportEntry, ...]:
        return self._load("imports.json", schema.parse_imports)

    # ---- per-function records (lazy, LRU-cached) ------------------------------------------

    def get_summary(self, address: AddressLike) -> FunctionSummary:
        key = normalize_address(address)
        summary = self.function_index.get(key)
        if summary is None:
            hint = ""
            if self.is_truncated:
                hint = "export was truncated at max_functions=%d, so it may exist but was not exported" \
                       % self.manifest.max_functions
            raise FunctionNotFoundError(key, hint)
        return summary

    def _function_path(self, summary: FunctionSummary) -> Path:
        rel = summary.file or "functions/%s.json" % summary.address
        pure = PurePosixPath(rel)
        bad = (pure.is_absolute() or "\\" in rel or ".." in pure.parts or len(pure.parts) != 2
               or pure.parts[0] != "functions" or pure.suffix != ".json")
        if bad:
            raise UnsafePathError(self.root / "functions",
                                  "refusing unsafe function file reference %r for %s" % (rel, summary.address))
        path = self.root.joinpath(*pure.parts)
        try:
            path.resolve().relative_to(self.root.resolve())
        except ValueError:
            raise UnsafePathError(path, "function file resolves outside the analysis directory") from None
        return path

    def load_function(self, address: AddressLike) -> FunctionDetail:
        """Load one function's full record (assembly + decompiled code)."""
        summary = self.get_summary(address)
        cached = self._functions.get(summary.address)
        if cached is not None:
            self._functions.move_to_end(summary.address)
            return cached

        if "functions" in self.manifest.failed_steps:
            raise ArtifactUnavailableError(self.root / "functions",
                                           "export step 'functions' failed, so function records are not trusted")
        path = self._function_path(summary)
        data = read_json(path, self.max_file_bytes)
        ctx = schema.ParseContext(path, self.strict, self._problems)
        detail = schema.parse_function_detail(data, ctx)
        if detail.address != summary.address:
            raise SchemaError(path, "address", "record is for %s but the index says %s"
                              % (detail.address, summary.address))
        if detail.name != summary.name:
            ctx.warn("name %r differs from index name %r" % (detail.name, summary.name))

        self._functions[summary.address] = detail
        while len(self._functions) > self._cache_size:
            self._functions.popitem(last=False)
        return detail

    @property
    def cached_function_count(self) -> int:
        return len(self._functions)
