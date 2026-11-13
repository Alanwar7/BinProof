import json
import os

import pytest

from binproof import (
    Analysis, AnalysisNotFoundError, ArtifactTooLargeError, ArtifactUnavailableError,
    FunctionNotFoundError, IncompleteAnalysisError, InvalidAddressError, LookupFailedError,
    ManifestError, MalformedJSONError, MissingArtifactError, SchemaError,
    UnsafePathError, UnsupportedSchemaError, normalize_address,
)
from binproof import store as store_mod
from fixture import make_export


# ---- addresses ---------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("0x401000", "0x00401000"), ("401000", "0x00401000"), (0x401000, "0x00401000"),
    ("0X00401000", "0x00401000"), ("external:0xAB", "EXTERNAL:0xab"),
])
def test_normalize_address(raw, expected):
    assert normalize_address(raw) == expected


@pytest.mark.parametrize("bad", ["", "xyz", "0x", None, True, -1, 1.5, "0x" + "f" * 17])
def test_normalize_address_rejects(bad):
    with pytest.raises(InvalidAddressError):
        normalize_address(bad)


# ---- opening / manifest ---------------------------------------------------------

def test_open_ok(export):
    root, a = export
    an = Analysis.open(root)
    assert an.is_complete and not an.is_truncated
    assert an.function_count == 4
    assert an.metadata.program_name == "SimpleKeyGen"
    assert an.metadata.sha256 == "b" * 64
    assert an.problems == ()


def test_missing_directory(tmp_path):
    with pytest.raises(AnalysisNotFoundError):
        Analysis.open(tmp_path / "nope")


def test_missing_manifest_explains_why(tmp_path):
    (tmp_path / "x").mkdir()
    with pytest.raises(ManifestError, match="did not finish"):
        Analysis.open(tmp_path / "x")


def test_malformed_manifest(export):
    root, _ = export
    (root / "manifest.json").write_text("{not json")
    with pytest.raises(ManifestError, match="invalid JSON at line"):
        Analysis.open(root)


def test_manifest_wrong_shape(export):
    root, _ = export
    (root / "manifest.json").write_text(json.dumps({"schema_version": "0.1"}))
    with pytest.raises(ManifestError, match="complete"):
        Analysis.open(root)


def test_unsupported_schema(export):
    root, _ = export
    m = json.loads((root / "manifest.json").read_text())
    m["schema_version"] = "9.9"
    (root / "manifest.json").write_text(json.dumps(m))
    with pytest.raises(UnsupportedSchemaError):
        Analysis.open(root)


def test_non_utf8_manifest(export):
    root, _ = export
    (root / "manifest.json").write_bytes(b"\xff\xfe\x00")
    with pytest.raises(ManifestError, match="UTF-8"):
        Analysis.open(root)


# ---- incomplete extraction -----------------------------------------------------------

def _incomplete(tmp_path):
    root = tmp_path / "inc"
    make_export(root, complete=False,
                errors=[{"step": "strings", "traceback": "Traceback...\nAttributeError: boom"}])
    return root


def test_incomplete_rejected_by_default(tmp_path):
    with pytest.raises(IncompleteAnalysisError, match="boom") as ei:
        Analysis.open(_incomplete(tmp_path))
    assert ei.value.failed_steps == ("strings",)


def test_incomplete_allowed_uses_good_steps(tmp_path):
    an = Analysis.open(_incomplete(tmp_path), allow_incomplete=True)
    assert not an.is_complete
    assert an.get_function("0x401000").name == "main"      # functions step succeeded
    with pytest.raises(ArtifactUnavailableError):           # strings step failed
        an.get_strings()
    assert any("strings" in str(p) for p in an.problems)


def test_failed_functions_step_blocks_function_records(tmp_path):
    root = tmp_path / "f"
    make_export(root, complete=False, errors=[{"step": "functions", "traceback": "x"}])
    an = Analysis.open(root, allow_incomplete=True)
    with pytest.raises(ArtifactUnavailableError):
        an.get_function("0x401000")
    assert [i.name for i in an.get_imports()] == ["printf", "strcmp"]


def test_truncated_flag_and_hint(tmp_path):
    root = tmp_path / "t"
    make_export(root, truncated=True)
    an = Analysis.open(root)
    assert an.is_truncated
    with pytest.raises(FunctionNotFoundError, match="truncated"):
        an.get_function("0xdeadbeef")


def test_missing_artifact_lenient_vs_strict(export):
    root, _ = export
    (root / "strings.json").unlink()
    an = Analysis.open(root)
    assert any("strings.json" in str(p) for p in an.problems)
    with pytest.raises(MissingArtifactError):
        an.get_strings()
    with pytest.raises(MissingArtifactError):
        Analysis.open(root, strict=True)


# ---- functions, lazy loading ------------------------------------------------------------

def test_function_lookup_formats(export):
    root, a = export
    an = Analysis.open(root)
    for form in ("0x401000", "401000", 0x401000, "0x00401000"):
        assert an.get_function(form).name == "main"
    assert [f.name for f in an.find_functions(name_contains="KEY")] == ["check_key"]
    assert [f.name for f in an.find_functions(include_thunks=False)] == ["main", "check_key"]
    assert an.get_functions_by_name("main")[0].address == a["MAIN"]
    with pytest.raises(FunctionNotFoundError):
        an.get_function("0x999999")
    with pytest.raises(InvalidAddressError):
        an.get_function("nonsense")


def test_function_records_load_lazily(export, monkeypatch):
    root, a = export
    reads = []
    real = store_mod.read_json
    monkeypatch.setattr(store_mod, "read_json", lambda p, m: (reads.append(p.name), real(p, m))[1])
    an = Analysis.open(root)
    an.get_function("0x401000")  # index only
    assert not any(n.startswith("0x") for n in reads)
    detail = an.load_function("0x401100")
    assert reads.count("0x00401100.json") == 1
    assert not any(n.startswith("0x") and n != "0x00401100.json" for n in reads)
    an.load_function("0x401100")  # cached
    assert reads.count("0x00401100.json") == 1
    assert detail.instruction_at("0x00401110").text == "CALL strcmp"
    assert "PUSH EBP" in an.get_assembly_text("0x401100")
    assert an.get_decompiled_code("0x401100") == "/* c */"


def test_lru_eviction(export):
    root, a = export
    an = Analysis.open(root, function_cache_size=2)
    for addr in a.values():
        an.load_function(addr)
    assert an._store.cached_function_count == 2


def test_failed_decompilation_returns_none(export):
    root, a = export
    p = root / "functions" / "0x00401100.json"
    rec = json.loads(p.read_text())
    rec["decompiled"] = {"status": "failed", "c": None, "error": "timeout"}
    p.write_text(json.dumps(rec))
    an = Analysis.open(root)
    assert an.get_decompiled_code("0x401100") is None
    assert an.load_function("0x401100").decompilation.error == "timeout"


def test_malformed_function_file(export):
    root, _ = export
    (root / "functions" / "0x00401100.json").write_text('{"name": ')
    an = Analysis.open(root)
    with pytest.raises(MalformedJSONError):
        an.load_function("0x401100")
    assert an.load_function("0x401000").name == "main"  # others unaffected


def test_function_record_address_mismatch(export):
    root, _ = export
    p = root / "functions" / "0x00401100.json"
    rec = json.loads(p.read_text())
    rec["address"] = "0x00409999"
    p.write_text(json.dumps(rec))
    with pytest.raises(SchemaError, match="index says"):
        Analysis.open(root).load_function("0x401100")


def test_bad_instruction_skipped_or_strict(export):
    root, _ = export
    p = root / "functions" / "0x00401100.json"
    rec = json.loads(p.read_text())
    rec["assembly"].append({"address": "zzz", "text": "BAD"})
    p.write_text(json.dumps(rec))
    an = Analysis.open(root)
    assert len(an.load_function("0x401100").assembly) == 2
    assert any("assembly[2]" in str(pr) for pr in an.problems)
    with pytest.raises(SchemaError):
        Analysis.open(root, strict=True).load_function("0x401100")


def test_path_traversal_rejected(export):
    root, _ = export
    idx = json.loads((root / "functions.json").read_text())
    idx["functions"][0]["file"] = "../../etc/passwd"
    (root / "functions.json").write_text(json.dumps(idx))
    an = Analysis.open(root)
    with pytest.raises(UnsafePathError):
        an.load_function(idx["functions"][0]["address"])


@pytest.mark.skipif(os.name == "nt", reason="symlinks")
def test_symlink_escape_rejected(export, tmp_path):
    root, a = export
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    link = root / "functions" / "0x00401000.json"
    link.unlink()
    link.symlink_to(outside)
    with pytest.raises(UnsafePathError):
        Analysis.open(root).load_function("0x401000")


def test_size_limit(export):
    root, _ = export
    an = Analysis.open(root, max_file_bytes=100)
    with pytest.raises(ArtifactTooLargeError):
        an.load_function("0x401000")


# ---- graph, references, strings, imports --------------------------------------------------

def test_callers_and_callees(export):
    root, a = export
    an = Analysis.open(root)
    callers = an.get_callers(a["CHECK"])
    assert [(c.function.name, c.call_sites) for c in callers] == [("main", ("0x00401020",))]
    callees = an.get_callees(a["MAIN"])
    assert [(c.function.name, c.thunk_target) for c in callees] == [("printf", "printf"), ("check_key", None)]
    assert an.get_callers(a["MAIN"]) == []
    assert an.load_function(a["MAIN"]).indirect_call_sites == ("0x00401030",)
    with pytest.raises(FunctionNotFoundError):
        an.get_callers("0x123456")


def test_references(export):
    root, a = export
    an = Analysis.open(root)
    refs = an.get_references_to(a["STRCMP"])
    assert len(refs) == 2
    assert [r.from_address for r in an.get_references_to(a["STRCMP"], calls_only=True)] == ["0x00401110"]
    assert refs[0].from_function.name == "check_key" and refs[1].from_function is None


def test_strings(export):
    root, a = export
    an = Analysis.open(root)
    assert [s.value for s in an.get_strings(contains="key")] == ["Enter key:", "Valid key!"]
    assert len(an.get_strings(min_length=11)) == 1
    assert len(an.get_strings(limit=2)) == 2
    assert an.get_string_at("402020").value == "SECRET-1234"
    with pytest.raises(LookupFailedError):
        an.get_string_at("0x1")
    assert [s.value for s in an.get_strings_for_function(a["CHECK"])] == ["SECRET-1234"]
    main_strings = an.get_strings_for_function(a["MAIN"])
    assert {s.value for s in main_strings} == {"Enter key:", "Valid key!", "popular"}
    assert next(s for s in main_strings if s.value == "popular").references_truncated


def test_imports(export):
    root, a = export
    an = Analysis.open(root)
    assert [i.name for i in an.get_imports(library="MSVCRT.DLL")] == ["printf", "strcmp"]
    assert [i.name for i in an.get_imports(name_contains="STR")] == ["strcmp"]
    assert [i.name for i in an.get_imports_for_function(a["CHECK"])] == ["strcmp"]
    assert [i.name for i in an.get_imports_for_function(a["MAIN"])] == ["printf"]
    assert an.get_imports()[0].address.startswith("EXTERNAL:0x")


def test_malformed_string_entry_skipped(export):
    root, _ = export
    data = json.loads((root / "strings.json").read_text())
    data["strings"].insert(1, {"address": "0x00402005", "referenced_from": "oops"})
    (root / "strings.json").write_text(json.dumps(data))
    an = Analysis.open(root)
    assert len(an.get_strings()) == 4
    assert any("strings[1]" in str(p) for p in an.problems)
    with pytest.raises(SchemaError):
        Analysis.open(root, strict=True).get_strings()


def test_wrong_top_level_type(export):
    root, _ = export
    (root / "imports.json").write_text("[]")
    with pytest.raises(SchemaError, match="expected an object"):
        Analysis.open(root).get_imports()


def test_function_count_mismatch_warns(export):
    root, _ = export
    m = json.loads((root / "manifest.json").read_text())
    m["counts"]["functions"] = 99
    (root / "manifest.json").write_text(json.dumps(m))
    an = Analysis.open(root)
    an.function_count
    assert any("99" in str(p) for p in an.problems)


def test_cli(export, capsys):
    from binproof.cli import main
    root, a = export
    assert main(["inspect", str(root)]) == 0
    assert main(["callers", str(root), "0x401100"]) == 0
    assert "main" in capsys.readouterr().out
    assert main(["function", str(root), "0x999"]) == 2
    assert main(["inspect", str(root / "missing")]) == 2
