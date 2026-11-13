"""Builds a small export directory that mirrors what ExportBinaryJSON.py writes (schema 0.1)."""

import json
from pathlib import Path


def fref(name, addr):
    return {"name": name, "address": addr}


def write(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2))


def func_record(name, addr, asm, call_sites=(), callers=(), decomp="/* c */", indirect=()):
    return {
        "name": name, "address": addr, "end_address": addr, "size_bytes": 4 * len(asm),
        "instruction_count": len(asm), "signature": "int %s(void)" % name,
        "return_type": "int", "parameters": [{"name": "a", "type": "int", "storage": "ECX"}],
        "calling_convention": "__cdecl", "namespace": "Global", "is_thunk": False,
        "callers": list(callers), "call_sites": list(call_sites),
        "indirect_call_sites": list(indirect),
        "decompiled": {"status": "ok", "c": decomp, "error": None},
        "assembly": [{"address": a, "bytes": "90", "text": t} for a, t in asm],
    }


def make_export(root: Path, *, complete=True, errors=(), truncated=False):
    """main(0x401000) -> check_key(0x401100) -> strcmp thunk; main -> printf thunk."""
    MAIN, CHECK, PRINTF, STRCMP = "0x00401000", "0x00401100", "0x00401300", "0x00401310"
    root.mkdir(parents=True, exist_ok=True)

    site_printf = {"site": "0x00401010", "target": PRINTF, "target_name": "printf",
                   "target_is_external": False, "target_is_thunk": True,
                   "thunk_target": "printf", "thunk_target_is_external": True}
    site_check = {"site": "0x00401020", "target": CHECK, "target_name": "check_key",
                  "target_is_external": False, "target_is_thunk": False,
                  "thunk_target": None, "thunk_target_is_external": None}
    site_strcmp = {"site": "0x00401110", "target": STRCMP, "target_name": "strcmp",
                   "target_is_external": False, "target_is_thunk": True,
                   "thunk_target": "strcmp", "thunk_target_is_external": True}

    records = {
        MAIN: func_record("main", MAIN, [("0x00401000", "PUSH EBP"), ("0x00401010", "CALL printf"),
                                         ("0x00401020", "CALL check_key")],
                          call_sites=[site_printf, site_check], indirect=["0x00401030"]),
        CHECK: func_record("check_key", CHECK, [("0x00401100", "PUSH EBP"), ("0x00401110", "CALL strcmp")],
                           call_sites=[site_strcmp], callers=[fref("main", MAIN)]),
        PRINTF: func_record("printf", PRINTF, [("0x00401300", "JMP dword ptr [IAT]")]),
        STRCMP: func_record("strcmp", STRCMP, [("0x00401310", "JMP dword ptr [IAT]")]),
    }
    records[PRINTF]["is_thunk"] = records[STRCMP]["is_thunk"] = True
    for a, r in records.items():
        write(root / "functions" / ("%s.json" % a), r)

    index = [{"name": r["name"], "address": a, "size_bytes": r["size_bytes"],
              "instruction_count": r["instruction_count"], "signature": r["signature"],
              "is_thunk": r["is_thunk"], "caller_count": len(r["callers"]),
              "callee_count": len(r["call_sites"]), "decompile_status": "ok",
              "file": "functions/%s.json" % a} for a, r in records.items()]
    write(root / "functions.json", {"truncated": truncated, "functions": index})

    edges = [
        {"from_function": MAIN, "from_name": "main", "call_site": "0x00401010", "to": PRINTF,
         "to_name": "printf", "to_is_external": False, "thunk_target": "printf"},
        {"from_function": MAIN, "from_name": "main", "call_site": "0x00401020", "to": CHECK,
         "to_name": "check_key", "to_is_external": False, "thunk_target": None},
        {"from_function": CHECK, "from_name": "check_key", "call_site": "0x00401110", "to": STRCMP,
         "to_name": "strcmp", "to_is_external": False, "thunk_target": "strcmp"},
    ]
    write(root / "call_graph.json", {"truncated": truncated,
          "nodes": [{"address": a, "name": r["name"]} for a, r in records.items()], "edges": edges})

    def xr(frm, fn, t="UNCONDITIONAL_CALL"):
        return {"from": frm, "from_function": fn, "type": t, "is_call": True}
    write(root / "xrefs.json", {"truncated": truncated, "xrefs": {
        MAIN: {"name": "main", "references_to": []},
        CHECK: {"name": "check_key", "references_to": [xr("0x00401020", fref("main", MAIN))]},
        PRINTF: {"name": "printf", "references_to": [xr("0x00401010", fref("main", MAIN))]},
        STRCMP: {"name": "strcmp", "references_to": [xr("0x00401110", fref("check_key", CHECK)),
                 {"from": "0x00403000", "from_function": None, "type": "DATA", "is_call": False}]},
    }})

    def s(addr, val, refs, count=None):
        return {"address": addr, "value": val, "length": len(val) + 1, "data_type": "string",
                "reference_count": len(refs) if count is None else count,
                "referenced_from": [{"from": f, "from_function": fn} for f, fn in refs]}
    write(root / "strings.json", {"strings": [
        s("0x00402000", "Enter key:", [("0x00401005", fref("main", MAIN))]),
        s("0x00402010", "Valid key!", [("0x00401015", fref("main", MAIN))]),
        s("0x00402020", "SECRET-1234", [("0x00401105", fref("check_key", CHECK))]),
        s("0x00402030", "popular", [("0x00401006", fref("main", MAIN))], count=500),
    ]})

    def imp(name, thunk, site, fn):
        return {"library": "msvcrt.dll", "name": name, "original_name": None,
                "address": "EXTERNAL:0x%x" % (0x1000 + len(name)), "thunks": [thunk],
                "call_sites": [{"from": site, "from_function": fn, "type": "UNCONDITIONAL_CALL", "is_call": True}],
                "other_references": []}
    write(root / "imports.json", {"imports": [
        imp("printf", PRINTF, "0x00401010", fref("main", MAIN)),
        imp("strcmp", STRCMP, "0x00401110", fref("check_key", CHECK)),
    ]})

    write(root / "metadata.json", {
        "schema_version": "0.1", "program_name": "SimpleKeyGen", "executable_path": "/tmp/SimpleKeyGen",
        "executable_format": "Portable Executable (PE)", "hashes": {"md5": "a" * 32, "sha256": "b" * 64},
        "language_id": "x86:LE:32:default", "processor": "x86", "big_endian": False,
        "pointer_size_bytes": 4, "compiler_spec": "windows", "image_base": "0x00400000",
        "entry_points": [MAIN], "ghidra_version": "12.0",
        "memory_blocks": [{"name": ".text", "start": "0x00401000", "end": "0x00401fff", "size": 4096,
                           "read": True, "write": False, "execute": True, "initialized": True}]})

    counts = {"functions": len(records), "functions_truncated": truncated, "strings": 4, "imports": 2}
    write(root / "manifest.json", {
        "schema_version": "0.1", "program_name": "SimpleKeyGen", "complete": complete,
        "counts": counts, "max_functions": 2 if truncated else 0, "errors": list(errors),
        "elapsed_seconds": 1.5,
        "files": ["metadata.json", "functions.json", "functions/", "strings.json",
                  "imports.json", "xrefs.json", "call_graph.json"]})
    return {"MAIN": MAIN, "CHECK": CHECK, "PRINTF": PRINTF, "STRCMP": STRCMP}
