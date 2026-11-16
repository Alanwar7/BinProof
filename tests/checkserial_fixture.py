"""A reconstructed export of the SimpleKeyGen binary around checkSerial.

NOTE: this is NOT real Ghidra output. The real export was not available when this was written, so the
checkSerial instructions and decompiled code are reconstructed to be consistent with every address and
quote in tests/data/checkserial_result.json (a real Gemini analysis). Other functions (main, copyHelper,
dispatcher, import thunks) are invented to give the validator callers, callees, strings, imports and an
indirect call to check against. Replace with a real export when convenient.
"""

from pathlib import Path

from fixture import fref, func_record, write

SHA256 = "95d4e0ba3b1c804e6ad051ef09e242e916bf768661dee835bfec96576839d09c"  # as in the real result
CHECK, MAIN, COPY, DISP = "0x00101197", "0x00101260", "0x00101230", "0x00101300"
STRLEN, PRINTF, SCANF, STRCPY = "0x00101040", "0x00101050", "0x00101060", "0x00101070"

CHECKSERIAL_C = """undefined8 checkSerial(char *param_1)

{
  size_t sVar1;
  undefined8 uVar2;
  int local_1c;

  sVar1 = strlen(param_1);
  if (sVar1 == 0x10) {
    for (local_1c = 0; local_1c < 0x10; local_1c = local_1c + 2) {
      if ((int)param_1[local_1c] - (int)param_1[(long)local_1c + 1] != -1) {
        return 0xffffffff;
      }
    }
    uVar2 = 0;
  }
  else {
    uVar2 = 0xffffffff;
  }
  return uVar2;
}
"""

CHECKSERIAL_ASM = [
    ("0x00101197", "PUSH RBP"), ("0x00101198", "MOV RBP,RSP"), ("0x0010119b", "SUB RSP,0x30"),
    ("0x001011a0", "MOV qword ptr [RBP + -0x28],RDI"), ("0x001011a4", "MOV RAX,qword ptr [RBP + -0x28]"),
    ("0x001011a8", "MOV RDI,RAX"), ("0x001011ab", "CALL 0x00101040"), ("0x001011b0", "CMP RAX,0x10"),
    ("0x001011b4", "JZ 0x001011bd"), ("0x001011b6", "MOV EAX,0xffffffff"), ("0x001011bb", "JMP 0x00101222"),
    ("0x001011bd", "MOV dword ptr [RBP + -0x14],0x0"), ("0x001011c4", "JMP 0x00101207"),
    ("0x001011c6", "MOV EAX,dword ptr [RBP + -0x14]"), ("0x001011c9", "MOVSXD RDX,EAX"),
    ("0x001011cc", "MOV RAX,qword ptr [RBP + -0x28]"), ("0x001011d0", "ADD RAX,RDX"),
    ("0x001011d3", "MOVZX EAX,byte ptr [RAX]"), ("0x001011d6", "MOVSX EDX,AL"),
    ("0x001011ef", "SUB EDX,EAX"), ("0x001011f1", "MOV EAX,EDX"), ("0x001011f3", "CMP EAX,-0x1"),
    ("0x001011f6", "JZ 0x001011ff"), ("0x001011f8", "MOV EAX,0xffffffff"), ("0x001011fd", "JMP 0x00101222"),
    ("0x001011ff", "ADD dword ptr [RBP + -0x14],0x2"), ("0x00101207", "CMP dword ptr [RBP + -0x14],0xf"),
    ("0x0010120b", "JLE 0x001011c6"), ("0x0010120d", "JMP 0x0010121a"),
    ("0x0010121a", "MOV EAX,0x0"), ("0x0010121f", "JMP 0x00101222"), ("0x00101222", "LEAVE"),
    ("0x00101223", "RET"),
]


def _site(site, target, name, thunk=True):
    return {"site": site, "target": target, "target_name": name, "target_is_external": False,
            "target_is_thunk": thunk, "thunk_target": name if thunk else None,
            "thunk_target_is_external": True if thunk else None}


def make_checkserial_export(root: Path, *, complete=True, errors=()):
    root.mkdir(parents=True, exist_ok=True)

    def thunk(addr, name):
        r = func_record(name, addr, [(addr, "JMP qword ptr [0x00104018]")], decomp="/* thunk */")
        r.update(is_thunk=True, parameters=[], size_bytes=6)
        return r

    check = func_record("checkSerial", CHECK, CHECKSERIAL_ASM, decomp=CHECKSERIAL_C,
                        call_sites=[_site("0x001011ab", STRLEN, "strlen")], callers=[fref("main", MAIN)])
    check.update(signature="undefined checkSerial()", parameters=[], size_bytes=0x8d)

    main = func_record("main", MAIN, [
        ("0x00101260", "PUSH RBP"), ("0x00101275", "LEA RDI,[0x00102004]"), ("0x0010127a", "CALL 0x00101050"),
        ("0x00101291", "CALL 0x00101060"), ("0x001012a5", "CALL checkSerial"),
        ("0x001012b9", "LEA RDI,[0x00102013]"), ("0x001012cb", "LEA RDI,[0x00102021]")],
        call_sites=[_site("0x0010127a", PRINTF, "printf"), _site("0x00101291", SCANF, "scanf"),
                    _site("0x001012a5", CHECK, "checkSerial", thunk=False)],
        decomp="int main(void) { printf(\"Enter serial: \"); scanf(); checkSerial(buf); return 0; }")
    main.update(size_bytes=0x80, parameters=[])
    copy = func_record("copyHelper", COPY, [("0x00101230", "PUSH RBP"), ("0x00101240", "CALL 0x00101070")],
                       call_sites=[_site("0x00101240", STRCPY, "strcpy")], decomp="void copyHelper(void){strcpy();}")
    copy.update(size_bytes=0x20, parameters=[])
    disp = func_record("dispatcher", DISP, [("0x00101300", "PUSH RBP"), ("0x00101308", "CALL RAX")],
                       indirect=["0x00101308"], decomp="void dispatcher(void){(*fp)();}")
    disp.update(size_bytes=0x20, parameters=[])
    records = {CHECK: check, MAIN: main, COPY: copy, DISP: disp, STRLEN: thunk(STRLEN, "strlen"),
               PRINTF: thunk(PRINTF, "printf"), SCANF: thunk(SCANF, "scanf"), STRCPY: thunk(STRCPY, "strcpy")}
    for a, r in records.items():
        write(root / "functions" / ("%s.json" % a), r)

    write(root / "functions.json", {"truncated": False, "functions": [
        {"name": r["name"], "address": a, "size_bytes": r["size_bytes"], "instruction_count": r["instruction_count"],
         "signature": r["signature"], "is_thunk": r["is_thunk"], "caller_count": 0, "callee_count": len(r["call_sites"]),
         "decompile_status": "ok", "file": "functions/%s.json" % a} for a, r in sorted(records.items())]})

    def edge(frm, name, site, to, to_name, thunk_target):
        return {"from_function": frm, "from_name": name, "call_site": site, "to": to, "to_name": to_name,
                "to_is_external": False, "thunk_target": thunk_target}
    write(root / "call_graph.json", {"truncated": False, "nodes": [{"address": a, "name": r["name"]}
                                                                    for a, r in records.items()], "edges": [
        edge(MAIN, "main", "0x0010127a", PRINTF, "printf", "printf"),
        edge(MAIN, "main", "0x00101291", SCANF, "scanf", "scanf"),
        edge(MAIN, "main", "0x001012a5", CHECK, "checkSerial", None),
        edge(CHECK, "checkSerial", "0x001011ab", STRLEN, "strlen", "strlen"),
        edge(COPY, "copyHelper", "0x00101240", STRCPY, "strcpy", "strcpy")]})

    def call_ref(frm, name, from_addr):
        return {"from": from_addr, "from_function": fref(name, frm), "type": "UNCONDITIONAL_CALL", "is_call": True}
    refs = {a: [] for a in records}
    refs[CHECK] = [call_ref(MAIN, "main", "0x001012a5")]
    refs[STRLEN] = [call_ref(CHECK, "checkSerial", "0x001011ab")]
    refs[PRINTF] = [call_ref(MAIN, "main", "0x0010127a")]
    refs[SCANF] = [call_ref(MAIN, "main", "0x00101291")]
    refs[STRCPY] = [call_ref(COPY, "copyHelper", "0x00101240")]
    write(root / "xrefs.json", {"truncated": False, "xrefs": {
        a: {"name": records[a]["name"], "references_to": v} for a, v in refs.items()}})

    def s(addr, val, site):
        return {"address": addr, "value": val, "length": len(val) + 1, "data_type": "string",
                "reference_count": 1, "referenced_from": [{"from": site, "from_function": fref("main", MAIN)}]}
    write(root / "strings.json", {"strings": [
        s("0x00102004", "Enter serial: ", "0x00101275"), s("0x00102013", "Valid serial!", "0x001012b9"),
        s("0x00102021", "Invalid serial", "0x001012cb")]})

    def imp(name, thunk_addr, user, user_name, site):
        return {"library": "<EXTERNAL>", "name": name, "original_name": None, "address": "EXTERNAL:0x%x" % (0x10 + len(name)),
                "thunks": [thunk_addr], "other_references": [],
                "call_sites": [{"from": site, "from_function": fref(user_name, user), "type": "UNCONDITIONAL_CALL",
                                "is_call": True}]}
    write(root / "imports.json", {"imports": [
        imp("strlen", STRLEN, CHECK, "checkSerial", "0x001011ab"), imp("printf", PRINTF, MAIN, "main", "0x0010127a"),
        imp("scanf", SCANF, MAIN, "main", "0x00101291"), imp("strcpy", STRCPY, COPY, "copyHelper", "0x00101240")]})

    write(root / "metadata.json", {
        "schema_version": "0.1", "program_name": "SimpleKeyGen", "executable_path": "/tmp/SimpleKeyGen",
        "executable_format": "Executable and Linking Format (ELF)", "hashes": {"md5": None, "sha256": SHA256},
        "language_id": "x86:LE:64:default", "processor": "x86", "big_endian": False, "pointer_size_bytes": 8,
        "compiler_spec": "gcc", "image_base": "0x00100000", "entry_points": [MAIN], "ghidra_version": "12.0",
        "memory_blocks": []})
    write(root / "manifest.json", {
        "schema_version": "0.1", "program_name": "SimpleKeyGen", "complete": complete,
        "counts": {"functions": len(records), "functions_truncated": False, "strings": 3, "imports": 4},
        "max_functions": 0, "errors": list(errors), "elapsed_seconds": 2.0,
        "files": ["metadata.json", "functions.json", "functions/", "strings.json", "imports.json",
                  "xrefs.json", "call_graph.json"]})
