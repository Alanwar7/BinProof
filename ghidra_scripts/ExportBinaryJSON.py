# BinaryLens: export the analyzed program to structured JSON.
#
# Run as a -postScript so Ghidra's auto-analysis has already finished:
#   ExportBinaryJSON.py <output_dir> [max_functions]
#
# @category BinaryLens
#
# Written to run under both Jython 2.7 (Ghidra 10/11 analyzeHeadless) and
# Python 3 (PyGhidra): no f-strings, no py3-only syntax, ASCII-safe JSON.
# `currentProgram`, `getScriptArgs`, `println` etc. are injected by Ghidra.

import json
import os
import time
import traceback

from ghidra.app.decompiler import DecompInterface
from ghidra.framework import Application
from ghidra.util.task import ConsoleTaskMonitor

SCHEMA_VERSION = "0.1"
DECOMPILE_TIMEOUT_SECONDS = 60
MAX_REFS_PER_STRING = 50

try:
    text_type = unicode  # noqa: F821  (Jython / Python 2)
except NameError:
    text_type = str


# ---------------------------------------------------------------- helpers

def txt(value):
    """Java/Ghidra object -> plain text (or None)."""
    if value is None:
        return None
    return text_type(value)


def addr_str(addr):
    """Stable address format used everywhere in the JSON output."""
    if addr is None:
        return None
    if addr.isExternalAddress():
        return "EXTERNAL:0x%x" % addr.getOffset()
    return "0x%08x" % addr.getOffset()


def write_json(path, obj):
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=2)


def func_ref(func):
    if func is None:
        return None
    return {"name": txt(func.getName()), "address": addr_str(func.getEntryPoint())}


def ref_info(program, ref):
    fn = program.getFunctionManager().getFunctionContaining(ref.getFromAddress())
    rtype = ref.getReferenceType()
    return {
        "from": addr_str(ref.getFromAddress()),
        "from_function": func_ref(fn),
        "type": txt(rtype),
        "is_call": bool(rtype.isCall()),
    }


def resolve_target(program, to_addr):
    """Describe what a call/jump reference points at."""
    fm = program.getFunctionManager()
    info = {
        "target": addr_str(to_addr),
        "target_name": None,
        "target_is_external": bool(to_addr.isExternalAddress()),
        "target_is_thunk": False,
        "thunk_target": None,
        "thunk_target_is_external": None,
    }
    callee = fm.getFunctionAt(to_addr)
    if callee is not None:
        info["target_name"] = txt(callee.getName())
        info["target_is_external"] = bool(callee.isExternal())
        if callee.isThunk():
            info["target_is_thunk"] = True
            final = callee.getThunkedFunction(True)
            if final is not None:
                info["thunk_target"] = txt(final.getName())
                info["thunk_target_is_external"] = bool(final.isExternal())
    else:
        sym = program.getSymbolTable().getPrimarySymbol(to_addr)
        if sym is not None:
            info["target_name"] = txt(sym.getName())
    return info


# ---------------------------------------------------------------- exporters

def export_metadata(program):
    mem = program.getMemory()
    blocks = []
    for b in mem.getBlocks():
        blocks.append({
            "name": txt(b.getName()),
            "start": addr_str(b.getStart()),
            "end": addr_str(b.getEnd()),
            "size": b.getSize(),
            "read": bool(b.isRead()),
            "write": bool(b.isWrite()),
            "execute": bool(b.isExecute()),
            "initialized": bool(b.isInitialized()),
        })

    entry_points = []
    for a in program.getSymbolTable().getExternalEntryPointIterator():
        entry_points.append(addr_str(a))

    hashes = {"md5": None, "sha256": None}
    try:
        hashes["md5"] = txt(program.getExecutableMD5())
    except Exception:
        pass
    try:
        hashes["sha256"] = txt(program.getExecutableSHA256())
    except Exception:
        pass  # older Ghidra builds don't have this

    lang = program.getLanguage()
    return {
        "schema_version": SCHEMA_VERSION,
        "program_name": txt(program.getName()),
        "executable_path": txt(program.getExecutablePath()),
        "executable_format": txt(program.getExecutableFormat()),
        "hashes": hashes,
        "language_id": txt(program.getLanguageID()),
        "processor": txt(lang.getProcessor()),
        "big_endian": bool(lang.isBigEndian()),
        "pointer_size_bytes": program.getDefaultPointerSize(),
        "compiler_spec": txt(program.getCompilerSpec().getCompilerSpecID()),
        "image_base": addr_str(program.getImageBase()),
        "entry_points": entry_points,
        "memory_blocks": blocks,
        "ghidra_version": txt(Application.getApplicationVersion()),
    }


def export_functions(program, outdir, max_functions):
    """Writes functions.json, functions/<addr>.json, xrefs.json, call_graph.json.

    Returns (function_count, truncated).
    """
    fm = program.getFunctionManager()
    listing = program.getListing()
    ref_mgr = program.getReferenceManager()
    monitor = ConsoleTaskMonitor()

    ifc = DecompInterface()
    ifc.openProgram(program)

    func_dir = os.path.join(outdir, "functions")
    if not os.path.isdir(func_dir):
        os.makedirs(func_dir)

    index = []
    xrefs = {}
    edges = []
    count = 0
    truncated = False

    try:
        for f in fm.getFunctions(True):
            if max_functions and count >= max_functions:
                truncated = True
                break
            count += 1

            entry = f.getEntryPoint()
            entry_s = addr_str(entry)
            body = f.getBody()

            # --- disassembly + outgoing calls (every call carries its site address)
            instructions = []
            call_sites = []
            indirect_call_sites = []
            for ins in listing.getInstructions(body, True):
                raw = "".join("%02x" % (int(b) & 0xff) for b in ins.getBytes())
                instructions.append({
                    "address": addr_str(ins.getAddress()),
                    "bytes": raw,
                    "text": txt(ins.toString()),
                })
                flow = ins.getFlowType()
                found_call_ref = False
                for ref in ins.getReferencesFrom():
                    if ref.getReferenceType().isCall():
                        found_call_ref = True
                        site = {"site": addr_str(ins.getAddress())}
                        site.update(resolve_target(program, ref.getToAddress()))
                        call_sites.append(site)
                        edges.append({
                            "from_function": entry_s,
                            "from_name": txt(f.getName()),
                            "call_site": site["site"],
                            "to": site["target"],
                            "to_name": site["target_name"],
                            "to_is_external": site["target_is_external"],
                            "thunk_target": site["thunk_target"],
                        })
                if flow.isCall() and not found_call_ref:
                    # e.g. `call rax` - Ghidra could not resolve a target
                    indirect_call_sites.append(addr_str(ins.getAddress()))

            # --- incoming references (xrefs)
            incoming = []
            callers = {}
            for ref in ref_mgr.getReferencesTo(entry):
                info = ref_info(program, ref)
                incoming.append(info)
                if info["is_call"] and info["from_function"] is not None:
                    callers[info["from_function"]["address"]] = info["from_function"]
            xrefs[entry_s] = {"name": txt(f.getName()), "references_to": incoming}

            # --- decompilation
            decomp = {"status": "failed", "c": None, "error": None}
            try:
                res = ifc.decompileFunction(f, DECOMPILE_TIMEOUT_SECONDS, monitor)
                if res.decompileCompleted():
                    decomp["status"] = "ok"
                    decomp["c"] = txt(res.getDecompiledFunction().getC())
                else:
                    decomp["error"] = txt(res.getErrorMessage())
            except Exception as exc:
                decomp["error"] = txt(exc)

            params = []
            for p in f.getParameters():
                params.append({
                    "name": txt(p.getName()),
                    "type": txt(p.getDataType().getName()),
                    "storage": txt(p.getVariableStorage()),
                })

            rel_file = "functions/%s.json" % entry_s
            record = {
                "name": txt(f.getName()),
                "address": entry_s,
                "end_address": addr_str(body.getMaxAddress()),
                "size_bytes": body.getNumAddresses(),
                "instruction_count": len(instructions),
                "signature": txt(f.getPrototypeString(False, False)),
                "return_type": txt(f.getReturnType().getName()),
                "parameters": params,
                "calling_convention": txt(f.getCallingConventionName()),
                "namespace": txt(f.getParentNamespace().getName()),
                "is_thunk": bool(f.isThunk()),
                "callers": sorted(callers.values(), key=lambda c: c["address"]),
                "call_sites": call_sites,
                "indirect_call_sites": indirect_call_sites,
                "decompiled": decomp,
                "assembly": instructions,
            }
            write_json(os.path.join(outdir, rel_file), record)

            index.append({
                "name": record["name"],
                "address": entry_s,
                "size_bytes": record["size_bytes"],
                "instruction_count": record["instruction_count"],
                "signature": record["signature"],
                "is_thunk": record["is_thunk"],
                "caller_count": len(callers),
                "callee_count": len(call_sites),
                "decompile_status": decomp["status"],
                "file": rel_file,
            })

            if count % 100 == 0:
                println("[BinaryLens] exported %d functions..." % count)
    finally:
        ifc.dispose()

    write_json(os.path.join(outdir, "functions.json"),
               {"truncated": truncated, "functions": index})
    write_json(os.path.join(outdir, "xrefs.json"), {"truncated": truncated, "xrefs": xrefs})
    write_json(os.path.join(outdir, "call_graph.json"), {
        "truncated": truncated,
        "nodes": [{"address": i["address"], "name": i["name"]} for i in index],
        "edges": edges,
    })
    return count, truncated


def export_strings(program, outdir):
    fm = program.getFunctionManager()
    listing = program.getListing()
    out = []
    for d in listing.getDefinedData(True):
        if not d.hasStringValue():
            continue
        refs = []
        total_refs = 0
        for ref in d.getReferenceIteratorTo():
            total_refs += 1
            if len(refs) < MAX_REFS_PER_STRING:
                fn = fm.getFunctionContaining(ref.getFromAddress())
                refs.append({
                    "from": addr_str(ref.getFromAddress()),
                    "from_function": func_ref(fn),
                })
        out.append({
            "address": addr_str(d.getAddress()),
            "value": txt(d.getValue()),
            "length": d.getLength(),
            "data_type": txt(d.getDataType().getName()),
            "reference_count": total_refs,
            "referenced_from": refs,
        })
    write_json(os.path.join(outdir, "strings.json"), {"strings": out})
    return len(out)


def export_imports(program, outdir):
    fm = program.getFunctionManager()
    ref_mgr = program.getReferenceManager()
    ext_mgr = program.getExternalManager()

    # Map (library, label) -> thunk functions that forward to it. Most calls to
    # imports go through these thunks, so they hold the real call sites.
    thunks = {}
    for f in fm.getFunctions(True):
        if not f.isThunk():
            continue
        final = f.getThunkedFunction(True)
        if final is None or not final.isExternal():
            continue
        loc = final.getExternalLocation()
        if loc is None:
            continue
        key = (txt(loc.getLibraryName()), txt(loc.getLabel()))
        thunks.setdefault(key, []).append(f)

    out = []
    for lib in ext_mgr.getExternalLibraryNames():
        it = ext_mgr.getExternalLocations(lib)
        while it.hasNext():
            loc = it.next()
            lib_name = txt(lib)
            label = txt(loc.getLabel())

            thunk_addrs = []
            call_sites = []
            for t in thunks.get((lib_name, label), []):
                thunk_addrs.append(addr_str(t.getEntryPoint()))
                for ref in ref_mgr.getReferencesTo(t.getEntryPoint()):
                    info = ref_info(program, ref)
                    if info["is_call"]:
                        call_sites.append(info)

            data_refs = []
            sym = loc.getSymbol()
            if sym is not None:
                for ref in sym.getReferences():
                    data_refs.append(ref_info(program, ref))

            out.append({
                "library": lib_name,
                "name": label,
                "original_name": txt(loc.getOriginalImportedName()),
                "address": addr_str(loc.getAddress()),
                "thunks": thunk_addrs,
                "call_sites": call_sites,
                "other_references": data_refs,
            })
    write_json(os.path.join(outdir, "imports.json"), {"imports": out})
    return len(out)


# ---------------------------------------------------------------- main

def main():
    # str() because under PyGhidra/JPype these arrive as Java strings
    args = [str(a) for a in getScriptArgs()]  # noqa: F821
    if len(args) < 1:
        println("[BinaryLens] usage: ExportBinaryJSON.py <output_dir> [max_functions]")
        return
    outdir = args[0]
    max_functions = int(args[1]) if len(args) > 1 else 0
    if not os.path.isdir(outdir):
        os.makedirs(outdir)

    program = currentProgram  # noqa: F821
    started = time.time()
    counts = {}
    errors = []

    steps = [
        ("metadata", lambda: write_json(os.path.join(outdir, "metadata.json"),
                                        export_metadata(program))),
        ("functions", lambda: counts.update(
            zip(("functions", "functions_truncated"),
                export_functions(program, outdir, max_functions)))),
        ("strings", lambda: counts.update(strings=export_strings(program, outdir))),
        ("imports", lambda: counts.update(imports=export_imports(program, outdir))),
    ]
    for name, step in steps:
        try:
            println("[BinaryLens] exporting %s ..." % name)
            step()
        except Exception:
            errors.append({"step": name, "traceback": traceback.format_exc()})
            println("[BinaryLens] ERROR in %s:\n%s" % (name, traceback.format_exc()))

    # Written last: its presence with complete=true is how the runner knows
    # the export finished (analyzeHeadless exits 0 even if this script fails).
    write_json(os.path.join(outdir, "manifest.json"), {
        "schema_version": SCHEMA_VERSION,
        "program_name": txt(program.getName()),
        "complete": len(errors) == 0,
        "counts": counts,
        "max_functions": max_functions,
        "errors": errors,
        "elapsed_seconds": round(time.time() - started, 2),
        "files": ["metadata.json", "functions.json", "functions/", "strings.json",
                  "imports.json", "xrefs.json", "call_graph.json"],
    })
    println("[BinaryLens] done -> %s" % outdir)


main()
