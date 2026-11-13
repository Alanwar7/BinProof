#!/usr/bin/env python3
"""BinaryLens step 1: run Ghidra headless on a binary and export JSON.

    python run_analysis.py ./samples/target.exe
    python run_analysis.py ./target --ghidra-dir ~/ghidra_12.0_PUBLIC --max-functions 200

Engines:
  pyghidra  (default) Ghidra 11.3+/12: runs the export script on CPython 3.
            Needs:  pip install pyghidra   (+ JDK 21, GHIDRA_INSTALL_DIR)
  headless  classic analyzeHeadless + Jython. Only for Ghidra <= 11.x.

Output lands in <out>/<name>-<sha256[:12]>/ (metadata.json, functions.json,
functions/*.json, strings.json, imports.json, xrefs.json, call_graph.json,
manifest.json). The target is only analyzed, never executed.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent / "ghidra_scripts"
SCRIPT_NAME = "ExportBinaryJSON.py"


def resolve_ghidra_dir(arg):
    root = arg or os.environ.get("GHIDRA_INSTALL_DIR")
    if not root:
        sys.exit("error: pass --ghidra-dir or set GHIDRA_INSTALL_DIR")
    root = Path(root).expanduser().resolve()
    if not (root / "support").is_dir():
        sys.exit("error: %s does not look like a Ghidra install dir" % root)
    return root


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run_pyghidra(ghidra_dir, binary, outdir, max_functions, project_dir):
    os.environ["GHIDRA_INSTALL_DIR"] = str(ghidra_dir)
    try:
        import pyghidra
    except ImportError:
        sys.exit("error: pyghidra not installed. Run: pip install pyghidra")
    try:
        pyghidra.run_script(
            str(binary), str(SCRIPT_DIR / SCRIPT_NAME),
            project_location=str(project_dir), project_name="binarylens",
            script_args=[str(outdir), str(max_functions)],
        )
        return 0
    except Exception:
        traceback.print_exc()
        return 1


def run_headless(ghidra_dir, binary, outdir, max_functions, project_dir, timeout):
    exe = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    cmd = [
        str(ghidra_dir / "support" / exe), str(project_dir), "binarylens",
        "-import", str(binary), "-overwrite",
        "-analysisTimeoutPerFile", str(timeout),
        "-scriptPath", str(SCRIPT_DIR),
        "-postScript", SCRIPT_NAME, str(outdir), str(max_functions),
    ]
    log_path = outdir / "ghidra.log"
    with open(log_path, "w") as log:
        rc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT).returncode
    print("[binarylens] analyzeHeadless log: %s" % log_path)
    return rc


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary", type=Path)
    ap.add_argument("--engine", choices=["pyghidra", "headless"], default="pyghidra")
    ap.add_argument("--ghidra-dir", help="Ghidra install dir (default: $GHIDRA_INSTALL_DIR)")
    ap.add_argument("--out", type=Path, default=Path("output"), help="base output dir")
    ap.add_argument("--max-functions", type=int, default=0,
                    help="cap exported functions (0 = all); useful while developing")
    ap.add_argument("--timeout", type=int, default=900,
                    help="auto-analysis timeout in seconds (headless engine only)")
    ap.add_argument("--project-dir", type=Path,
                    help="keep the Ghidra project here (default: temp dir, deleted after)")
    args = ap.parse_args()

    binary = args.binary.resolve()
    if not binary.is_file():
        sys.exit("error: %s is not a file" % binary)
    ghidra_dir = resolve_ghidra_dir(args.ghidra_dir)

    digest = sha256_of(binary)
    outdir = (args.out / ("%s-%s" % (binary.name, digest[:12]))).resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    # Clear stale results so an old manifest can't be mistaken for this run.
    (outdir / "manifest.json").unlink(missing_ok=True)
    shutil.rmtree(outdir / "functions", ignore_errors=True)

    temp_project = args.project_dir is None
    project_dir = Path(tempfile.mkdtemp(prefix="binarylens_")) if temp_project \
        else args.project_dir.resolve()
    project_dir.mkdir(parents=True, exist_ok=True)

    print("[binarylens] sha256 %s (engine: %s)" % (digest, args.engine))
    try:
        if args.engine == "pyghidra":
            rc = run_pyghidra(ghidra_dir, binary, outdir, args.max_functions, project_dir)
        else:
            rc = run_headless(ghidra_dir, binary, outdir, args.max_functions,
                              project_dir, args.timeout)
    finally:
        if temp_project:
            shutil.rmtree(project_dir, ignore_errors=True)

    # Don't trust exit codes: verify the manifest the export script writes last.
    manifest_path = outdir / "manifest.json"
    if rc != 0 or not manifest_path.is_file():
        sys.exit("FAILED: no manifest written (exit code %s)." % rc)
    manifest = json.loads(manifest_path.read_text())
    if not manifest.get("complete"):
        for err in manifest.get("errors", []):
            print("--- step '%s' failed ---\n%s" % (err["step"], err["traceback"]))
        sys.exit("FAILED: export incomplete. See %s" % manifest_path)

    c = manifest["counts"]
    print("[binarylens] OK in %.1fs: %s functions%s, %s strings, %s imports"
          % (manifest["elapsed_seconds"], c.get("functions"),
             " (truncated)" if c.get("functions_truncated") else "",
             c.get("strings"), c.get("imports")))
    print("[binarylens] output: %s" % outdir)


if __name__ == "__main__":
    main()
