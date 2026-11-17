# BinProof

BinProof is an open-source, AI-assisted reverse engineering tool built around Ghidra. It extracts and organizes binary information, including functions, assembly, decompiled code, strings, imports, cross-references and call relationships. It uses this structured data to help AI models analyze function behavior and generate evidence-backed explanations, with the goal of making binary analysis more accessible, structured and reliable.

## Milestone 1: extraction
```bash
pip install pyghidra            # Ghidra 12+, needs JDK 21
export GHIDRA_INSTALL_DIR=/path/to/ghidra
python run_analysis.py ./samples/target.exe [--max-functions 50]
```
Writes `output/<name>-<sha256[:12]>/` (manifest.json last; `complete: true` means it finished).

## Milestone 2: loading and querying
```python
from binproof import Analysis
a = Analysis.open("output/target.exe-95d4e0ba3b1c")   # allow_incomplete=True / strict=True optional
a.get_function("0x401000")            # summary (cheap)
a.load_function("0x401000")           # assembly + decompiled code, loaded on demand
a.get_callers("0x401100"); a.get_callees("0x401000")
a.get_references_to("0x401310"); a.get_strings(contains="key")
a.get_imports(library="kernel32.dll"); a.get_imports_for_function("0x401100")
a.problems                            # non-fatal issues found while loading
```
CLI: `python -m binproof inspect|functions|function|callers|callees|xrefs|strings|imports <export-dir>`

Tests: `pip install -e '.[dev]' && pytest` (expect 332 passed, 3 xfailed)

Strings, names and decompiled code come from the analyzed binary. Treat them as untrusted data.

## Milestone 3: AI function analysis
```bash
pip install -e '.[ai]'                       # adds pydantic
export BINPROOF_PROVIDER=anthropic           # anthropic | openai | ollama | openai-compatible
export BINPROOF_MODEL=<model name>           # no default on purpose
export ANTHROPIC_API_KEY=...                 # or OPENAI_API_KEY, or BINPROOF_API_KEY; never put keys in code
python -m binproof analyze output/<export-dir> --function 0x401100 [-o result.json] [--json]
python -m binproof analyze output/<export-dir> -f 0x401100 --show-prompt   # print the prompt, send nothing
```
Local models: `BINPROOF_PROVIDER=ollama BINPROOF_MODEL=<name>` (endpoint http://localhost:11434/v1), or
`openai-compatible` with `BINPROOF_BASE_URL`. Other settings: `BINPROOF_BASE_URL`, `BINPROOF_TIMEOUT`,
`BINPROOF_MAX_TOKENS`, `BINPROOF_TEMPERATURE` (omitted from requests unless set), `BINPROOF_MAX_ATTEMPTS`.

Layout (`binproof/ai/`): `providers/` (interface, Anthropic, OpenAI-compatible, registry), `config.py`,
`retry.py`, `context.py` (built from `Analysis`), `prompts.py`, `models.py` (Pydantic schema), `parsing.py`,
`analyzer.py` (orchestration), `render.py`. Add a provider with one class and `register_provider(...)`.

Every finding in the output carries evidence (address + exact quote) and a confidence level. Evidence is NOT yet
verified against the binary; that is the next milestone. Data sent to the model contains no local file paths.

## Milestone 4: evidence validation
```bash
python -m binproof analyze output/<export-dir> -f 0x401100 -o result.json     # produce a result
python -m binproof validate output/<export-dir> -r result.json [-o report.json] [--json] [--fail-on partial]
```
No model call is made: validation compares the AI result with the extracted data. It works in three separate layers,
reported separately in every claim:

1. **Evidence checks** (`validation/evidence.py`): does each cited address / instruction / call site / string / import /
   xref / code fragment exist, belong to this function, and match its quote?
2. **Claim checks** (`validation/support.py`): are constants and addresses in the claim text grounded; do "calls X" /
   "called by X" claims match the real callee and caller sets? (text heuristics)
3. **Semantic checks** (`validation/semantic.py`): interface only. Plug in a `SemanticVerifier` to judge whether evidence
   actually supports a claim; `RecordValidator(analysis, semantic_verifier=...)`.

Claim statuses: `VERIFIED`, `PARTIALLY_VERIFIED`, `UNVERIFIED`, `INVALID_EVIDENCE`, and `CONTRADICTED` (extracted data
refutes the claim). VERIFIED means the evidence is real and grounded, never that the interpretation is proven.
`--fail-on invalid|unverified|partial` makes the command exit 1 for scripts.

Full details, the corruption test matrix and the validator's current limitations: [docs/VALIDATION.md](docs/VALIDATION.md). A result from a different binary (hash mismatch) exits with code 3.

Test data: `tests/data/checkserial_result.json` is a real Gemini result. `tests/checkserial_fixture.py` is a
RECONSTRUCTED export consistent with it (not real Ghidra output); swap in a real export when convenient.
