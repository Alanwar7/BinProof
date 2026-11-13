# BinProof

AI-assisted, evidence-checked reverse engineering on top of Ghidra.
(Formerly BinaryLens.)

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

Tests: `pip install -e '.[dev]' && pytest`

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
