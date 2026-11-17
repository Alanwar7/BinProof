"""Small command-line viewer for an export: `python -m binproof <command> <dir> ...`."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .analysis import Analysis
from .errors import BinProofError


def _print_problems(a: Analysis) -> None:
    for p in a.problems:
        print("  ! %s" % p)


def _cmd_inspect(a: Analysis, args) -> None:
    d = a.describe()
    print("%s  (%s)" % (d["program"], d["path"]))
    print("  schema %s | complete=%s | truncated=%s" % (d["schema_version"], d["complete"], d["truncated"]))
    if d["failed_steps"]:
        print("  failed steps: %s" % ", ".join(d["failed_steps"]))
    print("  counts: %s" % d["counts"])
    try:
        m = a.metadata
        print("  %s | %s | image base %s" % (m.executable_format, m.language_id, m.image_base))
    except BinProofError as exc:
        print("  metadata unavailable: %s" % exc)
    _print_problems(a)


def _cmd_functions(a: Analysis, args) -> None:
    funcs = a.find_functions(name_contains=args.name, include_thunks=not args.no_thunks)
    for f in funcs[: args.limit]:
        print("%s  %-32s %4d insns  callers=%d callees=%d%s" % (
            f.address, f.name, f.instruction_count, f.caller_count, f.callee_count,
            "  [thunk]" if f.is_thunk else ""))
    if len(funcs) > args.limit:
        print("... %d more (use --limit)" % (len(funcs) - args.limit))


def _cmd_function(a: Analysis, args) -> None:
    f = a.load_function(args.address)
    print("%s  %s" % (f.address, f.signature or f.name))
    print("  size=%d bytes, %d instructions, thunk=%s" % (f.size_bytes, f.instruction_count, f.is_thunk))
    if f.indirect_call_sites:
        print("  unresolved indirect calls at: %s" % ", ".join(f.indirect_call_sites))
    if args.asm:
        print("\n" + f.assembly_text())
    if args.decompiled:
        print("\n" + (f.decompilation.c if f.decompilation.ok
                      else "(decompilation unavailable: %s)" % f.decompilation.error))


def _relations(rels) -> None:
    for r in rels:
        print("%s  %s%s  @ %s" % (r.function.address, r.function.name or "?",
                                  " [external]" if r.is_external else "", ", ".join(r.call_sites)))
    if not rels:
        print("(none)")


def _cmd_callers(a: Analysis, args) -> None:
    _relations(a.get_callers(args.address))


def _cmd_callees(a: Analysis, args) -> None:
    _relations(a.get_callees(args.address))


def _cmd_xrefs(a: Analysis, args) -> None:
    refs = a.get_references_to(args.address, calls_only=args.calls_only)
    for r in refs:
        fn = r.from_function.name if r.from_function else "?"
        print("%s  %-14s from %s" % (r.from_address, r.type, fn))
    if not refs:
        print("(none)")


def _cmd_strings(a: Analysis, args) -> None:
    for s in a.get_strings(contains=args.contains, min_length=args.min_length, limit=args.limit):
        print("%s  refs=%d%s  %r" % (s.address, s.reference_count,
                                     "+" if s.references_truncated else "", s.value[:100]))


def _cmd_imports(a: Analysis, args) -> None:
    for i in a.get_imports(library=args.library, name_contains=args.name):
        print("%-24s %-32s call sites: %d" % (i.library, i.name, len(i.call_sites)))


def _cmd_analyze(a: Analysis, args) -> None:
    try:
        from .ai import AIConfig, ContextLimits, FunctionAnalyzer, build_function_context, create_provider
        from .ai.prompts import SYSTEM_PROMPT, render_user_prompt
        from .ai.render import render_text
        from .ai.retry import RetryPolicy
    except ImportError as exc:
        if getattr(exc, "name", None) == "pydantic":
            raise BinProofError("AI analysis needs pydantic: pip install 'binproof[ai]'") from None
        raise

    limits = ContextLimits(max_instructions=args.max_instructions) if args.max_instructions \
        else ContextLimits()

    if args.show_prompt:  # dry run: no API key needed, nothing is sent anywhere
        ctx = build_function_context(a, args.function, limits)
        print("--- SYSTEM PROMPT ---\n%s\n\n--- USER PROMPT ---\n%s" % (SYSTEM_PROMPT, render_user_prompt(ctx)))
        return

    config = AIConfig.from_env(provider=args.provider, model=args.model, base_url=args.base_url,
                               max_tokens=args.max_tokens, timeout=args.timeout)
    provider = create_provider(config)

    def notify(exc, delay, attempt):
        print("  %s; retrying in %.0fs (attempt %d)" % (exc, delay, attempt), file=sys.stderr)

    analyzer = FunctionAnalyzer(a, provider, limits=limits,
                                retry=RetryPolicy(max_attempts=config.max_attempts),
                                max_tokens=config.max_tokens, temperature=config.temperature,
                                on_retry=notify)
    print("Analyzing %s with %s / %s ..." % (args.function, provider.name, provider.model), file=sys.stderr)
    record = analyzer.analyze(args.function)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(record.model_dump_json(indent=2) + "\n")
        except OSError as exc:
            raise BinProofError("cannot write %s: %s" % (args.output, exc.strerror or exc)) from None
        print("Saved structured result to %s" % args.output, file=sys.stderr)
    print(record.model_dump_json(indent=2) if args.json else render_text(record))


def _cmd_validate(a: Analysis, args) -> int:
    try:
        from .validation import RecordValidator, load_record, render_report
        from .validation.models import ClaimStatus, severity
    except ImportError as exc:
        if getattr(exc, "name", None) == "pydantic":
            raise BinProofError("validation needs pydantic: pip install 'binproof[ai]'") from None
        raise

    report = RecordValidator(a).validate(load_record(args.result))
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report.model_dump_json(indent=2) + "\n")
        except OSError as exc:
            raise BinProofError("cannot write %s: %s" % (args.output, exc.strerror or exc)) from None
        print("Saved validation report to %s" % args.output, file=sys.stderr)
    print(report.model_dump_json(indent=2) if args.json else render_report(report))

    if not report.integrity.ok:   # nothing below means anything for the wrong binary
        print("error: binary hash mismatch: this result was not produced from this export, so its validation "
              "is meaningless", file=sys.stderr)
        return 3
    threshold = {"invalid": ClaimStatus.INVALID_EVIDENCE, "unverified": ClaimStatus.UNVERIFIED,
                 "partial": ClaimStatus.PARTIALLY_VERIFIED}.get(args.fail_on)
    if threshold and any(severity(c.status) >= severity(threshold) for c in report.claims):
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("directory", help="export directory (contains manifest.json)")
    common.add_argument("--allow-incomplete", action="store_true",
                        help="open an export whose manifest says complete=false")
    common.add_argument("--strict", action="store_true", help="fail on malformed records")

    ap = argparse.ArgumentParser(prog="binproof", description="Inspect a BinProof export.")
    sub = ap.add_subparsers(dest="command", required=True)

    def add(name, func, help_):
        p = sub.add_parser(name, parents=[common], help=help_)
        p.set_defaults(func=func)
        return p

    add("inspect", _cmd_inspect, "manifest, completeness and problems")
    p = add("functions", _cmd_functions, "list functions")
    p.add_argument("--name"); p.add_argument("--no-thunks", action="store_true")
    p.add_argument("--limit", type=int, default=50)
    p = add("function", _cmd_function, "show one function")
    p.add_argument("address"); p.add_argument("--asm", action="store_true")
    p.add_argument("--decompiled", action="store_true")
    for name, func in (("callers", _cmd_callers), ("callees", _cmd_callees)):
        add(name, func, "functions that call / are called by ADDRESS").add_argument("address")
    p = add("xrefs", _cmd_xrefs, "references to a function entry")
    p.add_argument("address"); p.add_argument("--calls-only", action="store_true")
    p = add("strings", _cmd_strings, "list strings")
    p.add_argument("--contains"); p.add_argument("--min-length", type=int)
    p.add_argument("--limit", type=int, default=50)
    p = add("imports", _cmd_imports, "list imports")
    p.add_argument("--library"); p.add_argument("--name")
    p = add("analyze", _cmd_analyze, "AI analysis of one function (needs binproof[ai] and a configured provider)")
    p.add_argument("--function", "-f", required=True, metavar="ADDRESS")
    p.add_argument("--provider", help="anthropic | openai | ollama | openai-compatible (or BINPROOF_PROVIDER)")
    p.add_argument("--model", help="model name (or BINPROOF_MODEL)")
    p.add_argument("--base-url", help="API endpoint override (or BINPROOF_BASE_URL)")
    p.add_argument("--max-tokens", type=int, help="output token limit (default 4096)")
    p.add_argument("--timeout", type=float, help="seconds per request (default 120)")
    p.add_argument("--max-instructions", type=int, help="assembly instructions sent to the model (default 600)")
    p.add_argument("--json", action="store_true", help="print the structured result as JSON")
    p.add_argument("--output", "-o", metavar="FILE", help="also save the structured result as JSON")
    p.add_argument("--show-prompt", action="store_true", help="print the prompt and exit; sends nothing")
    p = add("validate", _cmd_validate, "check a saved AI analysis result against the extracted data (no model call)")
    p.add_argument("--result", "-r", required=True, metavar="FILE", help="JSON saved by `analyze --output`")
    p.add_argument("--output", "-o", metavar="FILE", help="save the validation report as JSON")
    p.add_argument("--json", action="store_true", help="print the report as JSON instead of text")
    p.add_argument("--fail-on", choices=["never", "invalid", "unverified", "partial"], default="never",
                   help="exit 1 if any claim is at least this bad (default: never). A binary hash mismatch always exits 3")
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        analysis = Analysis.open(args.directory, strict=args.strict,
                                 allow_incomplete=args.allow_incomplete)
        rc = args.func(analysis, args)
        if args.command != "inspect" and analysis.problems:
            print("\n%d problem(s) while loading; run `inspect` for details" % len(analysis.problems),
                  file=sys.stderr)
        return rc or 0
    except BinProofError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    except KeyboardInterrupt:   # Ctrl+C is a normal way to stop, not a crash; nothing partial is ever written
        print("\ninterrupted", file=sys.stderr)
        return 130
