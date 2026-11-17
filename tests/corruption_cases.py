"""The corruption matrix: deliberately damaged versions of a REAL AI result (checkSerial, Gemini).

One table drives both the tests (tests/test_validation_hardening.py) and the generated table in
docs/VALIDATION.md (`python tests/corruption_cases.py`). Each case states what was damaged and the
status the deterministic validator must give. Cases with `limitation=True` are things a deterministic
validator CANNOT catch; they are strict xfails so the gap stays documented and visible.
"""

import copy
import json
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Tuple

HERE = Path(__file__).parent
BASE = json.loads((HERE / "data" / "checkserial_result.json").read_text())

VERIFIED, PARTIAL, UNVERIFIED, INVALID, CONTRADICTED = (
    "VERIFIED", "PARTIALLY_VERIFIED", "UNVERIFIED", "INVALID_EVIDENCE", "CONTRADICTED")

FAB, ADDR, REF, MISS, UNSUP, CTRL, LIMIT = (
    "fabricated_instruction", "incorrect_address", "incorrect_function_reference", "missing_evidence",
    "unsupported_claim", "control", "known_limitation")
REQUIRED_CATEGORIES = (FAB, ADDR, REF, MISS, UNSUP)


@dataclass
class Case:
    id: str
    category: str
    damage: str                                   # what was done to the real result
    claim: str                                    # which claim to inspect
    status: str                                   # expected final status
    mutate: Callable[[dict], None] = lambda d: None
    codes: Optional[Tuple[str, ...]] = None       # expected evidence codes, in order
    findings: Tuple[str, ...] = ()                # finding codes that must be present
    no_findings: Tuple[str, ...] = ()             # finding codes that must be absent
    evidence_status: Optional[str] = None         # expected layer-1 status (proves layers stay separate)
    reason: Optional[str] = None                  # substring expected in the joined reasons
    post: Optional[Callable] = None               # applied to the validated record (bypasses schema rules)
    limitation: bool = False


def node(d, claim):
    if claim == "purpose":
        return d["analysis"]["purpose"]
    kind, i = claim.rstrip("]").split("[")
    return d["analysis"][kind][int(i)]


def ev(kind, quote, address=None, note=None):
    return {"kind": kind, "quote": quote, "address": address, "note": note}


def set_ev(claim, i, **changes):
    return lambda d: node(d, claim)["evidence"][i].update(changes)


def set_evidence(claim, evidence):
    return lambda d: node(d, claim).update(evidence=copy.deepcopy(evidence))


def set_statement(claim, text=None, suffix=None):
    def run(d):
        n = node(d, claim)
        n["statement"] = text if text is not None else n["statement"] + suffix
    return run


def both(*fns):
    return lambda d: [f(d) for f in fns]


def blank_evidence(claim, section="behavior", index=0):
    def post(rec):
        item = getattr(rec.analysis, section)[index].model_copy(update={"evidence": []})  # bypasses the schema
        getattr(rec.analysis, section)[index] = item
        return rec
    return post


B0 = "behavior[0]"
CASES = [
    # ---- fabricated assembly / code ---------------------------------------------------------------
    Case("fab-1", FAB, "instruction quote replaced by one that does not exist at that address", B0, PARTIAL,
         set_ev(B0, 1, quote="XOR EAX,EAX"), codes=("call_site_confirmed", "quote_mismatch", "quote_matches")),
    Case("fab-2", FAB, "every instruction quote in a claim fabricated", "behavior[1]", INVALID,
         lambda d: [node(d, "behavior[1]")["evidence"][i].update(quote=q) for i, q in
                    enumerate(["XOR EAX,EAX", "MOV RAX,RBX", "INC ECX"])],
         codes=("quote_mismatch",) * 3),
    Case("fab-3", FAB, "a real instruction quoted at the address of a different instruction", "behavior[1]", PARTIAL,
         set_ev("behavior[1]", 0, quote="CMP RAX,0x10"), codes=("quote_mismatch", "quote_matches", "quote_matches")),
    Case("fab-4", FAB, "call quoted with a fabricated target", B0, PARTIAL,
         set_ev(B0, 0, quote="CALL 0x00109999"), codes=("call_quote_mismatch", "quote_matches", "quote_matches")),
    Case("fab-5", FAB, "fabricated decompiled-code fragment", "purpose", PARTIAL,
         set_ev("purpose", 0, quote="if (sVar1 == 0x20) { exit(1); }"),
         codes=("fragment_not_in_decompiled_code", "fragment_confirmed")),
    Case("fab-6", FAB, "all decompiled-code fragments fabricated", "purpose", INVALID,
         lambda d: [e.update(quote="decrypt(buf, key);") for e in node(d, "purpose")["evidence"]],
         codes=("fragment_not_in_decompiled_code",) * 2),
    Case("fab-7", FAB, "an assembly instruction cited as decompiled code", "purpose", PARTIAL,
         set_ev("purpose", 0, quote="CMP RAX,0x10"), codes=("wrong_evidence_kind", "fragment_confirmed"),
         reason="should be cited as kind 'instruction'"),
    Case("fab-8", FAB, "instruction quote shortened to the bare mnemonic", B0, PARTIAL,
         set_ev(B0, 1, quote="CMP"), codes=("call_site_confirmed", "quote_too_short", "quote_matches")),
    Case("fab-9", FAB, "fabricated instructions at fabricated addresses", "behavior[2]", INVALID,
         lambda d: [node(d, "behavior[2]")["evidence"][i].update(address=a, quote=q) for i, (a, q) in
                    enumerate([("0x00109998", "XOR EAX,EAX"), ("0x0010999c", "RET")])],
         codes=("address_not_in_data", "address_not_in_data")),
    # ---- incorrect addresses -------------------------------------------------------------------------
    Case("addr-1", ADDR, "address does not exist anywhere in the binary", B0, PARTIAL,
         set_ev(B0, 1, address="0x00109999"), codes=("call_site_confirmed", "address_not_in_data", "quote_matches")),
    Case("addr-2", ADDR, "address belongs to a different function (main)", B0, PARTIAL,
         set_ev(B0, 1, address="0x00101260"), codes=("call_site_confirmed", "address_in_other_function",
                                                       "quote_matches"), reason="belongs to function main"),
    Case("addr-3", ADDR, "address points into the middle of an instruction", B0, PARTIAL,
         set_ev(B0, 1, address="0x001011b1"), codes=("call_site_confirmed", "address_not_an_instruction_start",
                                                      "quote_matches")),
    Case("addr-4", ADDR, "address off by one instruction (a jump instead of the compare)", B0, PARTIAL,
         set_ev(B0, 1, address="0x001011b4"), codes=("call_site_confirmed", "quote_mismatch", "quote_matches")),
    Case("addr-5", ADDR, "every address in a claim is wrong", "behavior[1]", INVALID,
         lambda d: [e.update(address="0x00109999") for e in node(d, "behavior[1]")["evidence"]],
         codes=("address_not_in_data",) * 3),
    Case("addr-6", ADDR, "call evidence pointing at an instruction that is not a call", B0, PARTIAL,
         set_ev(B0, 0, address="0x001011b0"), codes=("not_a_call", "quote_matches", "quote_matches")),
    Case("addr-7", ADDR, "string that exists but is used by another function", B0, PARTIAL,
         set_ev(B0, 0, kind="string", address="0x00102004", quote="Enter serial: "),
         codes=("string_not_referenced_by_function", "quote_matches", "quote_matches")),
    # ---- incorrect function references -------------------------------------------------------------------
    Case("ref-1", REF, "call evidence names the wrong callee", B0, PARTIAL,
         set_ev(B0, 0, quote="CALL strcpy"), codes=("call_quote_mismatch", "quote_matches", "quote_matches")),
    Case("ref-2", REF, "import that exists but this function never uses", B0, PARTIAL,
         set_ev(B0, 0, kind="import", address=None, quote="printf"),
         codes=("import_not_used_by_function", "quote_matches", "quote_matches")),
    Case("ref-3", REF, "import that does not exist in the binary", B0, PARTIAL,
         set_ev(B0, 0, kind="import", address=None, quote="gets"),
         codes=("import_not_found", "quote_matches", "quote_matches")),
    Case("ref-4", REF, "claim says the function calls strcpy (it does not)", B0, CONTRADICTED,
         set_statement(B0, "Calls strcpy to copy the serial and fails if it is not 16 characters."),
         findings=("claimed_callee_not_called",), evidence_status=VERIFIED),
    Case("ref-5", REF, "claim says it is called by copyHelper (it is called by main)", "purpose", CONTRADICTED,
         set_statement("purpose", suffix=" It is called by copyHelper."), findings=("claimed_caller_not_found",),
         evidence_status=VERIFIED),
    Case("ref-6", REF, "claim says it calls a function that does not exist", B0, CONTRADICTED,
         set_statement(B0, "Calls decryptPayload() before checking the length is 16."),
         findings=("claimed_callee_unknown",), evidence_status=VERIFIED),
    Case("ref-7", REF, "claim says it never calls strlen (it does)", B0, CONTRADICTED,
         set_statement(B0, "Never calls strlen; it measures the length itself and fails if it is not 16."),
         findings=("claimed_absence_but_called",), evidence_status=VERIFIED),
    Case("ref-8", REF, "claim says the function delegates to copyHelper (internal name, plain text)", B0, CONTRADICTED,
         set_statement(B0, "Delegates the length check of 16 characters to copyHelper."),
         findings=("claimed_callee_not_called",)),
    Case("ref-9", REF, "xref evidence at an address inside the function, not a reference to it", B0, PARTIAL,
         set_ev(B0, 0, kind="xref", quote="CALL checkSerial"),
         codes=("no_reference_at_address", "quote_matches", "quote_matches")),
    # ---- missing evidence ------------------------------------------------------------------------------------
    Case("miss-1", MISS, "all evidence removed from a claim", B0, UNVERIFIED, post=blank_evidence(B0),
         codes=(), reason="no supporting evidence"),
    Case("miss-2", MISS, "only free-form metadata that cannot be checked", B0, UNVERIFIED,
         set_evidence(B0, [ev("metadata", "uses a custom packer")]), codes=("metadata_not_checkable",)),
    Case("miss-3", MISS, "only a quote too short to prove anything", B0, PARTIAL,
         set_evidence(B0, [ev("instruction", "CMP", "0x001011b0")]), codes=("quote_too_short",)),
    # ---- evidence exists but does not support the claim --------------------------------------------------------
    Case("unsup-1", UNSUP, "real but meaningless evidence (prologue/epilogue only)", B0, PARTIAL,
         set_evidence(B0, [ev("instruction", "PUSH RBP", "0x00101197"), ev("instruction", "RET", "0x00101223")]),
         codes=("quote_matches", "quote_matches"), findings=("evidence_is_boilerplate",), evidence_status=VERIFIED),
    Case("unsup-2", UNSUP, "evidence swapped in from a different claim", B0, PARTIAL,
         lambda d: node(d, B0).update(evidence=copy.deepcopy(node(d, "behavior[1]")["evidence"])),
         findings=("evidence_does_not_cover_claim_specifics",), evidence_status=VERIFIED),
    Case("unsup-3", UNSUP, "claim states a constant (32) that exists nowhere", B0, PARTIAL,
         set_statement(B0, "Measures the input with strlen and fails if it is not 32 characters."),
         findings=("value_not_in_data",), evidence_status=VERIFIED),
    Case("unsup-4", UNSUP, "fabricated constant 'grounded' only by the model's own note", B0, PARTIAL,
         both(set_statement(B0, "Fails if the input is not 32 characters long."),
              set_ev(B0, 1, note="compares the length to 32")),
         findings=("value_not_in_data",), evidence_status=VERIFIED),
    Case("unsup-5", UNSUP, "fabricated constant 'grounded' only by an invalid evidence quote", B0, PARTIAL,
         both(set_statement(B0, "Fails if the input is not 32 characters long."),
              set_evidence(B0, [ev("instruction", "CMP RAX,0x20", "0x00109999"),
                                ev("instruction", "MOV EAX,0xffffffff", "0x001011b6")])),
         findings=("value_not_in_data",)),
    Case("unsup-6", UNSUP, "claim about 0xffffffff supported only by an instruction returning 0", "behavior[2]", PARTIAL,
         both(set_statement("behavior[2]", "Returns 0xffffffff when the serial is valid."),
              set_evidence("behavior[2]", [ev("instruction", "MOV EAX,0x0", "0x0010121a")])),
         findings=("evidence_does_not_cover_claim_specifics",), evidence_status=VERIFIED),
    Case("unsup-7", UNSUP, "claim quotes text the function never uses", B0, PARTIAL,
         set_statement(B0, 'Prints "Enter password" when the serial is wrong.'),
         findings=("quoted_text_not_in_function",), evidence_status=VERIFIED),
    Case("unsup-8", UNSUP, "decompiled evidence that is only a bare identifier", "purpose", PARTIAL,
         set_ev("purpose", 0, quote="local_1c"), codes=("fragment_too_generic", "fragment_confirmed")),
    # ---- controls: honest claims that must NOT be flagged ------------------------------------------------------------
    Case("ctl-1", CTRL, "NO damage: the real result", "purpose", VERIFIED, evidence_status=VERIFIED),
    Case("ctl-2", CTRL, "true negation: does not call strcpy", B0, VERIFIED,
         set_statement(B0, "Does not call strcpy; it uses strlen to measure the length, which must be 16."),
         no_findings=("claimed_callee_not_called", "claimed_callee_unknown", "claimed_absence_but_called")),
    Case("ctl-3", CTRL, "true caller claim: called by main", "purpose", VERIFIED,
         set_statement("purpose", suffix=" It is called by main.")),
    Case("ctl-4", CTRL, "same evidence cited three times is counted once", B0, VERIFIED,
         lambda d: node(d, B0).update(evidence=[copy.deepcopy(node(d, B0)["evidence"][1])] * 3),
         findings=("duplicate_evidence",), codes=("quote_matches",) * 3),
    Case("ctl-5", CTRL, "Ghidra variable names and bit widths are not function references", "behavior[1]", VERIFIED,
         set_statement("behavior[1]", "Stores sVar1 and local_1c, steps by 2 on a 64-bit machine, and compares "
                                       "each byte with its neighbour (difference of -1)."),
         no_findings=("function_mentioned_without_relationship", "value_not_in_data")),
    # ---- known limitations: deterministic checks cannot see these ------------------------------------------------------
    Case("limit-1", LIMIT, "claim reverses which return value means success; both constants are cited", "behavior[2]",
         PARTIAL, set_statement("behavior[2]", "Returns 0xffffffff when every pair check passes and 0 when one fails."),
         limitation=True),
    Case("limit-2", LIMIT, "claim inverts the length condition; the cited compare is real", B0, PARTIAL,
         set_statement(B0, "Measures the input with strlen and fails only if it is exactly 16 characters."),
         limitation=True),
    Case("limit-3", LIMIT, "vague claim with no checkable specifics, backed by real evidence", B0, PARTIAL,
         set_statement(B0, "Performs a robust cryptographic validation of the input."), limitation=True),
]


def build_record(case):
    from binproof.ai.models import FunctionAnalysisRecord
    d = copy.deepcopy(BASE)
    case.mutate(d)
    rec = FunctionAnalysisRecord.model_validate(d)
    return case.post(rec) if case.post else rec


if __name__ == "__main__":   # print the markdown table used in docs/VALIDATION.md
    sys.path[:0] = [str(HERE), str(HERE.parent)]
    from binproof import Analysis
    from binproof.validation import RecordValidator
    from checkserial_fixture import make_checkserial_export
    root = Path(tempfile.mkdtemp()) / "cs"
    make_checkserial_export(root)
    validator = RecordValidator(Analysis.open(root))
    print("| Case | Category | What was damaged | Expected | Actual |\n|---|---|---|---|---|")
    for c in CASES:
        rep = validator.validate(build_record(c))
        actual = next(x for x in rep.claims if x.id == c.claim).status.value
        note = " (not caught)" if c.limitation and actual == VERIFIED else ""
        print("| %s | %s | %s | %s | %s%s |" % (c.id, c.category.replace("_", " "), c.damage, c.status, actual, note))
