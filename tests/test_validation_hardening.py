"""Hardening tests for the deterministic validation layers.

Organised by what each group proves:
  matrix        deliberately corrupted real results get the expected status (corruption_cases.py)
  limitations   what a deterministic validator cannot catch (strict xfail, so the gap stays visible)
  separation    evidence existence, claim support and semantic judgement stay separate concepts
  integrity     binary-hash and context-reproduction checks, including mismatched inputs
  decompiled    evidence without addresses gets locations and assembly corroboration
  heuristics    claim-text checks: negation, unknown functions, variable names, constants
  quote rules   minimum strength of quotes
  golden        the validator reproduces what it said about the REAL export
"""

import copy
import json
import shutil
from pathlib import Path

import pytest

from binproof import Analysis
from binproof.ai.context import ContextLimits, build_function_context
from binproof.ai.models import Evidence, FunctionAnalysisRecord
from binproof.validation import RecordValidator, SemanticAssessment, SemanticStatus, ValidationReport, render_report
from binproof.validation.evidence import EvidenceChecker
from binproof.validation.facts import FunctionFacts
from binproof.validation.models import ClaimStatus as C, EvidenceStatus as S, severity, worst
from binproof.validation.semantic import semantic_floor
from checkserial_fixture import CHECK, MAIN, make_checkserial_export
from corruption_cases import BASE, CASES, REQUIRED_CATEGORIES, build_record, node

DATA = Path(__file__).parent / "data"
MATRIX = [c for c in CASES if not c.limitation]
LIMITS = [c for c in CASES if c.limitation]


@pytest.fixture
def cs_root(tmp_path):
    root = tmp_path / "cs"
    make_checkserial_export(root)
    return root


@pytest.fixture
def cs(cs_root):
    return Analysis.open(cs_root)


def claim_of(report, claim_id):
    return next(c for c in report.claims if c.id == claim_id)


def record(mutate=None):
    d = copy.deepcopy(BASE)
    if mutate:
        mutate(d)
    return FunctionAnalysisRecord.model_validate(d)


# =========================== matrix ===========================================================

@pytest.mark.parametrize("case", MATRIX, ids=[c.id for c in MATRIX])
def test_corruption_matrix(cs, case):
    result = claim_of(RecordValidator(cs).validate(build_record(case)), case.claim)
    assert result.status.value == case.status, (result.reasons, [e.code for e in result.evidence])
    if case.codes is not None:
        assert tuple(e.code for e in result.evidence) == case.codes
    found = {f.code for f in result.findings}
    assert set(case.findings) <= found, found
    assert not set(case.no_findings) & found, found
    if case.evidence_status:
        assert result.evidence_status.value == case.evidence_status
    if case.reason:
        assert case.reason in " | ".join(result.reasons)


def test_matrix_covers_every_required_category_and_every_status():
    for category in REQUIRED_CATEGORIES:
        assert sum(c.category == category for c in MATRIX) >= 3, category
    assert {c.status for c in MATRIX} == {s.value for s in C}


@pytest.mark.xfail(strict=True, reason="deterministic checks cannot judge meaning; this needs the semantic layer")
@pytest.mark.parametrize("case", LIMITS, ids=[c.id for c in LIMITS])
def test_known_limitation_is_not_caught(cs, case):
    result = claim_of(RecordValidator(cs).validate(build_record(case)), case.claim)
    assert result.status.value == case.status


def test_every_corrupted_claim_is_flagged_somewhere(cs):
    """No damaged case may come out clean: a summary of the whole matrix."""
    validator = RecordValidator(cs)
    clean = [c.id for c in MATRIX if c.status != "VERIFIED"
             and claim_of(validator.validate(build_record(c)), c.claim).status is C.VERIFIED]
    assert clean == []


# =========================== separation of concepts ========================================================

def test_layer1_results_do_not_depend_on_claim_wording(cs):
    base = RecordValidator(cs).validate(record())

    def scramble(d):
        a = d["analysis"]
        a["purpose"]["statement"] = "Something entirely different."
        for item in a["behavior"] + a["side_effects"]:
            item["statement"] = "Calls strcpy and never returns 99999."
        for item in a["inputs"] + a["outputs"]:
            item["description"] = "Unrelated text mentioning decryptPayload()."
    other = RecordValidator(cs).validate(record(scramble))
    for a, b in zip(base.claims, other.claims):
        assert [e.model_dump() for e in a.evidence] == [e.model_dump() for e in b.evidence]
        assert a.evidence_status == b.evidence_status == C.VERIFIED
    assert any(c.status is not C.VERIFIED for c in other.claims)     # ...yet the claims themselves are flagged


@pytest.mark.parametrize("case", MATRIX, ids=[c.id for c in MATRIX])
def test_final_status_is_exactly_the_worst_of_the_layers(cs, case):
    result = claim_of(RecordValidator(cs).validate(build_record(case)), case.claim)
    support = C.VERIFIED
    for f in result.findings:
        if f.severity.value == "contradiction":
            support = worst(support, C.CONTRADICTED)
        elif f.severity.value == "weak":
            support = worst(support, C.PARTIALLY_VERIFIED)
    expected = worst(result.evidence_status, support, semantic_floor(result.semantic))
    assert result.status is expected


class Verdict:
    name = "stub"

    def __init__(self, status):
        self.status = status

    def assess(self, claim, checks, facts):
        return SemanticAssessment(status=self.status, method=self.name, rationale="stub")


@pytest.mark.parametrize("case_id", ["fab-6", "addr-5", "ref-4", "unsup-2", "miss-1"])
def test_a_favourable_semantic_verdict_never_upgrades_a_claim(cs, case_id):
    case = next(c for c in CASES if c.id == case_id)
    plain = claim_of(RecordValidator(cs).validate(build_record(case)), case.claim)
    boosted = claim_of(RecordValidator(cs, semantic_verifier=Verdict(SemanticStatus.SUPPORTED))
                       .validate(build_record(case)), case.claim)
    assert boosted.status is plain.status and severity(plain.status) > 0
    assert boosted.evidence_status is plain.evidence_status


def test_a_semantic_verdict_never_rewrites_layer1_or_layer2(cs):
    plain = RecordValidator(cs).validate(record())
    judged = RecordValidator(cs, semantic_verifier=Verdict(SemanticStatus.UNSUPPORTED)).validate(record())
    for a, b in zip(plain.claims, judged.claims):
        assert b.evidence_status is a.evidence_status and b.findings == a.findings
        assert [e.model_dump() for e in b.evidence] == [e.model_dump() for e in a.evidence]
    assert all(c.status is C.UNVERIFIED for c in judged.claims)


def test_the_report_says_verified_is_not_proof(cs):
    rep = RecordValidator(cs).validate(record())
    text = " ".join(rep.limitations)
    assert "do not prove" in text and "not a guarantee" in text
    assert "VERIFIED = evidence real and grounded (not proof of correctness)" in render_report(rep)


# =========================== integrity ===========================================================================

def with_provenance(**changes):
    return record(lambda d: d["provenance"].update(changes))


def test_binary_hash_mismatch_is_an_integrity_failure(cs):
    rep = RecordValidator(cs).validate(with_provenance(program_sha256="ab" * 32))
    assert rep.integrity.binary_matches is False and rep.integrity.ok is False
    assert any(n.startswith("ERROR") and "different binary" in n for n in rep.integrity.notes)
    assert {c.status for c in rep.claims} == {C.VERIFIED}        # evidence still evaluated; integrity says it is moot
    assert "INTEGRITY FAILURE" in render_report(rep)


def test_hash_comparison_ignores_case(cs):
    rep = RecordValidator(cs).validate(with_provenance(program_sha256=BASE["provenance"]["program_sha256"].upper()))
    assert rep.integrity.binary_matches is True and rep.integrity.ok


def test_missing_hash_in_result_is_unknown_not_failure(cs):
    rep = RecordValidator(cs).validate(with_provenance(program_sha256=None))
    assert rep.integrity.binary_matches is None and rep.integrity.ok
    assert any("binary identity could not be confirmed" in n for n in rep.integrity.notes)


def test_missing_hash_in_export_is_unknown_not_failure(cs_root):
    meta = json.loads((cs_root / "metadata.json").read_text())
    meta["hashes"]["sha256"] = None
    (cs_root / "metadata.json").write_text(json.dumps(meta))
    rep = RecordValidator(Analysis.open(cs_root)).validate(record())
    assert rep.integrity.binary_matches is None and rep.integrity.ok


def test_unavailable_metadata_is_unknown_not_failure(tmp_path):
    root = tmp_path / "m"
    make_checkserial_export(root, complete=False, errors=[{"step": "metadata", "traceback": "x"}])
    rep = RecordValidator(Analysis.open(root, allow_incomplete=True)).validate(record())
    assert rep.integrity.binary_matches is None and rep.integrity.ok


def exact_context_hash(analysis, limits=None):
    return build_function_context(analysis, CHECK, limits or ContextLimits()).sha256()


def test_context_reproduced_exactly_when_nothing_changed(cs):
    rep = RecordValidator(cs).validate(with_provenance(context_sha256=exact_context_hash(cs)))
    assert rep.integrity.context_reproduced is True
    assert not any("cannot be reproduced" in n for n in rep.integrity.notes)


def test_context_not_reproduced_when_the_export_changed_after_analysis(cs, cs_root):
    original = exact_context_hash(cs)
    path = cs_root / "functions" / "0x00101197.json"
    rec = json.loads(path.read_text())
    rec["assembly"][6]["text"] = "CALL 0x00109999"        # re-extraction produced different data
    path.write_text(json.dumps(rec))
    rep = RecordValidator(Analysis.open(cs_root)).validate(with_provenance(context_sha256=original))
    assert rep.integrity.context_reproduced is False and rep.integrity.binary_matches is True
    assert rep.integrity.ok and any("cannot be reproduced" in n for n in rep.integrity.notes)


def test_context_not_reproduced_with_non_default_limits(cs):
    rep = RecordValidator(cs).validate(with_provenance(context_sha256=exact_context_hash(cs, ContextLimits(max_instructions=5))))
    assert rep.integrity.context_reproduced is False
    assert any("non-default context limits" in n for n in rep.integrity.notes)


def test_tampered_context_hash_is_detected(cs):
    rep = RecordValidator(cs).validate(with_provenance(context_sha256="0" * 64))
    assert rep.integrity.context_reproduced is False


def test_cli_exits_3_on_binary_mismatch_whatever_fail_on_says(cs_root, tmp_path, capsys):
    from binproof.cli import main
    d = copy.deepcopy(BASE)
    d["provenance"]["program_sha256"] = "cd" * 32
    result, out = tmp_path / "r.json", tmp_path / "report.json"
    result.write_text(json.dumps(d))
    for fail_on in ("never", "invalid", "partial"):
        assert main(["validate", str(cs_root), "-r", str(result), "-o", str(out), "--fail-on", fail_on]) == 3
        assert "hash mismatch" in capsys.readouterr().err
    assert ValidationReport.model_validate_json(out.read_text()).integrity.ok is False


def test_cli_matching_binary_still_exits_0(cs_root, tmp_path, capsys):
    from binproof.cli import main
    result = tmp_path / "r.json"
    result.write_text(json.dumps(BASE))
    assert main(["validate", str(cs_root), "-r", str(result)]) == 0
    capsys.readouterr()


# =========================== decompiled-code evidence ==========================================================

def check_one(analysis, kind, quote, address=None, function=CHECK):
    return EvidenceChecker(FunctionFacts.load(analysis, function)).check(Evidence(kind=kind, quote=quote, address=address))


def test_decompiled_evidence_gets_a_line_and_matching_assembly(cs):
    r = check_one(cs, "decompiled_code", "if (sVar1 == 0x10)")
    assert r.status is S.CONFIRMED and r.location == "decompiled code line 9" and r.occurrences == 1
    assert r.corroborating_addresses == ["0x001011b0"]                    # CMP RAX,0x10
    assert "matching assembly at 0x001011b0" in r.reason


def test_decompiled_call_fragment_points_at_the_call_site(cs):
    r = check_one(cs, "decompiled_code", "sVar1 = strlen(param_1);")
    assert r.location == "decompiled code line 8" and r.corroborating_addresses == ["0x001011ab"]


def test_ambiguous_fragment_reports_every_occurrence(cs):
    r = check_one(cs, "decompiled_code", "uVar2 =")
    assert r.status is S.CONFIRMED and r.occurrences == 2
    assert r.location == "decompiled code lines 15, 18"
    assert "occurs 2 times" in r.reason and "does not say which occurrence" in r.reason


def test_elided_fragment_reports_its_span(cs):
    r = check_one(cs, "decompiled_code", "if (sVar1 == 0x10) ... return uVar2;")
    assert r.status is S.CONFIRMED and r.occurrences is None and r.location == "decompiled code lines 9-20 (segments in order)"


def test_assembly_cited_as_decompiled_code_is_redirected(cs):
    r = check_one(cs, "decompiled_code", "CMP RAX,0x10")
    assert (r.status, r.code) == (S.PARTIAL, "wrong_evidence_kind")
    assert r.corroborating_addresses == ["0x001011b0"] and "kind 'instruction'" in r.reason


@pytest.mark.parametrize("quote", ["param_1", "sVar1", "0x10"])
def test_bare_identifiers_and_numbers_are_too_generic(cs, quote):
    assert check_one(cs, "decompiled_code", quote).code in ("fragment_too_generic", "fragment_too_short")


def test_cited_address_agreeing_with_the_assembly_is_accepted(cs):
    assert check_one(cs, "decompiled_code", "if (sVar1 == 0x10)", "0x001011b0").status is S.CONFIRMED
    assert check_one(cs, "decompiled_code", "if (sVar1 == 0x10)", "0x00109999").code == "address_not_in_function"


def test_fragment_whose_constant_has_no_assembly_is_noted(cs, cs_root):
    path = cs_root / "functions" / "0x00101197.json"
    rec = json.loads(path.read_text())
    rec["decompiled"]["c"] = rec["decompiled"]["c"].replace("uVar2 = 0;", "uVar2 = 0x77;")
    path.write_text(json.dumps(rec))
    r = check_one(Analysis.open(cs_root), "decompiled_code", "uVar2 = 0x77;")
    assert r.status is S.CONFIRMED and r.corroborating_addresses == []
    assert "no assembly instruction or call site matches" in r.reason


def test_coordinates_appear_in_the_json_and_text_report(cs):
    rep = RecordValidator(cs).validate(record())
    e = claim_of(rep, "purpose").evidence[0]
    assert e.location == "decompiled code line 9" and e.corroborating_addresses == ["0x001011b0"]
    assert "at decompiled code line 9; assembly: 0x001011b0" in render_report(rep)
    assert ValidationReport.model_validate_json(rep.model_dump_json()) == rep


def test_reports_written_before_these_fields_existed_still_load():
    old = ValidationReport.model_validate_json((DATA / "checkserial_report_real.json").read_text())
    assert old.claims[0].evidence[0].location is None and old.integrity.ok is True


# =========================== claim-text heuristics =============================================================

def findings_for(cs, statement, claim="behavior[0]"):
    def mutate(d):
        node(d, claim)["statement"] = statement
    return {f.code: f.severity.value for f in claim_of(RecordValidator(cs).validate(record(mutate)), claim).findings}


@pytest.mark.parametrize("statement,expected,forbidden", [
    ("Does not call strcpy.", {}, {"claimed_callee_not_called"}),
    ("Doesn't invoke strcpy; it measures with strlen, length 16.", {}, {"claimed_callee_not_called"}),
    ("Without calling strcpy, it uses strlen to check for 16.", {}, {"claimed_callee_not_called"}),
    ("Calls strcpy.", {"claimed_callee_not_called": "contradiction"}, set()),
    ("It never calls strlen.", {"claimed_absence_but_called": "contradiction"}, set()),
    ("Calls `decryptPayload` first.", {"claimed_callee_unknown": "contradiction"}, set()),
    ("Invokes decrypt_payload() first.", {"claimed_callee_unknown": "contradiction"}, set()),
    ("Calls the helper function afterwards.", {}, {"claimed_callee_unknown"}),               # plain words: not flagged
    ("Forwards the input to copyHelper.", {"claimed_callee_not_called": "contradiction"}, set()),
    ("Compare with copyHelper which handles copying.", {"function_mentioned_without_relationship": "weak"}, set()),
    ("Stores sVar1 and uVar2 in local_1c.", {}, {"function_mentioned_without_relationship"}),
    ("Works on a 64-bit machine with strlen.", {}, {"value_not_in_data"}),
    ("Compares the length with 16 (0x10) using strlen.", {}, {"value_not_in_data"}),
    ("Jumps to 0x00109999 afterwards.", {"value_not_in_data": "weak"}, set()),
    ('Prints "Enter serial: " first.', {"quoted_text_not_in_function": "weak"}, set()),   # real string, but main's, not this function's
])
def test_claim_text_heuristics(cs, statement, expected, forbidden):
    got = findings_for(cs, statement)
    for code, sev in expected.items():
        assert got.get(code) == sev, got
    assert not forbidden & set(got), got


def test_caller_phrasing_variants(cs):
    for phrase, code in ((" It is called from copyHelper.", "claimed_caller_not_found"),
                         (" It is invoked by copyHelper.", "claimed_caller_not_found"),
                         (" Its caller is copyHelper.", "claimed_caller_not_found")):
        assert code in findings_for(cs, BASE["analysis"]["purpose"]["statement"] + phrase, "purpose"), phrase
    assert "claimed_caller_not_found" not in findings_for(
        cs, BASE["analysis"]["purpose"]["statement"] + " It is called from main.", "purpose")


def test_contradictions_are_downgraded_when_call_data_cannot_be_trusted(tmp_path):
    root = tmp_path / "t"
    make_checkserial_export(root)
    idx = json.loads((root / "manifest.json").read_text())
    idx["counts"]["functions_truncated"] = True            # export stopped early: absence proves nothing
    (root / "manifest.json").write_text(json.dumps(idx))
    codes = findings_for(Analysis.open(root), "Calls strcpy.")
    assert codes.get("claimed_callee_unverifiable") == "weak" and "claimed_callee_not_called" not in codes


# =========================== quote strength ======================================================================

CASES_QUOTES = [
    ("instruction", "CMP", "0x001011b0", CHECK, S.PARTIAL, "quote_too_short"),
    ("instruction", "RAX", "0x001011b0", CHECK, S.PARTIAL, "quote_too_short"),
    ("instruction", "RET", "0x00101223", CHECK, S.CONFIRMED, "quote_matches"),            # exact short instruction is fine
    ("instruction", "RAX,0x10", "0x001011b0", CHECK, S.CONFIRMED, "quote_is_fragment"),
    ("call", "CALL", "0x001011ab", CHECK, S.PARTIAL, "quote_too_short"),
    ("string", "ser", "0x00102004", MAIN, S.PARTIAL, "quote_too_short"),
    ("string", "Enter", "0x00102004", MAIN, S.CONFIRMED, "string_confirmed"),
    ("xref", "checkSerial rocks", "0x001012a5", CHECK, S.PARTIAL, "xref_quote_unmatched"),  # the function's own name alone proves nothing
    ("xref", "called from main", "0x001012a5", CHECK, S.CONFIRMED, "xref_confirmed"),
    ("xref", "CALL checkSerial", "0x001012a5", CHECK, S.CONFIRMED, "xref_confirmed"),
    ("metadata", "uses 141 threads", None, CHECK, S.UNCHECKABLE, "metadata_not_checkable"),  # short values prove nothing
    ("metadata", "ELF", None, CHECK, S.CONFIRMED, "metadata_confirmed"),
]


@pytest.mark.parametrize("kind,quote,address,function,status,code", CASES_QUOTES)
def test_quote_strength_rules(cs, kind, quote, address, function, status, code):
    r = check_one(cs, kind, quote, address, function)
    assert (r.status, r.code) == (status, code), r.reason


def test_duplicate_evidence_counts_once_in_layer1(cs):
    one = claim_of(RecordValidator(cs).validate(record(
        lambda d: node(d, "behavior[0]").update(evidence=[node(d, "behavior[0]")["evidence"][1]]))), "behavior[0]")
    thrice = claim_of(RecordValidator(cs).validate(record(
        lambda d: node(d, "behavior[0]").update(evidence=[node(d, "behavior[0]")["evidence"][1]] * 3))), "behavior[0]")
    assert one.status is thrice.status is C.VERIFIED
    bad = claim_of(RecordValidator(cs).validate(record(
        lambda d: node(d, "behavior[0]").update(evidence=[node(d, "behavior[0]")["evidence"][1],
                                                           {**node(d, "behavior[0]")["evidence"][1], "quote": "XOR EAX,EAX"}]))),
                   "behavior[0]")
    assert bad.status is C.PARTIALLY_VERIFIED and "1 of 2 evidence items are invalid" in bad.reasons[0]


# =========================== golden: real export ====================================================================

def test_validator_reproduces_the_real_validation_run(cs):
    """tests/data/checkserial_report_real.json was produced by `validate` on the REAL SimpleKeyGen export.
    The reconstructed fixture must give the same claim statuses and evidence results."""
    real = ValidationReport.model_validate_json((DATA / "checkserial_report_real.json").read_text())
    ours = RecordValidator(cs).validate(record())
    assert [c.id for c in real.claims] == [c.id for c in ours.claims]
    for r, o in zip(real.claims, ours.claims):
        assert (r.status, r.evidence_status) == (o.status, o.evidence_status), r.id
        assert [(e.status, e.code) for e in r.evidence] == [(e.status, e.code) for e in o.evidence], r.id
    assert real.integrity.binary_matches is True and ours.integrity.binary_matches is True
    assert real.integrity.context_reproduced is True      # real export: the model's exact input was rebuilt
    assert ours.integrity.context_reproduced is False     # reconstruction: cannot be, by design
