import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from binproof import Analysis, FunctionNotFoundError
from binproof.ai.models import Evidence, FunctionAnalysisRecord
from binproof.validation import (
    ClaimStatus as C, EvidenceStatus as S, RecordValidator, SemanticAssessment, SemanticStatus,
    ValidationInputError, ValidationReport, load_record, render_report,
)
from binproof.validation.claims import extract_claims
from binproof.validation.evidence import EvidenceChecker
from binproof.validation.facts import FunctionFacts
from checkserial_fixture import CHECK, COPY, DISP, MAIN, make_checkserial_export

DATA = Path(__file__).parent / "data" / "checkserial_result.json"


@pytest.fixture
def export(tmp_path):
    root = tmp_path / "cs"
    make_checkserial_export(root)
    return root


@pytest.fixture
def analysis(export):
    return Analysis.open(export)


def raw():
    return json.loads(DATA.read_text())


def record(mutate=None):
    d = raw()
    if mutate:
        mutate(d)
    return FunctionAnalysisRecord.model_validate(d)


def validate(analysis, mutate=None, **kw):
    return RecordValidator(analysis, **kw).validate(record(mutate))


def claim(report, claim_id):
    return next(c for c in report.claims if c.id == claim_id)


def validate_with(analysis):
    return RecordValidator(analysis).validate(record())


def check_one(analysis, function, kind, quote, address=None):
    facts = FunctionFacts.load(analysis, function)
    return EvidenceChecker(facts).check(Evidence(kind=kind, address=address, quote=quote))


# ---- the real checkSerial result ---------------------------------------------------------------

def test_claims_are_linked_to_their_evidence():
    claims = extract_claims(record().analysis)
    assert [c.id for c in claims] == ["purpose", "behavior[0]", "behavior[1]", "behavior[2]", "inputs[0]", "outputs[0]"]
    assert [len(c.evidence) for c in claims] == [2, 3, 3, 2, 2, 2]
    assert claims[4].statement.startswith("param_1 (char *): Pointer to")
    assert claims[0].original["confidence"] == "high"


def test_real_result_against_reconstructed_export(analysis):
    rep = validate(analysis)
    assert rep.summary.total_claims == 6 and rep.summary.total_evidence == 14
    assert {c.status for c in rep.claims} == {C.VERIFIED}
    assert rep.summary.evidence_by_status["confirmed"] == 14
    assert rep.integrity.binary_matches is True
    assert rep.integrity.context_reproduced is False        # the model's real input can't be rebuilt from a reconstruction
    assert any("cannot be reproduced" in n for n in rep.integrity.notes)
    assert any("not run" in l for l in rep.limitations) and any("do not prove" in l for l in rep.limitations)
    assert all(c.semantic.status is SemanticStatus.NOT_ASSESSED for c in rep.claims)


def test_parameter_found_only_in_decompiled_code_is_explained(analysis):
    ev = claim(validate(analysis), "inputs[0]").evidence[1]
    assert ev.status is S.CONFIRMED and ev.code == "parameter_in_code"
    assert "no parameter list" in ev.reason


# ---- deliberately corrupted results --------------------------------------------------------------

def set_ev(path_to_claim, i, **changes):
    def mutate(d):
        node = d["analysis"]
        for key in path_to_claim:
            node = node[key]
        node["evidence"][i].update(changes)
    return mutate


def test_wrong_address_is_not_found_and_other_evidence_still_counts(analysis):
    rep = validate(analysis, set_ev(["behavior", 0], 1, address="0x00109999"))
    c = claim(rep, "behavior[0]")
    assert c.evidence[1].status is S.NOT_FOUND and c.evidence[1].code == "address_not_in_data"
    assert c.evidence[0].status is S.CONFIRMED
    assert c.status is C.PARTIALLY_VERIFIED and "1 of 3 evidence items are invalid" in c.reasons[0]


def test_all_evidence_invalid_means_invalid_evidence(analysis):
    def mutate(d):
        for ev in d["analysis"]["behavior"][0]["evidence"]:
            ev["address"] = "0x00109999"
    c = claim(validate(analysis, mutate), "behavior[0]")
    assert c.status is C.INVALID_EVIDENCE and c.evidence_status is C.INVALID_EVIDENCE


def test_address_that_exists_but_in_another_function(analysis):
    c = claim(validate(analysis, set_ev(["behavior", 0], 1, address=MAIN)), "behavior[0]")
    assert c.evidence[1].code == "address_in_other_function" and "main" in c.evidence[1].reason


def test_fabricated_instruction_at_real_address(analysis):
    c = claim(validate(analysis, set_ev(["behavior", 0], 1, quote="XOR EAX,EAX")), "behavior[0]")
    e = c.evidence[1]
    assert e.status is S.MISMATCH and e.code == "quote_mismatch" and e.actual == "CMP RAX,0x10"
    assert "XOR EAX,EAX" in e.reason and c.status is C.PARTIALLY_VERIFIED


def test_fabricated_decompiled_fragment(analysis):
    c = claim(validate(analysis, set_ev(["purpose"], 0, quote="if (sVar1 == 0x20) { exit(1); }")), "purpose")
    assert c.evidence[0].status is S.NOT_FOUND and c.evidence[0].code == "fragment_not_in_decompiled_code"


def test_missing_evidence_is_unverified(analysis):
    rec = record()
    rec.analysis.behavior[0] = rec.analysis.behavior[0].model_copy(update={"evidence": []})  # bypasses validation
    c = claim(RecordValidator(analysis).validate(rec), "behavior[0]")
    assert c.status is C.UNVERIFIED and c.evidence == []
    assert "no supporting evidence" in c.reasons[0] and c.missing_information == ["supporting evidence for this claim"]


def test_valid_evidence_but_unsupported_claim_is_flagged_not_verified(analysis):
    def mutate(d):
        d["analysis"]["behavior"][0]["statement"] = "Measures the input with strlen and fails if it is not 32 characters."
    c = claim(validate(analysis, mutate), "behavior[0]")
    assert c.evidence_status is C.VERIFIED                      # layer 1: the evidence is real
    assert c.status is C.PARTIALLY_VERIFIED                     # layer 2: the claim says something it doesn't ground
    assert [f.code for f in c.findings if f.severity.value == "weak"] == ["value_not_in_data"]
    assert any("not clearly supported" in r for r in c.reasons)


def test_claim_contradicting_callee_data(analysis):
    def mutate(d):
        d["analysis"]["behavior"][0]["statement"] = "Calls strcpy to copy the serial and fails if it is not 16 characters."
    c = claim(validate(analysis, mutate), "behavior[0]")
    assert c.evidence_status is C.VERIFIED and c.status is C.CONTRADICTED
    assert c.findings[0].code == "claimed_callee_not_called"


def test_caller_claims(analysis):
    def good(d):
        d["analysis"]["purpose"]["statement"] += " It is called by main."
    def bad(d):
        d["analysis"]["purpose"]["statement"] += " It is called by copyHelper."
    assert claim(validate(analysis, good), "purpose").status is C.VERIFIED
    c = claim(validate(analysis, bad), "purpose")
    assert c.status is C.CONTRADICTED and c.findings[0].code == "claimed_caller_not_found"


def test_unrelated_function_mention_is_weak(analysis):
    def mutate(d):
        d["analysis"]["behavior"][1]["statement"] += " Similar to `printf` formatting."
    c = claim(validate(analysis, mutate), "behavior[1]")
    assert c.status is C.PARTIALLY_VERIFIED and c.findings[0].code == "function_mentioned_without_relationship"


def synthetic(function_address, name, statement, evidence, confidence="medium"):
    d = raw()
    d["function"].update(address=function_address, name=name)
    d["analysis"]["purpose"] = {"statement": statement, "evidence": evidence, "confidence": confidence}
    d["analysis"]["behavior"] = [d["analysis"]["purpose"]]
    d["analysis"]["inputs"] = d["analysis"]["outputs"] = []
    d["provenance"]["context_sha256"] = "0" * 64
    return FunctionAnalysisRecord.model_validate(d)


def test_contradiction_is_downgraded_when_indirect_calls_exist(analysis):
    rec = synthetic(DISP, "dispatcher", "Calls strcpy through a function pointer.",
                    [{"kind": "instruction", "address": "0x00101308", "quote": "CALL RAX"}])
    c = claim(RecordValidator(analysis).validate(rec), "purpose")
    assert c.status is C.PARTIALLY_VERIFIED and c.findings[0].code == "claimed_callee_unverifiable"
    assert "indirect calls" in c.findings[0].message


def test_overconfidence_is_flagged(analysis):
    def mutate(d):
        for ev in d["analysis"]["purpose"]["evidence"]:
            ev["quote"] = "completely invented code"
    rep = validate(analysis, mutate)
    assert claim(rep, "purpose").overconfident and rep.summary.overconfident_claims == 1
    assert claim(rep, "behavior[1]").overconfident is False
    assert "overall confidence 'high' is not supported" in rep.summary.overall_confidence_note


# ---- integrity ---------------------------------------------------------------------------------------

def test_wrong_binary_is_reported(analysis):
    rep = validate(analysis, lambda d: d["provenance"].update(program_sha256="ab" * 32))
    assert rep.integrity.binary_matches is False and any("different binary" in n for n in rep.integrity.notes)


def test_function_not_in_export(analysis):
    with pytest.raises(FunctionNotFoundError):
        validate(analysis, lambda d: d["function"].update(address="0x00999999"))


def test_renamed_function_is_noted(analysis):
    rep = validate(analysis, lambda d: d["function"].update(name="oldName"))
    assert any("function name differs" in n for n in rep.integrity.notes)


def test_unavailable_data_is_uncheckable_not_guessed(tmp_path):
    root = tmp_path / "inc"
    make_checkserial_export(root, complete=False, errors=[{"step": "strings", "traceback": "x"}])
    rec = synthetic(MAIN, "main", "Prompts the user.",
                    [{"kind": "string", "address": "0x00102004", "quote": "Enter serial: "}])
    c = claim(RecordValidator(Analysis.open(root, allow_incomplete=True)).validate(rec), "purpose")
    e = c.evidence[0]
    assert e.status is S.UNCHECKABLE and e.code == "data_unavailable" and e.missing_information
    assert c.status is C.UNVERIFIED and c.missing_information


# ---- per-kind evidence checks (layer 1) ------------------------------------------------------------------

CASES = [
    # (function, kind, quote, address, status, code)
    (CHECK, "instruction", "CMP RAX,0x10", "0x001011b0", S.CONFIRMED, "quote_matches"),
    (CHECK, "instruction", "cmp rax, 0x10", "0x001011b0", S.CONFIRMED, "quote_matches"),
    (CHECK, "instruction", "0x001011b0  CMP RAX,0x10", "0x001011b0", S.CONFIRMED, "quote_matches"),
    (CHECK, "instruction", "RAX,0x10", "0x001011b0", S.CONFIRMED, "quote_is_fragment"),
    (CHECK, "instruction", "CMP RAX,0x11", "0x001011b0", S.MISMATCH, "quote_mismatch"),
    (CHECK, "instruction", "CM", "0x001011b0", S.PARTIAL, "quote_too_short"),
    (CHECK, "instruction", "CMP RAX,0x10", "0x001011b1", S.NOT_FOUND, "address_not_an_instruction_start"),
    (CHECK, "instruction", "PUSH RBP", MAIN, S.NOT_FOUND, "address_in_other_function"),
    (CHECK, "instruction", "NOP", "0x00200000", S.NOT_FOUND, "address_not_in_data"),
    (CHECK, "call", "CALL 0x00101040", "0x001011ab", S.CONFIRMED, "call_site_confirmed"),
    (CHECK, "call", "strlen", "0x001011ab", S.CONFIRMED, "call_site_confirmed"),
    (CHECK, "call", "CALL strlen", "0x001011ab", S.CONFIRMED, "call_site_confirmed"),
    (CHECK, "call", "CALL strcpy", "0x001011ab", S.MISMATCH, "call_quote_mismatch"),
    (CHECK, "call", "CMP RAX,0x10", "0x001011b0", S.MISMATCH, "not_a_call"),
    (DISP, "call", "CALL RAX", "0x00101308", S.CONFIRMED, "indirect_call"),
    (MAIN, "string", "Enter serial: ", "0x00102004", S.CONFIRMED, "string_confirmed"),
    (MAIN, "string", "\"Enter serial: \"", "0x00102004", S.CONFIRMED, "string_confirmed"),
    (MAIN, "string", "Enter serial: ", "0x00101275", S.CONFIRMED, "string_confirmed"),     # referencing site
    (MAIN, "string", "Enter password", "0x00102004", S.MISMATCH, "string_value_mismatch"),
    (CHECK, "string", "Enter serial: ", "0x00102004", S.MISMATCH, "string_not_referenced_by_function"),
    (MAIN, "string", "anything", "0x00109000", S.NOT_FOUND, "string_not_found"),
    (CHECK, "import", "strlen", None, S.CONFIRMED, "import_confirmed"),
    (CHECK, "import", "strlen()", "0x001011ab", S.CONFIRMED, "import_confirmed"),
    (CHECK, "import", "strlen", "0x00101111", S.PARTIAL, "address_not_a_use_site"),
    (CHECK, "import", "printf", None, S.MISMATCH, "import_not_used_by_function"),
    (CHECK, "import", "<EXTERNAL>!strlen", None, S.CONFIRMED, "import_confirmed"),
    (CHECK, "import", "msvcrt.dll!strlen", None, S.MISMATCH, "import_library_mismatch"),
    (CHECK, "import", "gets", None, S.NOT_FOUND, "import_not_found"),
    (CHECK, "import", "main", None, S.NOT_FOUND, "not_an_import"),
    (CHECK, "xref", "CALL checkSerial", "0x001012a5", S.CONFIRMED, "xref_confirmed"),
    (CHECK, "xref", "something unrelated", "0x001012a5", S.PARTIAL, "xref_quote_unmatched"),
    (CHECK, "xref", "CALL checkSerial", "0x001011ab", S.NOT_FOUND, "no_reference_at_address"),
    (CHECK, "xref", "CALL checkSerial", "0x00300000", S.NOT_FOUND, "no_reference_at_address"),
    (CHECK, "decompiled_code", "if (sVar1 == 0x10)", None, S.CONFIRMED, "fragment_confirmed"),
    (CHECK, "decompiled_code", "if(sVar1==0x10){", None, S.CONFIRMED, "fragment_confirmed"),
    (CHECK, "decompiled_code", "if (sVar1 == 0x10) ... return uVar2;", None, S.CONFIRMED, "fragment_confirmed"),
    (CHECK, "decompiled_code", "return uVar2; ... if (sVar1 == 0x10)", None, S.NOT_FOUND, "fragment_not_in_decompiled_code"),
    (CHECK, "decompiled_code", "free(param_1);", None, S.NOT_FOUND, "fragment_not_in_decompiled_code"),
    (CHECK, "decompiled_code", "if", None, S.PARTIAL, "fragment_too_short"),
    (CHECK, "decompiled_code", "return uVar2;", "0x00109999", S.PARTIAL, "address_not_in_function"),
    (CHECK, "decompiled_code", "return uVar2;", "0x001011b0", S.CONFIRMED, "fragment_confirmed"),
    (CHECK, "parameter", "param_1", None, S.CONFIRMED, "parameter_in_code"),
    (CHECK, "parameter", "char *param_1", None, S.CONFIRMED, "parameter_in_code"),
    (CHECK, "parameter", "param_7", None, S.NOT_FOUND, "parameter_not_found"),
    (CHECK, "metadata", "checkSerial", None, S.CONFIRMED, "metadata_confirmed"),
    (CHECK, "metadata", "x86:LE:64:default", None, S.CONFIRMED, "metadata_confirmed"),
    (CHECK, "metadata", "uses a custom packer", None, S.UNCHECKABLE, "metadata_not_checkable"),
]


@pytest.mark.parametrize("function,kind,quote,address,status,code", CASES)
def test_evidence_checks(analysis, function, kind, quote, address, status, code):
    result = check_one(analysis, function, kind, quote, address)
    assert (result.status, result.code) == (status, code), result.reason


def test_failed_functions_step_means_nothing_can_be_validated(tmp_path):
    from binproof import ArtifactUnavailableError
    root = tmp_path / "x"
    make_checkserial_export(root, complete=False, errors=[{"step": "functions", "traceback": "x"}])
    # function records are untrusted when their step failed, so validation refuses instead of guessing
    with pytest.raises(ArtifactUnavailableError):
        validate_with(Analysis.open(root, allow_incomplete=True))


# ---- layer 3: pluggable semantic verification ---------------------------------------------------------------

class FakeVerifier:
    name = "fake-judge"

    def __init__(self, status):
        self.status, self.seen = status, []

    def assess(self, claim, checks, facts):
        self.seen.append(claim.id)
        return SemanticAssessment(status=self.status, method=self.name, rationale="because")


class BrokenVerifier:
    name = "broken"

    def assess(self, claim, checks, facts):
        raise RuntimeError("boom")


def test_semantic_verdicts_lower_the_status(analysis):
    weak = validate(analysis, semantic_verifier=FakeVerifier(SemanticStatus.WEAK))
    assert {c.status for c in weak.claims} == {C.PARTIALLY_VERIFIED}
    assert all(c.evidence_status is C.VERIFIED for c in weak.claims)         # layers stay separate
    assert weak.claims[0].semantic.method == "fake-judge"
    assert not any("Semantic verification (layer 3) was not run." == l for l in weak.limitations)
    bad = validate(analysis, semantic_verifier=FakeVerifier(SemanticStatus.UNSUPPORTED))
    assert {c.status for c in bad.claims} == {C.UNVERIFIED}
    ok = validate(analysis, semantic_verifier=FakeVerifier(SemanticStatus.SUPPORTED))
    assert {c.status for c in ok.claims} == {C.VERIFIED}


def test_broken_semantic_verifier_does_not_break_validation(analysis):
    rep = validate(analysis, semantic_verifier=BrokenVerifier())
    c = rep.claims[0]
    assert c.status is C.VERIFIED and c.semantic.status is SemanticStatus.NOT_ASSESSED
    assert "failed" in c.semantic.rationale


# ---- report format / loader ----------------------------------------------------------------------------------------

def test_report_round_trips_as_json_and_keeps_original_claims(analysis):
    rep = validate(analysis, set_ev(["behavior", 0], 1, quote="XOR EAX,EAX"))
    again = ValidationReport.model_validate_json(rep.model_dump_json())
    assert again == rep
    assert claim(again, "behavior[0]").original_claim["evidence"][1]["quote"] == "XOR EAX,EAX"
    text = render_report(rep)
    assert "[PARTIALLY_VERIFIED] behavior[0]" in text and "[XX] instruction @ 0x001011b0" in text
    assert "STATUS KEY" in text


def test_loader_errors(tmp_path):
    with pytest.raises(ValidationInputError, match="cannot read"):
        load_record(tmp_path / "nope.json")
    junk = tmp_path / "junk.json"
    junk.write_text("not json")
    with pytest.raises(ValidationInputError, match="not a valid BinProof analysis result"):
        load_record(junk)
    d = raw()
    d["analysis"]["purpose"]["evidence"] = []
    bad = tmp_path / "noev.json"
    bad.write_text(json.dumps(d))
    with pytest.raises(ValidationInputError, match="purpose.evidence"):
        load_record(bad)
    assert load_record(DATA).function.name == "checkSerial"


# ---- independence ------------------------------------------------------------------------------------------------------

def test_validation_runs_with_all_provider_code_blocked(export, tmp_path):
    code = ("import sys\n"
            "for m in ('binproof.ai.providers', 'binproof.ai.analyzer', 'binproof.ai.config'):\n"
            "    sys.modules[m] = None\n"
            "from binproof.cli import main\n"
            "sys.exit(main(['validate', %r, '--result', %r]))\n" % (str(export), str(DATA)))
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).parent.parent))
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    assert r.returncode == 0 and "VERIFIED 6" in r.stdout, r.stderr


# ---- CLI ----------------------------------------------------------------------------------------------------------------

def test_cli_validate_text_and_saved_report(export, tmp_path, capsys):
    from binproof.cli import main
    out = tmp_path / "report.json"
    assert main(["validate", str(export), "-r", str(DATA), "-o", str(out)]) == 0
    printed = capsys.readouterr()
    assert "VERIFIED 6" in printed.out and "Saved validation report" in printed.err
    assert ValidationReport.model_validate_json(out.read_text()).summary.total_claims == 6


def test_cli_json_output_and_fail_on(export, tmp_path, capsys):
    from binproof.cli import main
    d = raw()
    d["analysis"]["behavior"][0]["evidence"][1]["quote"] = "XOR EAX,EAX"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(d))
    assert main(["validate", str(export), "-r", str(bad), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["claims_by_status"]["PARTIALLY_VERIFIED"] == 1
    assert main(["validate", str(export), "-r", str(bad), "--fail-on", "partial"]) == 1
    assert main(["validate", str(export), "-r", str(bad), "--fail-on", "invalid"]) == 0
    assert main(["validate", str(export), "-r", str(DATA), "--fail-on", "partial"]) == 0
    capsys.readouterr()


def test_cli_errors_exit_2(export, tmp_path, capsys):
    from binproof.cli import main
    assert main(["validate", str(export), "-r", str(tmp_path / "missing.json")]) == 2
    assert "cannot read" in capsys.readouterr().err
    junk = tmp_path / "j.json"
    junk.write_text("{}")
    assert main(["validate", str(export), "-r", str(junk)]) == 2
    d = raw()
    d["function"]["address"] = "0x00999999"
    other = tmp_path / "other.json"
    other.write_text(json.dumps(d))
    assert main(["validate", str(export), "-r", str(other)]) == 2
    assert "no function at" in capsys.readouterr().err
    assert main(["validate", str(export / "nope"), "-r", str(DATA)]) == 2
