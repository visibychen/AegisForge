from uuid import uuid4

import pytest
from app.schemas.contracts import AnalysisResult, Finding, RepairCreate, ScanCreate
from pydantic import ValidationError


def valid_finding():
    return {
        "category": "xss",
        "cwe": "CWE-79",
        "severity": "high",
        "location": {"kind": "source", "artifact_id": str(uuid4()), "start_line": 2, "end_line": 3},
        "evidence": "return user_input",
        "explanation": "Unescaped output",
        "recommendation": "Use context-aware escaping",
        "sources": ["llm"],
    }


@pytest.mark.parametrize(
    "change",
    [
        {"cwe": "CWE-89"},
        {"severity": "certain"},
        {"confidence": 1.5},
        {"evidence_status": "verified"},
        {"sources": ["llm", "llm"]},
        {"unexpected": "ignored?"},
    ],
)
def test_invalid_or_unverifiable_model_claims_are_rejected(change):
    with pytest.raises(ValidationError):
        Finding.model_validate(valid_finding() | change)


def test_source_line_range_and_http_evidence_boundary():
    data = valid_finding()
    data["location"]["end_line"] = 1
    with pytest.raises(ValidationError):
        Finding.model_validate(data)
    http = valid_finding() | {
        "location": {"kind": "http", "artifact_id": str(uuid4()), "field": "query.q"},
        "evidence_status": "attack_indicator",
    }
    assert Finding.model_validate(http).evidence_status == "attack_indicator"
    with pytest.raises(ValidationError):
        Finding.model_validate(valid_finding() | {"evidence_status": "attack_indicator"})


def test_scan_inputs_are_bounded_and_unique():
    artifact = uuid4()
    assert ScanCreate(artifact_ids=[artifact]).artifact_ids == [artifact]
    for ids in [[], [artifact, artifact], [uuid4() for _ in range(11)]]:
        with pytest.raises(ValidationError):
            ScanCreate(artifact_ids=ids)


def test_fake_cannot_claim_real_completion_and_repairs_require_valid_hash():
    with pytest.raises(ValidationError):
        AnalysisResult(mode="fake", analysis_complete=True)
    with pytest.raises(ValidationError):
        RepairCreate(source_sha256="../untrusted")
    assert RepairCreate(source_sha256="a" * 64).source_sha256 == "a" * 64
