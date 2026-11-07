import asyncio
import json
from uuid import uuid4

import pytest
from app.llm.deepseek import validate_result
from app.parsers.inputs import parse_input
from app.rules.detector import detect
from app.schemas.contracts import AnalysisRequest, AnalysisResult, Finding, SourceLocation
from app.worker.runner import hints_for, run_once
from tests.test_scans import create


def test_model_location_must_be_tight_to_its_evidence():
    artifact_id = uuid4()
    request = AnalysisRequest(
        artifact_id=artifact_id,
        input_type="source",
        content="x=1\ncursor.execute(q)\ny=2",
        start_line=1,
        end_line=3,
    )
    finding = Finding(
        category="sqli",
        cwe="CWE-89",
        severity="high",
        sources=["llm"],
        location=SourceLocation(artifact_id=artifact_id, start_line=1, end_line=3),
        evidence="cursor.execute(q)",
        explanation="Dynamic query",
        recommendation="Bind parameters",
    )
    try:
        checked = validate_result(
            AnalysisResult(mode="real", analysis_complete=True, findings=[finding]), request
        )
    except ValueError:
        return  # Rejection or exact server normalization are both acceptable.
    assert checked.findings[0].location.start_line == checked.findings[0].location.end_line == 2


def test_punctuation_alone_is_not_supported_source_evidence():
    artifact_id = uuid4()
    request = AnalysisRequest(artifact_id=artifact_id, input_type="source", content="x=1")
    finding = Finding(
        category="sqli",
        cwe="CWE-89",
        severity="high",
        sources=["llm"],
        location=SourceLocation(artifact_id=artifact_id, start_line=1, end_line=1),
        evidence="=",
        explanation="Unsupported claim",
        recommendation="Bind parameters",
    )
    with pytest.raises(ValueError):
        validate_result(
            AnalysisResult(mode="real", analysis_complete=True, findings=[finding]), request
        )


def test_http_hints_only_reference_the_current_chunk():
    body = json.dumps(
        {f"field{i}": ("<script>" + "a" * 2990 if i == 0 else "b" * 3000) for i in range(18)},
        indent=2,
    )
    parsed = parse_input("http", "POST / HTTP/1.1\nContent-Type: application/json\n\n" + body)
    rules = detect(uuid4(), "http", parsed)
    chunk = parsed.chunks[-1]
    fields = {line.partition(" ")[0] for line in chunk.content.split("\n")}
    assert all(h.location.field in fields for h in hints_for(rules.findings, chunk))


def test_unexpected_provider_error_preserves_completed_rule_analysis(api, monkeypatch):
    monkeypatch.setenv("AEGISFORGE_DEEPSEEK_API_KEY", "synthetic-review-key")
    api.app.state.settings.model_mode = "real"

    class Broken:
        async def analyze(self, _request):
            raise RuntimeError("private internal diagnostic")

    scan_id = create(api, strategy="hybrid", alias="deepseek").json()["scan"]["id"]
    asyncio.run(run_once(api.app.state.engine, api.app.state.settings, lambda *_: Broken()))
    scan = api.get(f"/api/v1/scans/{scan_id}").json()["scan"]
    assert scan["status"] == "partial"
    assert api.get(f"/api/v1/scans/{scan_id}/findings").json()["total"] == 1
