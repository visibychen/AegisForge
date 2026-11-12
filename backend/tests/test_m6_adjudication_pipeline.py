import asyncio
import json

from app.schemas.contracts import AnalysisResult, Finding, SourceLocation
from app.services.report_integrity import verify_bytes
from app.services.reports import proof_summary
from app.worker.runner import run_once
from tests.test_pipeline import configure
from tests.test_scans import create, upload


def test_refuted_model_clue_is_visible_but_does_not_leak_prose_in_reports(api, monkeypatch):
    configure(api, monkeypatch)
    source = (
        "import subprocess\nfrom flask import request\n"
        'subprocess.run(["wc", "--", request.args["path"]], shell=False)\n'
    )

    class Reply:
        async def analyze(self, request):
            return AnalysisResult(
                mode="real",
                analysis_complete=True,
                findings=[
                    Finding(
                        category="cmdi",
                        cwe="CWE-78",
                        severity="high",
                        sources=["llm"],
                        location=SourceLocation(
                            artifact_id=request.artifact_id, start_line=3, end_line=3
                        ),
                        evidence=source.splitlines()[2],
                        explanation="PRIVATE_MODEL_TEXT",
                        recommendation="PRIVATE_RECOMMENDATION",
                    )
                ],
            )

    ident = create(api, [upload(api, source)], strategy="hybrid", alias="deepseek").json()["scan"][
        "id"
    ]
    asyncio.run(run_once(api.app.state.engine, api.app.state.settings, lambda *_: Reply()))
    result = api.get(f"/api/v1/scans/{ident}").json()["scan"]["result"]
    assert result["finding_count"] == 0 and result["raw_finding_count"] == 1
    proof = result["adjudication"]
    assert proof["refuted"] == 1 and proof["by_criterion"] == {"argv_data_operands": 1}
    assert proof["refuted_findings"][0]["contributors"][0]["explanation"] == "PRIVATE_MODEL_TEXT"
    assert api.get(f"/api/v1/scans/{ident}/findings").json()["total"] == 0
    exported = api.get(f"/api/v1/workspace/{ident}/report")
    report = verify_bytes(exported.content)
    assert report["scan"]["adjudication"]["refuted"] == 1
    for forbidden in ("PRIVATE_MODEL_TEXT", "PRIVATE_RECOMMENDATION", "subprocess.run", "path"):
        assert forbidden not in exported.text
    md = api.get(f"/api/v1/workspace/{ident}/report?format=markdown")
    assert "依据受限静态判据排除 1 条" in md.text


def test_report_proof_summary_rejects_unknown_names_and_noninteger_counts():
    value = {
        "version": "adjudication-1.3",
        "examined": True,
        "kept": 10001,
        "refuted": "secret",
        "refuted_findings": [{"contributors": "SECRET"}],
        "by_criterion": {"SECRET": 1, "argv_data_operands": False},
    }
    public = proof_summary(value)
    assert public["examined"] is None and public["kept"] is None and public["refuted"] is None
    assert public["by_criterion"] == {"argv_data_operands": None}
    assert "SECRET" not in json.dumps(public)
    value["by_criterion"] = ["SECRET"]
    assert proof_summary(value)["by_criterion"] == {}
