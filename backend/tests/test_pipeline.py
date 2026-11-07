import asyncio

from app.llm.deepseek import ProviderError
from app.schemas.contracts import AnalysisResult, Finding, SourceLocation
from app.worker.runner import run_once
from tests.test_scans import create


def configure(api, monkeypatch):
    monkeypatch.setenv("AEGISFORGE_DEEPSEEK_API_KEY", "synthetic-pipeline-key")
    api.app.state.settings.model_mode = "real"


def test_hybrid_keeps_rule_results_when_model_fails(api, monkeypatch):
    configure(api, monkeypatch)

    class Failure:
        async def analyze(self, _request):
            raise ProviderError("MODEL_TRANSPORT")

    scan_id = create(api, strategy="hybrid", alias="deepseek").json()["scan"]["id"]
    asyncio.run(run_once(api.app.state.engine, api.app.state.settings, lambda *_: Failure()))
    scan = api.get(f"/api/v1/scans/{scan_id}").json()["scan"]
    assert scan["status"] == "partial" and scan["error_code"] == "MODEL_TRANSPORT"
    assert api.get(f"/api/v1/scans/{scan_id}/findings").json()["total"] == 1


def test_merge_keeps_severity_disagreement_and_both_contributions(api, monkeypatch):
    configure(api, monkeypatch)

    class Reply:
        async def analyze(self, request):
            return AnalysisResult(
                mode="real",
                analysis_complete=True,
                findings=[
                    Finding(
                        category="cmdi",
                        cwe="CWE-78",
                        severity="low",
                        sources=["llm"],
                        location=SourceLocation(
                            artifact_id=request.artifact_id, start_line=2, end_line=2
                        ),
                        evidence="os.system(request.args['cmd'])",
                        explanation="Model assessment",
                        recommendation="Use a fixed executable and argument list",
                    )
                ],
            )

    scan_id = create(api, strategy="hybrid", alias="deepseek").json()["scan"]["id"]
    asyncio.run(run_once(api.app.state.engine, api.app.state.settings, lambda *_: Reply()))
    assert api.get(f"/api/v1/scans/{scan_id}").json()["scan"]["status"] == "completed"
    result = api.get(f"/api/v1/scans/{scan_id}/findings").json()
    finding = result["findings"][0]
    assert result["total"] == 1 and finding["sources"] == ["rule", "llm"]
    assert finding["severity_disagreement"] and len(finding["contributors"]) == 2
