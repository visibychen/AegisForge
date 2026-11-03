import asyncio
from uuid import uuid4

from app.llm.provider import FakeProvider
from app.schemas.contracts import AnalysisRequest


def test_fake_provider_never_claims_that_empty_findings_mean_safe():
    request = AnalysisRequest(
        artifact_id=uuid4(), input_type="source", content="os.system(user_input)"
    )
    result = asyncio.run(FakeProvider().analyze(request))
    assert result.mode == "fake"
    assert result.analysis_complete is False
    assert result.findings == []
    assert result.warnings
