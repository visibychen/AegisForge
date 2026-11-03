from typing import Protocol

from app.schemas.contracts import AnalysisRequest, AnalysisResult


class AnalysisProvider(Protocol):
    async def analyze(self, request: AnalysisRequest) -> AnalysisResult: ...


class FakeProvider:
    """Contract fixture only: it neither detects vulnerabilities nor confirms safety."""

    async def analyze(self, request: AnalysisRequest) -> AnalysisResult:
        return AnalysisResult(
            mode="fake",
            analysis_complete=False,
            warnings=["模拟 Provider 未执行真实模型分析，空发现不代表输入安全。"],
        )
