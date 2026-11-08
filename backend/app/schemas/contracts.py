from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Strategy(StrEnum):
    RULES = "rules"
    LLM = "llm"
    HYBRID = "hybrid"


class ScanCreate(Contract):
    artifact_ids: list[UUID] = Field(min_length=1, max_length=10)
    strategy: Strategy = Strategy.HYBRID
    model_alias: Literal["fake", "deepseek"] = "fake"

    @model_validator(mode="after")
    def unique_artifacts(self):
        if len(set(self.artifact_ids)) != len(self.artifact_ids):
            raise ValueError("artifact_ids must be unique")
        return self


class SourceLocation(Contract):
    kind: Literal["source"] = "source"
    artifact_id: UUID
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)

    @model_validator(mode="after")
    def ordered_lines(self):
        if self.end_line < self.start_line:
            raise ValueError("end_line must not precede start_line")
        return self


class HttpLocation(Contract):
    kind: Literal["http"] = "http"
    artifact_id: UUID
    field: str = Field(min_length=1, max_length=200)


class Finding(Contract):
    category: Literal["xss", "sqli", "cmdi"]
    cwe: Literal["CWE-79", "CWE-89", "CWE-78"]
    severity: Literal["critical", "high", "medium", "low", "info"]
    location: Annotated[SourceLocation | HttpLocation, Field(discriminator="kind")]
    evidence: str = Field(min_length=1, max_length=4000)
    # True only when a rule cut an original excerpt at 4,000 chars; never append filler text.
    evidence_truncated: bool = False
    explanation: str = Field(min_length=1, max_length=8000)
    recommendation: str = Field(min_length=1, max_length=8000)
    sources: list[Literal["rule", "llm"]] = Field(min_length=1, max_length=2)
    evidence_status: Literal["potential", "attack_indicator"] = "potential"
    confidence: float | None = Field(default=None, ge=0, le=1)

    @model_validator(mode="after")
    def coherent_evidence(self):
        expected = {"xss": "CWE-79", "sqli": "CWE-89", "cmdi": "CWE-78"}
        if self.cwe != expected[self.category]:
            raise ValueError("CWE does not match category")
        if self.location.kind == "source" and self.evidence_status == "attack_indicator":
            raise ValueError("attack_indicator is reserved for HTTP input")
        if len(set(self.sources)) != len(self.sources):
            raise ValueError("sources must be unique")
        return self


class AnalysisRequest(Contract):
    artifact_id: UUID
    input_type: Literal["source", "http"]
    content: str = Field(min_length=1, max_length=12000)
    start_line: int = Field(default=1, ge=1)
    end_line: int = Field(default=1, ge=1)
    fields: dict[str, str] = Field(default_factory=dict, max_length=1000)
    rule_hints: list[Finding] = Field(default_factory=list, max_length=8)


class AnalysisResult(Contract):
    schema_version: Literal["1.0"] = "1.0"
    mode: Literal["fake", "real"]
    analysis_complete: bool
    findings: list[Finding] = Field(default_factory=list, max_length=100)
    warnings: list[str] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def bounded_warnings(self):
        if any(len(warning) > 1000 for warning in self.warnings):
            raise ValueError("warning exceeds output budget")
        return self

    @model_validator(mode="after")
    def fake_cannot_claim_analysis(self):
        if self.mode == "fake" and self.analysis_complete:
            raise ValueError("fake provider cannot claim completed real analysis")
        return self


class RepairCreate(Contract):
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ValidationStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    UNVERIFIED = "unverified"
    ERROR = "error"


class HealthResponse(Contract):
    status: Literal["ok"] = "ok"
    request_id: str


class CapabilitiesResponse(Contract):
    request_id: str
    version: str
    stage: Literal["M4"] = "M4"
    model_mode: Literal["fake", "real"] = "fake"
    analysis_available: Literal[True] = True
    model_aliases: list[str] = ["fake"]
    repair_available: Literal[True] = True
    dynamic_validation_available: Literal[True] = True
    supported_input_types: list[str] = ["source", "http"]
    planned_input_types: list[str] = ["source", "http"]
    max_file_bytes: int
    max_files: int
    max_total_bytes: int


class ErrorDetail(Contract):
    code: str
    message: str


class ErrorResponse(Contract):
    request_id: str
    error: ErrorDetail
