"""Model wire protocol (prompt analysis-1.1): only what the model is allowed to say.

The server, not the model, decides provenance (``sources``), mode, completeness, artifact
identity, evidence truncation and the final severity. Any of those keys, ``verified`` or any
other extra key in model output is a schema violation.
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

WIRE_SCHEMA_VERSION = "1.1"


class Wire(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WireSourceLocation(Wire):
    kind: Literal["source"]
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)


class WireHttpLocation(Wire):
    kind: Literal["http"]
    field: str = Field(min_length=1, max_length=200)


class WireFinding(Wire):
    category: Literal["xss", "sqli", "cmdi"]
    cwe: Literal["CWE-79", "CWE-89", "CWE-78"]
    severity: Literal["critical", "high", "medium", "low", "info"]  # model opinion only
    location: Annotated[WireSourceLocation | WireHttpLocation, Field(discriminator="kind")]
    evidence: str = Field(min_length=1, max_length=2000)
    explanation: str = Field(min_length=1, max_length=2000)
    recommendation: str = Field(min_length=1, max_length=2000)
    evidence_status: Literal["potential", "attack_indicator"] = "potential"
    confidence: float | None = Field(default=None, ge=0, le=1)


class WireResult(Wire):
    schema_version: Literal["1.1"]
    findings: list[WireFinding] = Field(default_factory=list, max_length=50)
    warnings: list[str] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def bounded_warnings(self):
        if any(len(warning) > 500 for warning in self.warnings):
            raise ValueError("warning exceeds output budget")
        return self


EXAMPLE = {
    "schema_version": WIRE_SCHEMA_VERSION,
    "findings": [
        {
            "category": "sqli",
            "cwe": "CWE-89",
            "severity": "high",
            "location": {"kind": "source", "start_line": 12, "end_line": 12},
            "evidence": 'cursor.execute("SELECT id FROM users WHERE name = \'" + name + "\'")',
            "explanation": "User-controlled name is concatenated into SQL text.",
            "recommendation": "Use a parameterized query: cursor.execute(sql, (name,)).",
            "evidence_status": "potential",
            "confidence": 0.8,
        }
    ],
    "warnings": [],
}
