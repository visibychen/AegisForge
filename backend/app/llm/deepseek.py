import asyncio
import json
import re
import time
from bisect import bisect_right
from collections.abc import Callable

import httpx
from pydantic import ValidationError

from app.core.config import Settings
from app.core.errors import DomainError
from app.core.redaction import redact_text
from app.llm.prompts import MAX_MODEL_SPAN, messages
from app.llm.wire import WireResult
from app.schemas.contracts import (
    AnalysisRequest,
    AnalysisResult,
    Finding,
    HttpLocation,
    SourceLocation,
)

DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"
# Stable, content-free reasons for rejected model output (stored per call for diagnosis).
FAILURE_CATEGORIES = (
    "envelope",  # transport JSON / choices structure unusable
    "truncated",  # finish_reason other than stop
    "json",  # message content is not strict JSON
    "schema",  # wire schema / server contract violated (extra keys, sources, verified...)
    "incomplete",  # server-side result not marked complete
    "provenance",  # server-side finding not attributed to the model alone
    "location",  # wrong artifact/kind or line range outside the chunk
    "location_mismatch",  # verbatim evidence exists, but outside the declared range
    "field",  # unknown HTTP field
    "evidence",  # evidence absent from the claimed place
    "evidence_weak",  # punctuation-only or uninformative evidence
    "ambiguous_evidence",  # several distinct places match inside the claimed range
    "span",  # grounded evidence spans more lines than the model policy allows
    "credential",  # provider credential echoed
    # Repair edits failing the exact apply_edits checks (services/patches.check_edits).
    "patch_conflict",  # old_text differs from the immutable snapshot lines
    "patch_range",  # edit range outside the file, overlapping or unordered
    "patch_newline",  # replacement drops the line ending of the replaced lines
)
_INFORMATIVE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
_ALNUM = re.compile(r"[A-Za-z0-9]")
# Server-computed correction facts are integers and fixed words only; never source or model text.
_DETAIL = re.compile(r"[A-Za-z0-9_ ,;:=.\-()\[\]]{1,240}")


class ProviderError(DomainError):
    def __init__(self, code: str, category: str | None = None):
        super().__init__(code, "模型分析未完成；具体原因见任务错误码。", 503)
        self.category = category
        self.detail: str | None = None  # server-computed integers/words of the last rejection


class OutputRejected(ValueError):
    """A rejected model output. ``detail`` carries only server-computed integers/words for the
    single correction round; str(error) stays the bare category (tests and logs rely on it)."""

    def __init__(self, category: str, detail: str | None = None):
        super().__init__(category)
        self.category = category
        self.detail = detail if detail and _DETAIL.fullmatch(detail) else None


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def constant(_value):
        raise ValueError("non-finite JSON value")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def _ground_source(item: Finding, request: AnalysisRequest) -> Finding:
    """Pin a model source finding to the exact lines of its verbatim evidence."""
    location = item.location
    if not request.start_line <= location.start_line <= location.end_line <= request.end_line:
        raise OutputRejected("location")
    evidence = item.evidence
    if len(re.sub(r"\s+", "", evidence)) < 6 or not _INFORMATIVE.search(evidence):
        raise OutputRejected("evidence_weak")
    content = request.content
    starts = [0] + [index + 1 for index, char in enumerate(content) if char == "\n"]
    spans: set[tuple[int, int]] = set()
    elsewhere: list[tuple[int, int]] = []  # other occurrences; used for the hint only
    position = content.find(evidence)
    while position != -1 and len(spans) < 2:  # identical stop rule to the original check
        first = bisect_right(starts, position) - 1 + request.start_line
        last = bisect_right(starts, position + len(evidence) - 1) - 1 + request.start_line
        if first <= location.end_line and last >= location.start_line:
            spans.add((first, last))
        elif len(elsewhere) < 3:
            elsewhere.append((first, last))
        position = content.find(evidence, position + 1)
    if not spans:
        if evidence not in content:
            raise OutputRejected("evidence")
        # The check is unchanged (the declared range must intersect the evidence). The correction
        # round only learns where the verbatim text really is, as integers.
        places = ",".join(f"{a}-{b}" for a, b in elsewhere)
        raise OutputRejected(
            "location_mismatch",
            f"declared {location.start_line}-{location.end_line}; evidence lines {places}",
        )
    if len(spans) > 1:
        places = ",".join(f"{a}-{b}" for a, b in sorted(spans))
        raise OutputRejected("ambiguous_evidence", f"evidence lines inside the range {places}")
    first, last = spans.pop()
    if last - first + 1 > MAX_MODEL_SPAN:
        raise OutputRejected("span")
    narrowed = location.model_copy(update={"start_line": first, "end_line": last})
    return item.model_copy(update={"location": narrowed})


def validate_result(result: AnalysisResult, request: AnalysisRequest) -> AnalysisResult:
    """Server-side check of model findings; returns a copy with grounded locations."""
    if result.mode != "real" or not result.analysis_complete:
        raise OutputRejected("incomplete")
    checked = []
    for number, item in enumerate(result.findings, 1):
        location = item.location
        if location.artifact_id != request.artifact_id or location.kind != request.input_type:
            raise OutputRejected("location")
        if item.sources != ["llm"] or item.evidence_truncated:
            raise OutputRejected("provenance")
        if not item.evidence.strip():
            raise OutputRejected("evidence")
        if location.kind == "source":
            try:
                checked.append(_ground_source(item, request))
            except OutputRejected as rejected:
                if rejected.detail:
                    rejected.detail = f"finding {number}; {rejected.detail}"
                raise
            continue
        if location.field not in request.fields:
            raise OutputRejected("field")
        value = request.fields[location.field]
        if item.evidence not in value:
            raise OutputRejected("evidence")
        # Short HTTP values may be proven in full; partial quotes must carry content.
        if item.evidence.strip() != value.strip() and not _ALNUM.search(item.evidence):
            raise OutputRejected("evidence_weak")
        checked.append(item)
    return result.model_copy(update={"findings": checked})


def to_result(data, request: AnalysisRequest) -> AnalysisResult:
    """Convert model wire output into a server result; the server assigns provenance."""
    try:
        wire = WireResult.model_validate(data)
        findings = []
        for item in wire.findings:
            if item.location.kind != request.input_type:
                raise OutputRejected("location")
            location = (
                SourceLocation(
                    artifact_id=request.artifact_id,
                    start_line=item.location.start_line,
                    end_line=item.location.end_line,
                )
                if item.location.kind == "source"
                else HttpLocation(artifact_id=request.artifact_id, field=item.location.field)
            )
            findings.append(
                Finding(
                    category=item.category,
                    cwe=item.cwe,
                    severity=item.severity,
                    location=location,
                    evidence=item.evidence,
                    explanation=item.explanation,
                    recommendation=item.recommendation,
                    sources=["llm"],
                    evidence_status=item.evidence_status,
                    confidence=item.confidence,
                )
            )
        result = AnalysisResult(
            mode="real", analysis_complete=True, findings=findings, warnings=wire.warnings
        )
    except ValidationError:
        raise OutputRejected("schema") from None
    return validate_result(result, request)


def clean_public(value, key: str):
    if isinstance(value, dict):
        return {name: clean_public(item, key) for name, item in value.items()}
    if isinstance(value, list):
        return [clean_public(item, key) for item in value]
    if isinstance(value, str):
        return redact_text(value.replace(key, "[REDACTED]") if key else value)
    return value


def decode_wire(content: bytes, usage: dict):
    """Decode one response; ``usage`` is filled first so rejected outputs still count tokens."""
    try:
        envelope = strict_json(content)
        if not isinstance(envelope, dict):
            raise ValueError("invalid envelope")
        raw_usage = envelope.get("usage")
        usage.update(raw_usage if isinstance(raw_usage, dict) else {})
        choice = envelope["choices"][0]
        finish_reason = choice.get("finish_reason")
        message = choice["message"]["content"]
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError):
        raise OutputRejected("envelope") from None
    if finish_reason != "stop":
        raise ProviderError("MODEL_OUTPUT_TRUNCATED", "truncated")
    try:
        data = strict_json(message)
    except (ValueError, TypeError, RecursionError):
        raise OutputRejected("json") from None
    return data


def _decode(content: bytes, request: AnalysisRequest, key: str, usage: dict) -> AnalysisResult:
    result = to_result(decode_wire(content, usage), request)
    for finding in result.findings:
        if key in finding.evidence:
            raise OutputRejected("credential")
        # Verified evidence stays verbatim; free text from the model is redacted again.
        finding.explanation = clean_public(finding.explanation, key)
        finding.recommendation = clean_public(finding.recommendation, key)
    result.warnings = [text[:1000] for text in clean_public(result.warnings, key)]
    return result


class DeepSeekProvider:
    def __init__(
        self,
        settings: Settings,
        reserve: Callable,
        finish: Callable,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.settings, self.reserve, self.finish, self.transport = (
            settings,
            reserve,
            finish,
            transport,
        )

    async def analyze(self, request: AnalysisRequest) -> AnalysisResult:
        return await self._run(request)

    async def _run(self, request: AnalysisRequest, render=None, decode=None):
        render, decode = render or messages, decode or _decode
        settings = self.settings
        key = settings.deepseek_api_key.get_secret_value()
        if not settings.valid_model_key:
            raise ProviderError("MODEL_NOT_CONFIGURED")
        network_retries, corrections, previous, previous_detail = 0, 0, None, None
        async with httpx.AsyncClient(
            transport=self.transport,
            timeout=settings.model_timeout_seconds,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            while True:
                payload = {
                    "model": settings.deepseek_model,
                    "messages": render(request, previous, previous_detail),
                    "thinking": {"type": "disabled"},
                    "temperature": 0,
                    "max_tokens": settings.model_output_tokens,
                    "response_format": {"type": "json_object"},
                    "stream": False,
                }
                # The key alphabet needs no JSON escaping. Check precisely the bytes sent,
                # including system prompts, fields, hints and subsequent corrections.
                body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
                if key.encode("ascii") in body:
                    raise ProviderError("MODEL_INPUT_CREDENTIAL", "credential")
                call_id = self.reserve(len(request.content))
                started, usage, size = time.monotonic(), {}, 0
                code, result, category, detail = "MODEL_TRANSPORT", None, None, None
                try:
                    async with asyncio.timeout(settings.model_timeout_seconds):
                        async with client.stream(
                            "POST",
                            DEEPSEEK_URL,
                            headers={
                                "Authorization": "Bearer " + key,
                                "Content-Type": "application/json",
                            },
                            content=body,
                        ) as response:
                            code = {
                                401: "MODEL_AUTH_FAILED",
                                402: "MODEL_BALANCE",
                                429: "MODEL_RATE_LIMIT",
                            }.get(
                                response.status_code,
                                "MODEL_UPSTREAM"
                                if response.status_code >= 500
                                else "MODEL_HTTP_ERROR",
                            )
                            if response.status_code == 200:
                                content = bytearray()
                                async for part in response.aiter_bytes():
                                    size += len(part)
                                    if size > settings.model_response_bytes:
                                        raise ProviderError("MODEL_OUTPUT_LIMIT")
                                    content.extend(part)
                                try:
                                    result = decode(bytes(content), request, key, usage)
                                    code = "succeeded"
                                except OutputRejected as rejection:
                                    code, result = "MODEL_INVALID_OUTPUT", None
                                    category, detail = rejection.category, rejection.detail
                except asyncio.CancelledError:
                    code = "cancelled"
                    raise
                except ProviderError as error:
                    code, category = error.code, error.category
                except (httpx.HTTPError, TimeoutError):
                    code = "MODEL_TRANSPORT"
                finally:
                    safe_usage = {
                        name: value
                        for name, value in usage.items()
                        if name in {"prompt_tokens", "completion_tokens"}
                        and type(value) is int
                        and 0 <= value <= 10_000_000
                    }
                    self.finish(
                        call_id,
                        code,
                        int((time.monotonic() - started) * 1000),
                        size,
                        safe_usage,
                        category,
                    )
                if result is not None and code == "succeeded":
                    return result
                if (
                    code in {"MODEL_RATE_LIMIT", "MODEL_UPSTREAM", "MODEL_TRANSPORT"}
                    and network_retries < 2
                ):
                    network_retries += 1
                    await asyncio.sleep(0.2 * network_retries)
                    continue
                if code == "MODEL_INVALID_OUTPUT" and corrections < 1:
                    corrections, previous, previous_detail = corrections + 1, category, detail
                    continue
                failure = ProviderError(code, category)
                failure.detail = detail
                raise failure
