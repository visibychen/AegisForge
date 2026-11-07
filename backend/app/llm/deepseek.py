import asyncio
import json
import time
from collections.abc import Callable

import httpx
from pydantic import ValidationError

from app.core.config import Settings
from app.core.errors import DomainError
from app.core.redaction import redact_text
from app.llm.prompts import messages
from app.schemas.contracts import AnalysisRequest, AnalysisResult

DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"


class ProviderError(DomainError):
    def __init__(self, code: str):
        super().__init__(code, "模型分析未完成；具体原因见任务错误码。", 503)


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


def validate_result(result: AnalysisResult, request: AnalysisRequest) -> AnalysisResult:
    if result.mode != "real" or not result.analysis_complete:
        raise ValueError("incomplete result")
    lines = request.content.split("\n")
    for item in result.findings:
        loc = item.location
        if loc.artifact_id != request.artifact_id or loc.kind != request.input_type:
            raise ValueError("forged artifact/location")
        if item.sources != ["llm"] or item.evidence_truncated:
            raise ValueError("forged provenance")
        if loc.kind == "source":
            if not request.start_line <= loc.start_line <= loc.end_line <= request.end_line:
                raise ValueError("evidence outside chunk")
            evidence = "\n".join(
                lines[loc.start_line - request.start_line : loc.end_line - request.start_line + 1]
            )
        else:
            if loc.field not in request.fields:
                raise ValueError("forged HTTP field")
            evidence = request.fields[loc.field]
        if not item.evidence.strip() or item.evidence not in evidence:
            raise ValueError("evidence absent from input")
    return result


def clean_public(value, key: str):
    if isinstance(value, dict):
        return {name: clean_public(item, key) for name, item in value.items()}
    if isinstance(value, list):
        return [clean_public(item, key) for item in value]
    if isinstance(value, str):
        return redact_text(value.replace(key, "[REDACTED]") if key else value)
    return value


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
        settings = self.settings
        key = settings.deepseek_api_key.get_secret_value()
        if not key:
            raise ProviderError("MODEL_NOT_CONFIGURED")
        network_retries, corrections = 0, 0
        async with httpx.AsyncClient(
            transport=self.transport,
            timeout=settings.model_timeout_seconds,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            while True:
                call_id = self.reserve(len(request.content))
                started, usage, size = time.monotonic(), {}, 0
                code, result = "MODEL_TRANSPORT", None
                try:
                    payload = {
                        "model": settings.deepseek_model,
                        "messages": messages(request, corrections > 0),
                        "thinking": {"type": "disabled"},
                        "temperature": 0,
                        "max_tokens": settings.model_output_tokens,
                        "response_format": {"type": "json_object"},
                        "stream": False,
                    }
                    async with asyncio.timeout(settings.model_timeout_seconds):
                        async with client.stream(
                            "POST",
                            DEEPSEEK_URL,
                            headers={"Authorization": "Bearer " + key},
                            json=payload,
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
                                    envelope = strict_json(content)
                                    if not isinstance(envelope, dict):
                                        raise ValueError("invalid envelope")
                                    raw_usage = envelope.get("usage")
                                    usage = raw_usage if isinstance(raw_usage, dict) else {}
                                    choice = envelope["choices"][0]
                                    if choice.get("finish_reason") != "stop":
                                        raise ValueError("truncated response")
                                    data = strict_json(choice["message"]["content"])
                                    result = validate_result(
                                        AnalysisResult.model_validate(data), request
                                    )
                                    # Evidence was verified against the public input; do not
                                    # run free-text redaction over Python syntax a second time.
                                    for finding in result.findings:
                                        if key in finding.evidence:
                                            raise ValueError("credential in evidence")
                                        finding.explanation = clean_public(finding.explanation, key)
                                        finding.recommendation = clean_public(
                                            finding.recommendation, key
                                        )
                                    result.warnings = [
                                        text[:1000] for text in clean_public(result.warnings, key)
                                    ]
                                    code = "succeeded"
                                except (
                                    ValueError,
                                    TypeError,
                                    KeyError,
                                    IndexError,
                                    AttributeError,
                                    ValidationError,
                                    RecursionError,
                                ):
                                    code, result = "MODEL_INVALID_OUTPUT", None
                except asyncio.CancelledError:
                    code = "cancelled"
                    raise
                except ProviderError as error:
                    code = error.code
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
                        call_id, code, int((time.monotonic() - started) * 1000), size, safe_usage
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
                    corrections += 1
                    continue
                raise ProviderError(code)
