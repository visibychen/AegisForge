import asyncio
import json
from uuid import uuid4

import httpx
import pytest
from app.core.config import Settings
from app.llm.deepseek import DeepSeekProvider, ProviderError, strict_json
from app.schemas.contracts import AnalysisRequest


def request():
    return AnalysisRequest(
        artifact_id=uuid4(),
        input_type="source",
        content="os.system(cmd)",
        start_line=10,
        end_line=10,
    )


def finding(req):
    return {
        "category": "cmdi",
        "cwe": "CWE-78",
        "severity": "high",
        "location": {
            "kind": "source",
            "artifact_id": str(req.artifact_id),
            "start_line": 10,
            "end_line": 10,
        },
        "evidence": "os.system(cmd)",
        "explanation": "Untrusted shell input",
        "recommendation": "Use an argument list",
        "sources": ["llm"],
        "evidence_status": "potential",
    }


def envelope(req, change=None):
    data = {
        "schema_version": "1.0",
        "mode": "real",
        "analysis_complete": True,
        "findings": [finding(req)],
        "warnings": [],
    }
    if change:
        change(data)
    return {
        "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(data)}}],
        "usage": {"prompt_tokens": 123, "completion_tokens": 55},
    }


def provider(monkeypatch, handler, **options):
    monkeypatch.setenv("AEGISFORGE_DEEPSEEK_API_KEY", "synthetic-test-credential")
    settings = Settings(_env_file=None, **options)
    calls, finishes = [], []

    def reserve(chars):
        calls.append(chars)
        return str(len(calls))

    instance = DeepSeekProvider(
        settings,
        reserve,
        lambda *args: finishes.append(args),
        transport=httpx.MockTransport(handler),
    )
    return instance, calls, finishes


def test_real_adapter_uses_json_mode_and_no_secret_in_prompt(monkeypatch):
    req = request()

    def handler(http_request):
        data = json.loads(http_request.content)
        assert http_request.url.host == "api.deepseek.com"
        assert data["response_format"] == {"type": "json_object"}
        assert data["thinking"] == {"type": "disabled"}
        assert "synthetic-test-credential" not in http_request.content.decode()
        assert "tools" not in data
        return httpx.Response(200, json=envelope(req))

    instance, calls, finishes = provider(monkeypatch, handler)
    assert asyncio.run(instance.analyze(req)).analysis_complete
    assert len(calls) == 1 and finishes[0][1] == "succeeded"
    assert finishes[0][-1] == {"prompt_tokens": 123, "completion_tokens": 55}


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d["findings"][0]["location"].update(start_line=9),
        lambda d: d["findings"][0]["location"].update(artifact_id=str(uuid4())),
        lambda d: d["findings"][0].update(evidence="invented evidence"),
        lambda d: d["findings"][0].update(sources=["rule"]),
        lambda d: d["findings"][0].update(evidence_truncated=True),
        lambda d: d["findings"][0].update(evidence_status="verified"),
    ],
)
def test_forged_outputs_get_only_one_correction(monkeypatch, mutation):
    req = request()
    instance, calls, finishes = provider(
        monkeypatch, lambda _: httpx.Response(200, json=envelope(req, mutation))
    )
    with pytest.raises(ProviderError, match="MODEL_INVALID_OUTPUT"):
        asyncio.run(instance.analyze(req))
    assert len(calls) == len(finishes) == 2


@pytest.mark.parametrize(
    "status,count,code",
    [
        (429, 3, "MODEL_RATE_LIMIT"),
        (503, 3, "MODEL_UPSTREAM"),
        (401, 1, "MODEL_AUTH_FAILED"),
        (402, 1, "MODEL_BALANCE"),
    ],
)
def test_http_retries_are_bounded_and_do_not_echo_responses(monkeypatch, status, count, code):
    instance, calls, _ = provider(
        monkeypatch, lambda _: httpx.Response(status, text="PRIVATE_BODY")
    )
    with pytest.raises(ProviderError, match=code) as error:
        asyncio.run(instance.analyze(request()))
    assert len(calls) == count and "PRIVATE_BODY" not in str(error.value)


def test_timeouts_and_output_limit(monkeypatch):
    def timeout(_):
        raise httpx.ReadTimeout("private network data")

    instance, calls, _ = provider(monkeypatch, timeout)
    with pytest.raises(ProviderError, match="MODEL_TRANSPORT"):
        asyncio.run(instance.analyze(request()))
    assert len(calls) == 3
    instance, calls, _ = provider(
        monkeypatch, lambda _: httpx.Response(200, content=b"x" * 4097), model_response_bytes=4096
    )
    with pytest.raises(ProviderError, match="MODEL_OUTPUT_LIMIT"):
        asyncio.run(instance.analyze(request()))
    assert len(calls) == 1


def test_blank_json_is_failure_even_when_stop(monkeypatch):
    instance, calls, _ = provider(
        monkeypatch,
        lambda _: httpx.Response(
            200, json={"choices": [{"finish_reason": "stop", "message": {"content": "   "}}]}
        ),
    )
    with pytest.raises(ProviderError, match="MODEL_INVALID_OUTPUT"):
        asyncio.run(instance.analyze(request()))
    assert len(calls) == 2


def test_credentials_cannot_be_loaded_from_dotenv(tmp_path, monkeypatch):
    monkeypatch.delenv("AEGISFORGE_DEEPSEEK_API_KEY", raising=False)
    path = tmp_path / ".env"
    path.write_text("AEGISFORGE_DEEPSEEK_API_KEY=synthetic-forbidden-file-secret\n")
    assert not Settings(_env_file=path).deepseek_api_key.get_secret_value()


@pytest.mark.parametrize("text", ['{"a":1,"a":2}', '{"a":NaN}', "not json"])
def test_duplicate_or_nonfinite_json_is_rejected(text):
    with pytest.raises(ValueError):
        strict_json(text)
