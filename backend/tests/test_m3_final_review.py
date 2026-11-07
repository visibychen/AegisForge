"""Regressions found by Codex when reviewing Claude's M3 stage-2 implementation."""

import asyncio
import json
import os
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from app.llm.deepseek import ProviderError
from app.models import Job, ScanTask
from app.services.queue import claim, utcnow
from app.worker.runner import run_once
from sqlalchemy.orm import Session
from tests.test_deepseek import envelope, provider, request
from tests.test_scans import create, upload


def test_known_service_credential_in_input_is_rejected_before_reserving_or_sending(monkeypatch):
    req = request().model_copy(
        update={
            "content": "os.system(cmd)\n# synthetic-test-credential",
            "end_line": 11,
        }
    )
    sent = []

    def transport(http_request):
        sent.append(http_request)
        return httpx.Response(200, json=envelope(req))

    instance, calls, finishes = provider(monkeypatch, transport)
    with pytest.raises(ProviderError, match="MODEL_INPUT_CREDENTIAL"):
        asyncio.run(instance.analyze(req))
    assert sent == calls == finishes == []


@pytest.mark.parametrize("part", ["fields", "hints", "system"])
def test_guard_covers_fields_hints_and_final_system_prompt(monkeypatch, part):
    from app.llm import deepseek
    from app.schemas.contracts import Finding, SourceLocation

    req = request()
    credential = "synthetic-test-credential"
    if part == "fields":
        req = req.model_copy(update={"input_type": "http", "fields": {"query.0": credential}})
    elif part == "hints":
        hint = Finding(
            category="cmdi",
            cwe="CWE-78",
            severity="high",
            sources=["rule"],
            location=SourceLocation(artifact_id=req.artifact_id, start_line=10, end_line=10),
            evidence=credential,
            explanation="test",
            recommendation="test",
        )
        req = req.model_copy(update={"rule_hints": [hint]})
    else:
        monkeypatch.setattr(
            deepseek, "messages", lambda *_: [{"role": "system", "content": credential}]
        )
    sent = []
    instance, calls, _ = provider(monkeypatch, lambda r: sent.append(r))
    with pytest.raises(ProviderError, match="MODEL_INPUT_CREDENTIAL"):
        asyncio.run(instance.analyze(req))
    assert sent == calls == []


@pytest.mark.parametrize(
    "bad",
    [
        "short",
        "invalid key of length",
        "invalid\nkey-of-length",
        'quotes"are-not-valid',
        "非ASCII密钥不能用",
    ],
)
def test_invalid_credentials_are_hidden_and_never_sent(monkeypatch, bad):
    instance, calls, _ = provider(
        monkeypatch, lambda _: pytest.fail("network reached"), model_mode="real"
    )
    monkeypatch.setenv("AEGISFORGE_DEEPSEEK_API_KEY", bad)
    assert instance.settings.model_aliases == ["fake"]
    with pytest.raises(ProviderError, match="MODEL_NOT_CONFIGURED"):
        asyncio.run(instance.analyze(request()))
    assert calls == []


def test_credential_prefix_alone_is_not_rejected(monkeypatch):
    req = request().model_copy(update={"content": "os.system(cmd) # synthetic-test-credentia"})
    instance, calls, _ = provider(monkeypatch, lambda _: httpx.Response(200, json=envelope(req)))
    assert asyncio.run(instance.analyze(req)).analysis_complete
    assert len(calls) == 1


@pytest.mark.parametrize("case", ["source", "bom", "http", "encoded", "json", "name"])
def test_service_credential_upload_never_persists_or_echoes(api, monkeypatch, case):
    key = "synthetic-test-credential"
    monkeypatch.setenv("AEGISFORGE_DEEPSEEK_API_KEY", key)
    name, kind, text = "sample.py", "source", "# " + key
    if case == "bom":
        text = "\ufeff# " + key + "\r\n"
    elif case in {"http", "encoded"}:
        kind, name = "http", "sample.http"
        value = key if case == "http" else key.replace("-", "%2D")
        text = f"GET /?q={value} HTTP/1.1\nHost: example.invalid\n\n"
    elif case == "json":
        kind, name = "http", "sample.http"
        encoded = "".join(f"\\u{ord(c):04x}" for c in key)
        text = (
            'POST / HTTP/1.1\nHost: example.invalid\nContent-Type: application/json\n\n{"q":"'
            + encoded
            + '"}'
        )
    elif case == "name":
        name, text = key + ".py", "x = 1"
    response = api.post(
        "/api/v1/artifacts", params={"filename": name, "input_type": kind}, content=text.encode()
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INPUT_CONTAINS_SERVICE_CREDENTIAL"
    assert key not in response.text
    assert not list(api.app.state.settings.data_dir.glob("artifacts/*.blob"))


def test_receipts_bind_content_and_strategy_but_not_ids_or_limits(api, monkeypatch):
    first, duplicate = upload(api), upload(api)
    a = create(api, [first]).json()["scan"]["receipt"]
    b = create(api, [duplicate], strategy="hybrid").json()["scan"]["receipt"]
    assert a["input_digest"] == b["input_digest"]
    assert a["plan_digest"] != b["plan_digest"]
    same = create(api, [duplicate]).json()["scan"]["receipt"]
    assert a["plan_digest"] == same["plan_digest"]
    settings = api.app.state.settings
    settings.daily_model_calls = 150
    settings.model_timeout_seconds = 42
    monkeypatch.setenv("AEGISFORGE_DEEPSEEK_API_KEY", "a-new-credential-1234")
    c = create(api, [first]).json()["scan"]["receipt"]
    assert a["input_digest"] == c["input_digest"] and a["plan_digest"] == c["plan_digest"]
    public = json.dumps(c)
    assert "os.system" not in public and "sample.py" not in public
    assert "credential" not in public and str(settings.data_dir) not in public


def test_configuration_drift_stops_before_calls_and_retry_archives_old_receipt(api, monkeypatch):
    monkeypatch.setenv("AEGISFORGE_DEEPSEEK_API_KEY", "synthetic-review-key")
    settings = api.app.state.settings
    settings.model_mode = "real"
    created = create(api, strategy="hybrid", alias="deepseek").json()["scan"]
    scan_id, old = created["id"], created["receipt"]
    settings.deepseek_model = "deepseek-v4-pro"

    def forbidden(*_):
        pytest.fail("provider must not be constructed for a changed plan")

    asyncio.run(run_once(api.app.state.engine, settings, forbidden))
    changed = api.get(f"/api/v1/scans/{scan_id}").json()["scan"]
    assert changed["error_code"] == "ANALYSIS_CONFIG_CHANGED" and changed["call_count"] == 0
    retried = api.post(f"/api/v1/scans/{scan_id}/retry").json()["scan"]
    assert retried["attempts"][0]["receipt"] == old
    assert retried["receipt"]["plan_digest"] != old["plan_digest"]
    assert retried["receipt"]["input_digest"] == old["input_digest"]


def test_deadline_cancels_inflight_and_keeps_real_coverage(api, monkeypatch):
    monkeypatch.setenv("AEGISFORGE_DEEPSEEK_API_KEY", "synthetic-review-key")
    settings, engine = api.app.state.settings, api.app.state.engine
    settings.model_mode, settings.task_timeout_seconds = "real", 0.05
    scan_id = create(api, [upload(api), upload(api)], strategy="hybrid", alias="deepseek").json()[
        "scan"
    ]["id"]
    cancelled = []

    class Slow:
        async def analyze(self, _request):
            try:
                await asyncio.sleep(5)
            finally:
                cancelled.append(True)

    asyncio.run(run_once(engine, settings, lambda *_: Slow()))
    scan = api.get(f"/api/v1/scans/{scan_id}").json()["scan"]
    assert cancelled == [True]
    assert scan["status"] == "partial" and scan["error_code"] == "TASK_TIMEOUT"
    coverage = scan["result"]["coverage"]
    assert [c["rules"] for c in coverage] == ["ran", "pending"]
    assert [c["model"] for c in coverage] == ["failed", "pending"]
    assert coverage[0]["model_error"] == "TASK_TIMEOUT"
    assert api.get(f"/api/v1/scans/{scan_id}/findings").json()["total"] == 1


def test_recovered_attempt_does_not_reset_deadline(api):
    engine, settings = api.app.state.engine, api.app.state.settings
    scan_id = create(api).json()["scan"]["id"]
    lease = claim(engine, settings)
    with Session(engine) as session:
        session.get(ScanTask, scan_id).attempt_started_at = utcnow() - timedelta(seconds=181)
        session.get(Job, lease.job_id).lease_until = utcnow() - timedelta(seconds=1)
        session.commit()
    asyncio.run(run_once(engine, settings))
    scan = api.get(f"/api/v1/scans/{scan_id}").json()["scan"]
    assert scan["error_code"] == "TASK_TIMEOUT" and scan["call_count"] == 0


def test_rotated_key_already_in_snapshot_blocks_preview_create_and_worker(api, monkeypatch):
    source = '# synthetic-rotated-key\nimport os\nos.system(request.args["cmd"])\n'
    artifact_id = upload(api, source)
    scan_id = create(api, [artifact_id]).json()["scan"]["id"]
    monkeypatch.setenv("AEGISFORGE_DEEPSEEK_API_KEY", "synthetic-rotated-key")
    assert (
        api.get(f"/api/v1/artifacts/{artifact_id}").json()["error"]["code"]
        == "INPUT_CONTAINS_SERVICE_CREDENTIAL"
    )
    assert create(api, [artifact_id]).json()["error"]["code"] == "INPUT_CONTAINS_SERVICE_CREDENTIAL"
    asyncio.run(run_once(api.app.state.engine, api.app.state.settings))
    scan = api.get(f"/api/v1/scans/{scan_id}").json()["scan"]
    assert scan["error_code"] == "INPUT_CONTAINS_SERVICE_CREDENTIAL" and scan["call_count"] == 0


def test_task_deadline_does_not_become_network_retry_and_cancel_wins(api, monkeypatch):
    from app.llm.deepseek import DeepSeekProvider

    monkeypatch.setenv("AEGISFORGE_DEEPSEEK_API_KEY", "synthetic-review-key")
    settings, engine = api.app.state.settings, api.app.state.engine
    settings.model_mode, settings.task_timeout_seconds = "real", 0.05
    settings.model_timeout_seconds = 0.06
    scan_id = create(api, strategy="hybrid", alias="deepseek").json()["scan"]["id"]
    sent = []

    async def stalled(_request):
        sent.append(True)
        await asyncio.sleep(5)

    def factory(s, ledger):
        return DeepSeekProvider(
            s, ledger.reserve, ledger.finish, transport=httpx.MockTransport(stalled)
        )

    asyncio.run(run_once(engine, settings, factory))
    scan = api.get(f"/api/v1/scans/{scan_id}").json()["scan"]
    assert scan["error_code"] == "TASK_TIMEOUT" and len(sent) == 1
    assert api.get(f"/api/v1/scans/{scan_id}/calls").json()["calls"][0]["status"] == "cancelled"

    # A cancellation flag arriving before the deadline dominates the terminal publish.
    from app.services.scans import change_scan

    settings.task_timeout_seconds = 0.05
    scan_id = create(api, strategy="hybrid", alias="deepseek").json()["scan"]["id"]

    class Cancelling:
        async def analyze(self, _request):
            change_scan(engine, settings, scan_id, "cancel")
            await asyncio.sleep(5)

    asyncio.run(run_once(engine, settings, lambda *_: Cancelling()))
    scan = api.get(f"/api/v1/scans/{scan_id}").json()["scan"]
    assert scan["status"] == "cancelled" and scan["error_code"] is None


def test_independent_worker_cli_consumes_persisted_queue(api):
    scan_id = create(api, strategy="hybrid").json()["scan"]["id"]
    env = os.environ.copy()
    env.pop("AEGISFORGE_DEEPSEEK_API_KEY", None)
    env["AEGISFORGE_MODEL_MODE"] = "fake"
    result = subprocess.run(
        [sys.executable, "-m", "app.worker", "--once"],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    api.app.state.engine.dispose()
    scan = api.get(f"/api/v1/scans/{scan_id}").json()["scan"]
    assert scan["status"] == "partial" and scan["call_count"] == 0
    assert scan["result"]["coverage"][0]["model"] == "simulated"
