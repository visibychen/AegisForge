"""M3 stage-2 behaviour: grounded locations, merge, robustness, budgets and coverage."""

import asyncio
import json
import time
from uuid import uuid4

import httpx
import pytest
from app.llm.deepseek import DeepSeekProvider, OutputRejected, ProviderError, validate_result
from app.parsers.inputs import parse_input
from app.schemas.contracts import (
    AnalysisRequest,
    AnalysisResult,
    Finding,
    HttpLocation,
    SourceLocation,
)
from app.services.merge import merge_findings
from app.services.scans import change_scan
from app.worker.runner import run_once
from sqlalchemy.exc import OperationalError
from tests.test_deepseek import envelope
from tests.test_scans import create, upload


def configure(api, monkeypatch):
    monkeypatch.setenv("AEGISFORGE_DEEPSEEK_API_KEY", "synthetic-stage2-key")
    api.app.state.settings.model_mode = "real"


def llm(artifact_id, start, end, evidence, severity="high", cwe="CWE-89", category="sqli"):
    return Finding(
        category=category,
        cwe=cwe,
        severity=severity,
        sources=["llm"],
        location=SourceLocation(artifact_id=artifact_id, start_line=start, end_line=end),
        evidence=evidence,
        explanation="model view",
        recommendation="bind parameters",
    )


def rule(artifact_id, line, evidence):
    return Finding(
        category="sqli",
        cwe="CWE-89",
        severity="high",
        sources=["rule"],
        location=SourceLocation(artifact_id=artifact_id, start_line=line, end_line=line),
        evidence=evidence,
        explanation="rule view",
        recommendation="bind parameters",
    )


def check(request, finding):
    return validate_result(
        AnalysisResult(mode="real", analysis_complete=True, findings=[finding]), request
    )


def test_ambiguous_or_over_wide_model_evidence_is_rejected():
    artifact_id = uuid4()
    twice = AnalysisRequest(
        artifact_id=artifact_id,
        input_type="source",
        content="cur.execute(q)\ncur.execute(q)",
        start_line=1,
        end_line=2,
    )
    with pytest.raises(OutputRejected, match="ambiguous_evidence"):
        check(twice, llm(artifact_id, 1, 2, "cur.execute(q)"))
    pinned = check(twice, llm(artifact_id, 2, 2, "cur.execute(q)")).findings[0]
    assert (pinned.location.start_line, pinned.location.end_line) == (2, 2)
    lines = [f"value_{i} = helper_{i}()" for i in range(40)]
    wide = AnalysisRequest(
        artifact_id=artifact_id,
        input_type="source",
        content="\n".join(lines),
        start_line=1,
        end_line=40,
    )
    with pytest.raises(OutputRejected, match="span"):
        check(wide, llm(artifact_id, 1, 31, "\n".join(lines[:31])))


def test_http_short_values_may_be_proven_whole_but_not_by_punctuation():
    artifact_id = uuid4()
    request = AnalysisRequest(
        artifact_id=artifact_id,
        input_type="http",
        content="query.0 q = ab;",
        fields={"query.0": "ab;"},
    )

    def http(evidence):
        return Finding(
            category="cmdi",
            cwe="CWE-78",
            severity="medium",
            sources=["llm"],
            location=HttpLocation(artifact_id=artifact_id, field="query.0"),
            evidence=evidence,
            explanation="payload feature",
            recommendation="validate input",
            evidence_status="attack_indicator",
        )

    assert check(request, http("ab;")).findings
    with pytest.raises(OutputRejected, match="evidence_weak"):
        check(request, http(";"))


def test_merge_keeps_independent_sinks_and_standard_severity():
    text = "a = 1\ncur.execute(one)\nb = 2\ncur.execute(two)\n"
    parsed = parse_input("source", text)
    artifact_id = uuid4()
    findings = [
        rule(artifact_id, 4, "cur.execute(two)"),
        rule(artifact_id, 2, "cur.execute(one)"),
        llm(artifact_id, 2, 4, "cur.execute(one)\nb = 2\ncur.execute(two)", severity="critical"),
    ]
    entries = merge_findings(findings, {str(artifact_id): parsed})
    assert [e["finding"]["location"]["start_line"] for e in entries] == [2, 4]
    first = entries[0]
    assert first["finding"]["severity"] == "high" and first["severity_disagreement"]
    assert first["finding"]["sources"] == ["rule", "llm"]
    assert {c["severity"] for c in first["contributors"]} == {"high", "critical"}
    assert first["severity_policy"] == "severity-1.0"


def test_numeric_order_survives_into_the_findings_api(api):
    # Lines 9 and 10: a JSON-string sort would put "10" before "9".
    source = "import os\n" + "\n" * 7 + "os.system(a)\n" + "os.system(b)\n"
    scan_id = create(api, [upload(api, source)]).json()["scan"]["id"]
    asyncio.run(run_once(api.app.state.engine, api.app.state.settings))
    lines = [
        f["location"]["start_line"]
        for f in api.get(f"/api/v1/scans/{scan_id}/findings").json()["findings"]
    ]
    assert lines == [9, 10]


def test_running_cancel_is_published_promptly(api, monkeypatch):
    configure(api, monkeypatch)
    engine, settings = api.app.state.engine, api.app.state.settings
    scan_id = create(api, strategy="hybrid", alias="deepseek").json()["scan"]["id"]

    class Slow:
        async def analyze(self, _request):
            change_scan(engine, settings, scan_id, "cancel")
            await asyncio.sleep(10)

    started = time.monotonic()
    assert asyncio.run(run_once(engine, settings, lambda *_: Slow()))
    assert time.monotonic() - started < 8
    scan = api.get(f"/api/v1/scans/{scan_id}").json()["scan"]
    assert scan["status"] == "cancelled" and not scan["result"]["analysis_complete"]
    assert api.get(f"/api/v1/scans/{scan_id}/findings").json()["total"] == 0


def test_storage_error_inside_provider_keeps_rules_and_never_echoes(api, monkeypatch):
    configure(api, monkeypatch)

    class Locked:
        async def analyze(self, _request):
            raise OperationalError(
                "UPDATE private", {}, Exception(r"database is locked C:\private\credential")
            )

    scan_id = create(api, strategy="hybrid", alias="deepseek").json()["scan"]["id"]
    asyncio.run(run_once(api.app.state.engine, api.app.state.settings, lambda *_: Locked()))
    response = api.get(f"/api/v1/scans/{scan_id}")
    scan = response.json()["scan"]
    assert scan["status"] == "partial" and scan["error_code"] == "MODEL_PROVIDER_INTERNAL"
    assert "private" not in response.text and "credential" not in response.text
    assert api.get(f"/api/v1/scans/{scan_id}/findings").json()["total"] == 1


def test_heartbeat_storage_errors_do_not_kill_the_worker(api, monkeypatch):
    configure(api, monkeypatch)

    def broken_heartbeat(*_args):
        raise OperationalError("UPDATE jobs", {}, Exception("database is locked"))

    monkeypatch.setattr("app.worker.runner.heartbeat", broken_heartbeat)

    class Patient:
        async def analyze(self, _request):
            await asyncio.sleep(2.5)
            return AnalysisResult(mode="real", analysis_complete=True)

    scan_id = create(api, strategy="hybrid", alias="deepseek").json()["scan"]["id"]
    engine, settings = api.app.state.engine, api.app.state.settings
    assert asyncio.run(run_once(engine, settings, lambda *_: Patient()))
    assert api.get(f"/api/v1/scans/{scan_id}").json()["scan"]["status"] == "completed"


def deepseek_factory(handler):
    return lambda settings, ledger: DeepSeekProvider(
        settings, ledger.reserve, ledger.finish, transport=httpx.MockTransport(handler)
    )


def test_daily_cap_failure_category_and_coverage_are_recorded(api, monkeypatch):
    configure(api, monkeypatch)
    engine, settings = api.app.state.engine, api.app.state.settings
    settings.daily_model_calls = 1
    request_stub = AnalysisRequest(artifact_id=uuid4(), input_type="source", content="x")

    def invented(_request):
        return httpx.Response(
            200,
            json=envelope(
                request_stub,
                lambda d: d["findings"][0].update(
                    evidence="invented_call(argument)",
                    location={"kind": "source", "start_line": 2, "end_line": 2},
                ),
            ),
        )

    scan_id = create(api, strategy="hybrid", alias="deepseek").json()["scan"]["id"]
    asyncio.run(run_once(engine, settings, deepseek_factory(invented)))
    scan = api.get(f"/api/v1/scans/{scan_id}").json()["scan"]
    assert scan["status"] == "partial" and scan["error_code"] == "MODEL_DAILY_BUDGET"
    calls = api.get(f"/api/v1/scans/{scan_id}/calls").json()["calls"]
    assert [c["failure_category"] for c in calls] == ["evidence"]
    entry = scan["result"]["coverage"][0]
    assert entry["rules"] == "ran" and entry["model"] == "failed"
    assert entry["model_error"] == "MODEL_DAILY_BUDGET"
    assert scan["budget"]["daily_used"] == 1 and scan["budget"]["daily_limit"] == 1
    blocked = create(api, strategy="hybrid", alias="deepseek")
    assert blocked.status_code == 429 and blocked.json()["error"]["code"] == "MODEL_DAILY_BUDGET"


def test_retry_prechecks_budget_and_keeps_previous_attempt(api, monkeypatch):
    configure(api, monkeypatch)
    engine, settings = api.app.state.engine, api.app.state.settings
    settings.max_model_calls = 2
    scan_id = create(api, strategy="hybrid", alias="deepseek").json()["scan"]["id"]
    asyncio.run(run_once(engine, settings, deepseek_factory(lambda _: httpx.Response(503))))
    before = api.get(f"/api/v1/scans/{scan_id}").json()["scan"]
    assert before["status"] == "partial" and before["call_count"] == 2
    refused = api.post(f"/api/v1/scans/{scan_id}/retry")
    assert refused.status_code == 409 and refused.json()["error"]["code"] == "RETRY_BUDGET"
    assert api.get(f"/api/v1/scans/{scan_id}").json()["scan"]["status"] == "partial"
    assert api.get(f"/api/v1/scans/{scan_id}/findings").json()["total"] == 1
    settings.max_model_calls = 32
    accepted = api.post(f"/api/v1/scans/{scan_id}/retry").json()["scan"]
    assert accepted["attempt"] == 1 and accepted["attempts"][0]["status"] == "partial"
    assert accepted["attempts"][0]["summary"]["coverage"][0]["model"] == "failed"
    previous = api.get(f"/api/v1/scans/{scan_id}/findings?attempt=0").json()
    assert previous["total"] == 1 and previous["attempt"] == 0
    assert api.get(f"/api/v1/scans/{scan_id}/findings").json()["total"] == 0


def test_coverage_states_for_rules_and_simulated_models(api):
    engine, settings = api.app.state.engine, api.app.state.settings
    rules_scan = create(api).json()["scan"]["id"]
    fake_scan = create(api, strategy="hybrid").json()["scan"]["id"]
    asyncio.run(run_once(engine, settings))
    asyncio.run(run_once(engine, settings))
    rules_entry = api.get(f"/api/v1/scans/{rules_scan}").json()["scan"]["result"]["coverage"][0]
    fake_entry = api.get(f"/api/v1/scans/{fake_scan}").json()["scan"]["result"]["coverage"][0]
    assert (rules_entry["rules"], rules_entry["model"]) == ("ran", "not_requested")
    assert (fake_entry["rules"], fake_entry["model"]) == ("ran", "simulated")
    assert json.dumps(fake_entry).count("succeeded") == 0


def test_provider_error_category_reaches_coverage(api, monkeypatch):
    configure(api, monkeypatch)

    class Rejecting:
        async def analyze(self, _request):
            raise ProviderError("MODEL_INVALID_OUTPUT", "provenance")

    scan_id = create(api, strategy="hybrid", alias="deepseek").json()["scan"]["id"]
    asyncio.run(run_once(api.app.state.engine, api.app.state.settings, lambda *_: Rejecting()))
    entry = api.get(f"/api/v1/scans/{scan_id}").json()["scan"]["result"]["coverage"][0]
    assert entry["model"] == "failed" and entry["failure_category"] == "provenance"
