import asyncio
from uuid import uuid4

from app.worker.runner import run_once


def upload(api, source="import os\nos.system(request.args['cmd'])\n"):
    response = api.post(
        "/api/v1/artifacts?filename=sample.py&input_type=source", content=source.encode()
    )
    assert response.status_code == 201, response.text
    return response.json()["artifact"]["id"]


def create(api, ids=None, strategy="rules", alias="fake", **kwargs):
    return api.post(
        "/api/v1/scans",
        json={"artifact_ids": ids or [upload(api)], "strategy": strategy, "model_alias": alias},
        **kwargs,
    )


def run(api):
    return asyncio.run(run_once(api.app.state.engine, api.app.state.settings))


def test_rules_and_fake_jobs_are_persistent_and_truthful(api):
    response = create(api)
    assert response.status_code == 202, response.text
    scan_id = response.json()["scan"]["id"]
    assert response.json()["scan"]["status"] == "queued"
    assert run(api)
    api.app.state.engine.dispose()
    scan = api.get(f"/api/v1/scans/{scan_id}").json()["scan"]
    assert scan["status"] == "completed" and scan["result"]["model_mode"] == "rules"
    assert scan["call_count"] == 0
    findings = api.get(f"/api/v1/scans/{scan_id}/findings").json()
    assert findings["total"] == 1 and findings["findings"][0]["sources"] == ["rule"]
    assert api.get("/api/v1/scans").json()["total"] == 1
    scan_id = create(api, strategy="hybrid").json()["scan"]["id"]
    run(api)
    scan = api.get(f"/api/v1/scans/{scan_id}").json()["scan"]
    assert scan["status"] == "partial" and not scan["result"]["analysis_complete"]
    assert scan["call_count"] == 0 and any("模拟" in w for w in scan["result"]["warnings"])


def test_idempotency_conflicts_queue_limit_and_combined_budgets(api):
    ids = [upload(api)]
    key = {"Idempotency-Key": str(uuid4())}
    first = create(api, ids, headers=key)
    assert create(api, ids, headers=key).json()["scan"]["id"] == first.json()["scan"]["id"]
    assert create(api, ids, strategy="llm", headers=key).status_code == 409
    api.app.state.settings.queue_limit = 1
    assert create(api, ids).status_code == 429
    api.app.state.settings.queue_limit = 10
    ids = [upload(api, "x=1\n" * 12000), upload(api, "y=2\n" * 12000)]
    response = create(api, ids)
    assert response.status_code == 422 and response.json()["error"]["code"] == "TASK_INPUT_BUDGET"


def test_cancel_queued_retry_limit_and_authorization(api):
    scan_id = create(api).json()["scan"]["id"]
    for _ in range(2):
        assert api.post(f"/api/v1/scans/{scan_id}/cancel").json()["scan"]["status"] == "cancelled"
        assert not run(api)
        assert api.post(f"/api/v1/scans/{scan_id}/retry").status_code == 202
    api.post(f"/api/v1/scans/{scan_id}/cancel")
    assert api.post(f"/api/v1/scans/{scan_id}/retry").json()["error"]["code"] == "RETRY_LIMIT"
    api.headers.pop("Authorization")
    for path in ["", f"/{scan_id}", f"/{scan_id}/findings", f"/{scan_id}/calls"]:
        assert api.get("/api/v1/scans" + path).status_code == 401


def test_body_limit_and_model_alias_validation(api):
    assert api.post("/api/v1/scans", content=b"x" * 9000).status_code == 413
    assert create(api, alias="https://untrusted.invalid").status_code == 422
    assert create(api, alias="deepseek").json()["error"]["code"] == "MODEL_NOT_AVAILABLE"
