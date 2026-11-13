from tests.test_scans import create, run


def test_report_and_logical_deletion(api):
    ident = create(api).json()["scan"]["id"]
    assert api.post(f"/api/v1/workspace/{ident}/delete").status_code == 409
    run(api)
    response = api.get(f"/api/v1/workspace/{ident}/report")
    assert response.status_code == 200
    payload = response.json()
    assert payload["schema_version"] == "report-2.1" and payload["source_free"] is True
    assert payload["findings"][0]["cwe"] == "CWE-78"
    assert "os.system" not in response.text and "sample.py" not in response.text
    md = api.get(f"/api/v1/workspace/{ident}/report?format=markdown")
    # Markdown is a readable report (tables), not a fenced dump of the JSON.
    assert "| CWE | 等级 |" in md.text and "CWE-78" in md.text and ident in md.text
    assert "```" not in md.text and "os.system" not in md.text
    assert f"aegisforge-report-{ident[:8]}.md" in md.headers["content-disposition"]
    assert api.get("/api/v1/workspace").json()["tasks"] == 1
    assert api.post(f"/api/v1/workspace/{ident}/delete").status_code == 200
    assert api.get("/api/v1/workspace").json()["tasks"] == 0
    assert api.get(f"/api/v1/scans/{ident}").status_code == 404
    assert api.get("/api/v1/scans").json()["total"] == 0


def test_history_filters_and_pagination(api):
    first = create(api).json()["scan"]["id"]
    create(api)
    data = api.get("/api/v1/workspace/history?limit=1").json()
    assert data["total"] == 2 and len(data["scans"]) == 1
    assert api.get("/api/v1/workspace/history", params={"q": first}).json()["total"] == 1
    assert api.get("/api/v1/workspace/history?status=completed").json()["total"] == 0
    assert api.get("/api/v1/workspace/history?limit=500").status_code == 422


def test_removed_history_blocks_repair_backdoors(api):
    import asyncio

    from app.worker.runner import run_once
    from tests.test_repairs import repair, target

    finding, artifact = target(api)
    item = repair(api, finding, artifact).json()["repair"]
    asyncio.run(run_once(api.app.state.engine, api.app.state.settings))
    assert api.post(f"/api/v1/workspace/{item['scan_id']}/delete").status_code == 200
    assert api.get(f"/api/v1/repairs/{item['id']}/download?format=source").status_code == 404
    assert repair(api, finding, artifact).status_code == 404
