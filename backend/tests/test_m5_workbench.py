"""M5 workbench: removal consistency, aggregates, filters, reports and evidence views.

All scans use rules or the simulated model, so no test consumes real model budget.
"""

import asyncio
import json
import re
from uuid import uuid4

from app.models import Job, ModelCall, Repair
from app.services.queue import transaction
from app.worker.runner import run_once
from tests.test_m4_stage2 import REPLACEMENT, real_repair
from tests.test_repairs import repair, target
from tests.test_scans import create, run

MARKERS = [
    "TOPSECRETNAME",
    "REQ_SECRET_NAME",
    "MARKER_LITERAL_VALUE",
    "MARKER_COMMENT",
    "marker_param_name",
    "marker.example.test",
]
TWO = "import os\nos.system(request.args['cmd'])\ncursor.execute('SELECT ' + request.args['q'])\n"


def put(api, raw, name, kind="source"):
    response = api.post(
        "/api/v1/artifacts",
        params={"filename": name, "input_type": kind},
        content=raw.encode(),
        headers={"Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 201, response.text
    return response.json()["artifact"]


def work(api):
    return asyncio.run(run_once(api.app.state.engine, api.app.state.settings))


def only_scan(api):
    return api.get("/api/v1/scans").json()["scans"][0]["id"]


def remove(api, scan_id):
    response = api.post(f"/api/v1/workspace/{scan_id}/delete")
    assert response.status_code == 200, response.text


# --- removal closes every path ----------------------------------------------------------


def test_every_repair_entry_is_closed_after_removal(api):
    finding, artifact = target(api)
    key = str(uuid4())
    item = repair(api, finding, artifact, key=key).json()["repair"]
    work(api)
    ident, scan_id = item["id"], item["scan_id"]
    assert api.get(f"/api/v1/repairs/{ident}/compare").status_code == 200
    remove(api, scan_id)
    closed = [
        api.get(f"/api/v1/repairs/{ident}"),
        api.get(f"/api/v1/repairs/{ident}/compare"),
        api.get(f"/api/v1/repairs/{ident}/download?format=diff"),
        api.get(f"/api/v1/repairs/{ident}/download?format=source"),
        api.get(f"/api/v1/repairs?scan_id={scan_id}"),
        api.post(f"/api/v1/repairs/{ident}/validate"),
        api.post(f"/api/v1/repairs/{ident}/cancel"),
        repair(api, finding, artifact),  # a fresh key
        repair(api, finding, artifact, key=key),  # idempotent reuse must not resurrect it
    ]
    assert [r.status_code for r in closed] == [404] * len(closed)
    assert api.get("/api/v1/workspace").json()["repairs"]["total"] == 0


def test_removed_scan_is_unreachable_through_scan_endpoints(api):
    finding, artifact = target(api)
    scan_id = only_scan(api)
    remove(api, scan_id)
    paths = [
        api.get(f"/api/v1/scans/{scan_id}"),
        api.get(f"/api/v1/scans/{scan_id}/findings"),
        api.get(f"/api/v1/scans/{scan_id}/calls"),
        api.get(f"/api/v1/scans/{scan_id}/inputs/{artifact['id']}"),
        api.get(f"/api/v1/workspace/{scan_id}/report"),
        api.post(f"/api/v1/scans/{scan_id}/retry"),
        api.post(f"/api/v1/scans/{scan_id}/cancel"),
        api.post(f"/api/v1/workspace/{scan_id}/delete"),
    ]
    assert [r.status_code for r in paths] == [404] * len(paths)
    assert api.get("/api/v1/workspace/history").json()["total"] == 0


def test_removal_does_not_reset_budget_accounting(api):
    target(api)
    scan_id = only_scan(api)
    engine = api.app.state.engine
    with transaction(engine) as session:
        job = session.query(Job).filter(Job.scan_id == scan_id).one()
        for _ in range(3):
            session.add(
                ModelCall(
                    scan_id=scan_id, job_id=job.id, model="m", prompt_version="p", input_chars=1
                )
            )
    assert api.get(f"/api/v1/scans/{scan_id}").json()["scan"]["budget"]["daily_used"] == 3
    remove(api, scan_id)
    fresh = create(api).json()["scan"]["budget"]
    assert fresh["daily_used"] == 3 and fresh["scan_used"] == 0


def test_removal_is_refused_while_a_repair_or_validation_is_active(api):
    finding, artifact = target(api)
    item = repair(api, finding, artifact).json()["repair"]
    refused = api.post(f"/api/v1/workspace/{item['scan_id']}/delete")
    assert refused.status_code == 409 and refused.json()["error"]["code"] == "TASK_ACTIVE"
    work(api)  # the simulated candidate is generated
    engine = api.app.state.engine
    with transaction(engine) as session:
        row = session.get(Repair, item["id"])
        row.dynamic_requested, row.dynamic_json = True, json.dumps({"status": "pending"})
    assert api.post(f"/api/v1/workspace/{item['scan_id']}/delete").status_code == 409
    with transaction(engine) as session:
        row = session.get(Repair, item["id"])
        row.dynamic_requested, row.dynamic_json = False, json.dumps({"status": "cancelled"})
    remove(api, item["scan_id"])


# --- reports ---------------------------------------------------------------------------


def test_reports_export_no_names_evidence_or_parameter_names(api):
    source = put(
        api,
        (
            "import os\nLABEL = 'MARKER_LITERAL_VALUE'\n"
            "os.system(request.args['cmd'])  # MARKER_COMMENT\n"
        ),
        "TOPSECRETNAME.py",
    )
    http = put(
        api,
        "GET /?marker_param_name=%3Cscript%3E HTTP/1.1\nHost: marker.example.test\n\n",
        "REQ_SECRET_NAME.http",
        "http",
    )
    scan_id = create(api, [source["id"], http["id"]]).json()["scan"]["id"]
    run(api)
    listed = api.get(f"/api/v1/scans/{scan_id}/findings?cwe=CWE-78").json()["findings"]
    ident = repair(api, listed[0], source).json()["repair"]["id"]
    work(api)
    texts = []
    for kind in ("json", "markdown"):
        response = api.get(f"/api/v1/workspace/{scan_id}/report?format={kind}")
        assert response.status_code == 200
        texts.append(response.text)
    for text in texts:
        assert not [marker for marker in MARKERS if marker in text]
    data = json.loads(texts[0])
    # HTTP locations are positional ids such as "query.0", never the parameter's own name.
    fields = [f["location"]["field"] for f in data["findings"] if f["location"]["kind"] == "http"]
    assert all(re.fullmatch(r"[a-z]+\.\d+", str(field)) for field in fields)
    card = data["repairs"][0]
    assert card["id"] == ident and card["simulated"] is True and card["current_attempt"] is True
    assert card["validation_status"] != "passed" and card["finding_attempt"] == 0
    assert data["scan"]["mode"] == "rules" and data["truncated"] == {
        "findings": False,
        "repairs": False,
    }
    assert "不是数字签名" in " ".join(data["limits"])
    assert "| 门禁 | 状态 |" in texts[1] and "```" not in texts[1]


def test_report_separates_current_and_earlier_attempts(api):
    scan_id = create(api, strategy="hybrid").json()["scan"]["id"]  # simulated model -> partial
    run(api)
    assert api.post(f"/api/v1/scans/{scan_id}/retry").status_code == 202
    run(api)
    data = api.get(f"/api/v1/workspace/{scan_id}/report").json()
    assert data["scan"]["attempt"] == 1 and data["scan"]["mode"] == "simulated"
    assert data["scan"]["analysis_complete"] is False
    assert data["findings_by_attempt"] == {"0": 1, "1": 1}
    assert [f["attempt"] for f in data["findings"]] == [1]
    assert data["attempts"][0]["attempt"] == 0 and data["attempts"][0]["plan_digest"]
    assert data["attempts"][0]["status"] == "partial"
    assert sum(data["scan"]["coverage"]["model"].values()) == 1
    assert "not_requested" not in data["scan"]["coverage"]["model"]
    md = api.get(f"/api/v1/workspace/{scan_id}/report?format=markdown").text
    assert "## 以往尝试" in md and "模拟模型" in md


# --- overview, history and filters -----------------------------------------------------


def test_overview_counts_the_current_attempt_and_distinguishes_modes(api):
    rules = create(api).json()["scan"]["id"]
    simulated = create(api, strategy="hybrid").json()["scan"]["id"]
    run(api)
    run(api)
    data = api.get("/api/v1/workspace").json()
    assert data["tasks"] == 2 and data["states"] == {"completed": 1, "partial": 1}
    assert data["modes"] == {"rules": 1, "simulated": 1} and data["real_outcomes"] == {}
    assert data["cwes"] == {"CWE-78": 2} and sum(data["severities"].values()) == 2
    api.post(f"/api/v1/scans/{simulated}/retry")
    run(api)  # attempt 1 stored next to attempt 0: only the current one is counted
    assert api.get("/api/v1/workspace").json()["cwes"] == {"CWE-78": 2}
    finding = api.get(f"/api/v1/scans/{rules}/findings").json()["findings"][0]
    artifact = api.get(f"/api/v1/scans/{rules}").json()["scan"]["artifacts"][0]
    repair(api, finding, artifact)
    work(api)
    stats = api.get("/api/v1/workspace").json()["repairs"]
    assert stats["total"] == 1 and stats["simulated"] == 1
    assert stats["by_status"] == {"candidate": 1} and sum(stats["verdicts"].values()) == 1
    assert "passed" not in stats["verdicts"] and stats["verdicts_truncated"] is False


def test_finding_filters_facets_and_pagination(api):
    artifact = put(api, TWO, "two.py")
    scan_id = create(api, [artifact["id"]]).json()["scan"]["id"]
    run(api)
    base = f"/api/v1/scans/{scan_id}/findings"
    everything = api.get(base).json()
    assert everything["total"] == 2
    assert everything["facets"]["cwe"] == {"CWE-78": 1, "CWE-89": 1}
    assert everything["facets"]["source"] == {"rule": 2}
    narrowed = api.get(f"{base}?cwe=CWE-89").json()
    assert narrowed["total"] == 1 and narrowed["findings"][0]["cwe"] == "CWE-89"
    assert narrowed["facets"] == everything["facets"]  # chips stay stable under a filter
    severity = narrowed["findings"][0]["severity"]
    assert api.get(f"{base}?cwe=CWE-89&severity={severity}").json()["total"] == 1
    assert api.get(f"{base}?source=rule").json()["total"] == 2
    assert api.get(f"{base}?source=llm").json()["total"] == 0
    assert api.get(f"{base}?evidence_status=attack_indicator").json()["total"] == 0
    assert api.get(f"{base}?cwe=CWE-78&source=rule").json()["total"] == 1
    first = api.get(f"{base}?limit=1&offset=0").json()
    second = api.get(f"{base}?limit=1&offset=1").json()
    assert first["total"] == second["total"] == 2
    assert len(first["findings"]) == len(second["findings"]) == 1
    assert first["findings"][0]["id"] != second["findings"][0]["id"]
    assert api.get(f"{base}?offset=10").json()["findings"] == []
    assert api.get(f"{base}?cwe=CWE-1").status_code == 422


def test_history_rows_are_light_summaries_with_server_side_filters(api):
    artifact = put(api, TWO, "two.py")
    create(api, [artifact["id"]])
    create(api)  # a second, smaller rules scan
    run(api)
    run(api)
    data = api.get("/api/v1/workspace/history").json()
    assert data["total"] == 2
    row = next(r for r in data["scans"] if r["findings"]["total"] == 2)
    assert row["mode"] == "rules" and row["findings"]["cwes"] == {"CWE-78": 1, "CWE-89": 1}
    assert row["artifacts"] == [{"display_name": "two.py", "input_type": "source"}]
    assert not {"receipt", "result", "attempts", "budget"} & row.keys()
    assert (
        row["repairs"]["total"] == 0
        and row["repairs"]["current"] == 0
        and row["repairs"]["archived"] == 0
    )
    severity = next(iter(row["findings"]["severities"]))
    history = "/api/v1/workspace/history"
    assert api.get(f"{history}?cwe=CWE-89").json()["total"] == 1
    assert api.get(f"{history}?cwe=CWE-78").json()["total"] == 2
    absent = "low" if severity != "low" else "info"
    assert api.get(f"{history}?severity={absent}").json()["total"] == 0
    both = api.get(f"{history}?status=completed&cwe=CWE-89&severity={severity}").json()
    assert both["total"] == 1 and both["scans"][0]["id"] == row["id"]
    one = api.get(f"{history}?limit=1&offset=1").json()
    assert one["total"] == 2 and len(one["scans"]) == 1
    assert api.get(f"{history}?offset=50").json()["scans"] == []
    assert api.get(f"{history}?cwe=nope").status_code == 422


# --- evidence navigation and compare ---------------------------------------------------


def test_input_view_is_plain_text_and_scoped_to_the_scan(api):
    artifact = put(api, TWO, "two.py")
    scan_id = create(api, [artifact["id"]]).json()["scan"]["id"]
    run(api)
    view = api.get(f"/api/v1/scans/{scan_id}/inputs/{artifact['id']}")
    assert view.status_code == 200
    assert view.headers["content-type"].startswith("application/json")
    body = view.json()["input"]
    assert body["artifact_id"] == artifact["id"] and body["input_type"] == "source"
    assert "os.system" in body["content"] and body["chunk_count"] == 1
    other = put(api, "print(1)\n", "other.py")
    assert api.get(f"/api/v1/scans/{scan_id}/inputs/{other['id']}").status_code == 404


def test_compare_requires_a_candidate_and_shows_both_sides(api, monkeypatch):
    finding, artifact = target(api)
    queued = repair(api, finding, artifact).json()["repair"]["id"]
    refused = api.get(f"/api/v1/repairs/{queued}/compare")
    assert refused.status_code == 409 and refused.json()["error"]["code"] == "CANDIDATE_NOT_READY"
    work(api)
    simulated = api.get(f"/api/v1/repairs/{queued}/compare").json()["compare"]
    assert simulated["simulated"] is True
    assert simulated["original"]["content"] == simulated["candidate"]["content"]
    ident, _, _ = real_repair(api, monkeypatch)
    compare = api.get(f"/api/v1/repairs/{ident}/compare").json()["compare"]
    assert compare["candidate"]["content"] == REPLACEMENT
    assert compare["original"]["content"].startswith("import os\n")
    assert compare["hunks"] and compare["target"] == {
        "cwe": "CWE-78",
        "start_line": 2,
        "end_line": 2,
    }
    assert compare["baseline"] and set(compare["after"]) == {
        "persisting",
        "preexisting",
        "introduced",
    }
    assert compare["after"]["persisting"] == []


def test_compare_is_refused_once_a_candidate_is_no_longer_current(api, monkeypatch):
    ident, *_ = real_repair(api, monkeypatch)
    for status in ("failed", "cancelled"):
        with transaction(api.app.state.engine) as session:
            session.get(Repair, ident).status = status
        refused = api.get(f"/api/v1/repairs/{ident}/compare")
        assert (
            refused.status_code == 409 and refused.json()["error"]["code"] == "CANDIDATE_NOT_READY"
        )
