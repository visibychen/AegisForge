import copy
import json
from uuid import uuid4

import pytest
from app.models import FindingRecord, Repair
from app.services.queue import transaction
from app.services.report_integrity import MAX_BYTES, read_report, verify_bytes
from app.services.workspace import _delta_lists
from app.validation.runner import validate_one
from sqlalchemy import select
from sqlalchemy.orm import Session
from tests.test_m5_workbench import work
from tests.test_repairs import repair
from tests.test_scans import create, run


def test_export_checksum_is_stable_and_rejects_tampering(api, tmp_path):
    ident = create(api).json()["scan"]["id"]
    run(api)
    first = api.get(f"/api/v1/workspace/{ident}/report").json()
    second = api.get(f"/api/v1/workspace/{ident}/report").json()
    assert first["content_digest"] == second["content_digest"]
    assert (
        first["content_digest"] in api.get(f"/api/v1/workspace/{ident}/report?format=markdown").text
    )
    raw = json.dumps(first).encode()
    assert verify_bytes(raw)["schema_version"] == "report-2.1"
    path = tmp_path / "report.json"
    path.write_bytes(raw)
    assert read_report(path)["scan"]["id"] == ident
    changed = copy.deepcopy(first)
    changed["scan"]["status"] = "failed"
    for invalid in (
        json.dumps(changed).encode(),
        raw[:-5],
        raw.replace(b'"source_free": true', b'"source_free": true, "source_free": true'),
        raw.replace(b'"source_free": true', b'"source_free": NaN'),
        b" " * (MAX_BYTES + 1),
    ):
        with pytest.raises((ValueError, RecursionError)):
            verify_bytes(invalid)


def test_report_snapshot_survives_a_concurrent_writer(api, monkeypatch):
    from app.api import workspace

    ident = create(api).json()["scan"]["id"]
    run(api)
    original = workspace.build_report

    def after_first_select(session, scan):
        with Session(api.app.state.engine) as other:
            row = other.scalar(select(FindingRecord).where(FindingRecord.scan_id == ident))
            other.add(
                FindingRecord(
                    id=str(uuid4()),
                    scan_id=ident,
                    artifact_id=row.artifact_id,
                    attempt=row.attempt,
                    position=999,
                    payload=row.payload,
                )
            )
            other.commit()
        return original(session, scan)

    monkeypatch.setattr(workspace, "build_report", after_first_select)
    response = api.get(f"/api/v1/workspace/{ident}/report")
    assert response.status_code == 200
    report = response.json()
    assert report["findings_by_attempt"]["0"] == len(report["findings"]) == 1
    assert api.get(f"/api/v1/scans/{ident}/findings").json()["total"] == 2


def test_archived_candidates_keep_history_but_cannot_run_new_validation(api):
    scan = create(api, strategy="hybrid").json()["scan"]
    run(api)
    finding = api.get(f"/api/v1/scans/{scan['id']}/findings").json()["findings"][0]
    item = repair(api, finding, scan["artifacts"][0]).json()["repair"]
    work(api)
    assert api.post(f"/api/v1/scans/{scan['id']}/retry").status_code == 202
    run(api)
    base = f"/api/v1/repairs/{item['id']}"
    assert api.get(base).json()["repair"]["archived"] is True
    compare = api.get(base + "/compare").json()["compare"]
    assert compare["finding_attempt"] == 0 and compare["scan_attempt"] == 1 and compare["archived"]
    assert api.get(base + "/download?format=source").status_code == 200
    refused = api.post(base + "/validate")
    assert refused.status_code == 409 and refused.json()["error"]["code"] == "REPAIR_ARCHIVED"
    assert api.post(base + "/cancel").status_code == 200
    with transaction(api.app.state.engine) as session:
        row = session.get(Repair, item["id"])
        row.dynamic_requested, row.dynamic_json = True, '{"status":"pending"}'
    calls = []
    validate_one(
        api.app.state.engine,
        api.app.state.settings,
        item["id"],
        runner=lambda *_a, **_k: calls.append(True),
    )
    assert not calls
    assert api.get(base).json()["repair"]["dynamic"]["error_code"] == "REPAIR_ARCHIVED"
    counts = api.get("/api/v1/workspace/history").json()["scans"][0]["repairs"]
    assert counts["archived"] == 1 and counts["current"] == 0 and counts["total"] == 1


def test_compare_deduplicates_positions_without_losing_source_disagreement():
    position = {"cwe": "CWE-78", "start_line": 2, "end_line": 2}
    merged, positions = _delta_lists(
        {
            "delta": {
                "rules": {"persisting": [position]},
                "model": {"preexisting": [position]},
            }
        }
    )
    assert len(positions) == 1 and len(merged["persisting"]) == 1
    assert positions[0]["by_source"] == {"rule": "persisting", "llm": "preexisting"}
    assert not merged["preexisting"]


def test_history_counts_more_than_300_repairs_without_hiding_later_tasks(api):
    from app.models import Job
    from sqlalchemy import insert
    from tests.test_scans import upload

    source = "import os\n" + "".join(f"os.system(request.args['c{i}'])\n" for i in range(101))
    first = create(api, [upload(api, source)]).json()["scan"]
    run(api)
    second = create(api).json()["scan"]
    run(api)
    jobs, repairs = [], []
    for scan in (first, second):
        findings = []
        for offset in (0, 100):
            findings += api.get(
                f"/api/v1/scans/{scan['id']}/findings?offset={offset}&limit=100"
            ).json()["findings"]
        for finding in findings:
            for _ in range(3 if scan["id"] == first["id"] else 1):
                jid = str(uuid4())
                jobs.append(
                    {
                        "id": jid,
                        "scan_id": scan["id"],
                        "kind": "repair",
                        "status": "failed",
                        "idempotency_key": jid,
                    }
                )
                repairs.append(
                    {
                        "id": str(uuid4()),
                        "scan_id": scan["id"],
                        "finding_id": finding["id"],
                        "source_id": finding["location"]["artifact_id"],
                        "job_id": jid,
                        "source_sha256": scan["artifacts"][0]["sha256"],
                        "anchor": "a" * 64,
                        "model_alias": "fake",
                        "model_name": "deepseek-flash",
                        "status": "failed",
                        "checks_json": '{"mode":"fake"}',
                    }
                )
    assert len(repairs) > 300
    with Session(api.app.state.engine) as session:
        session.execute(insert(Job), jobs)
        session.execute(insert(Repair), repairs)
        session.commit()
    rows = {r["id"]: r for r in api.get("/api/v1/workspace/history").json()["scans"]}
    assert rows[first["id"]]["repairs"]["total"] == len(repairs) - 1
    assert rows[second["id"]]["repairs"]["total"] == 1
    assert rows[first["id"]]["repairs"]["simulated"] == len(repairs) - 1
