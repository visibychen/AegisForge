import asyncio
from uuid import uuid4

import pytest
from app.core.errors import DomainError
from app.schemas.contracts import AnalysisResult
from app.services.patches import Edit, RepairWire, apply_edits
from app.services.repairs import run_repair_once
from app.worker.runner import run_once
from tests.test_scans import create, upload


def target(api, source=None):
    artifact_id = upload(api) if source is None else upload(api, source)
    scan = create(api, [artifact_id]).json()["scan"]
    asyncio.run(run_once(api.app.state.engine, api.app.state.settings))
    finding = api.get(f"/api/v1/scans/{scan['id']}/findings").json()["findings"][0]
    return finding, scan["artifacts"][0]


def repair(api, finding, artifact, alias="fake", key=None):
    return api.post(
        "/api/v1/repairs",
        headers={"Idempotency-Key": key or str(uuid4())},
        json={
            "finding_id": finding["id"],
            "source_sha256": artifact["sha256"],
            "model_alias": alias,
        },
    )


def test_fake_candidate_persists_without_claiming_real_repair(api):
    finding, artifact = target(api)
    created = repair(api, finding, artifact)
    assert created.status_code == 202, created.text
    repair_id = created.json()["repair"]["id"]
    assert asyncio.run(run_once(api.app.state.engine, api.app.state.settings))
    item = api.get(f"/api/v1/repairs/{repair_id}").json()["repair"]
    assert item["status"] == "candidate" and item["candidate_id"] != artifact["id"]
    assert item["validation_status"] != "passed" and item["checks"]["mode"] == "fake"
    assert item["call_count"] == 0
    assert api.get(f"/api/v1/repairs/{repair_id}/download?format=source").status_code == 200
    assert (
        api.get(f"/api/v1/artifacts/{artifact['id']}").json()["artifact"]["sha256"]
        == artifact["sha256"]
    )
    assert (
        api.post(f"/api/v1/repairs/{repair_id}/validate").json()["error"]["code"]
        == "CONTROLLED_SAMPLE_REQUIRED"
    )


def test_real_adapter_path_rechecks_and_stays_unverified_without_dynamic(api, monkeypatch):
    finding, artifact = target(api)
    monkeypatch.setenv("AEGISFORGE_DEEPSEEK_API_KEY", "synthetic-repair-key")
    api.app.state.settings.model_mode = "real"
    repair_id = repair(api, finding, artifact, "deepseek").json()["repair"]["id"]

    class Provider:
        async def generate(self, request, _target):
            return RepairWire(
                schema_version="repair-1.0",
                explanation="Use an argument array",
                edits=[
                    Edit(
                        start_line=1,
                        end_line=2,
                        old_text=request.content,
                        new_text=(
                            "import subprocess\n"
                            "subprocess.run(['echo', request.args['cmd']], shell=False)\n"
                        ),
                    )
                ],
            )

        async def analyze(self, _request):
            return AnalysisResult(mode="real", analysis_complete=True)

    asyncio.run(
        run_repair_once(api.app.state.engine, api.app.state.settings, lambda *_: Provider())
    )
    item = api.get(f"/api/v1/repairs/{repair_id}").json()["repair"]
    assert item["status"] == "candidate" and item["checks"]["static_passed"]
    assert item["validation_status"] == "unverified" and "--- original.py" in item["diff"]


def test_idempotency_cancel_hash_conflict_and_auth(api):
    finding, artifact = target(api)
    key = str(uuid4())
    first = repair(api, finding, artifact, key=key).json()["repair"]
    assert repair(api, finding, artifact, key=key).json()["repair"]["id"] == first["id"]
    assert repair(api, finding, {**artifact, "sha256": "0" * 64}, key=key).status_code == 409
    assert (
        repair(api, finding, {**artifact, "sha256": "0" * 64}).json()["error"]["code"]
        == "REPAIR_STALE"
    )
    assert (
        api.post(f"/api/v1/repairs/{first['id']}/cancel").json()["repair"]["status"] == "cancelled"
    )
    api.headers.pop("Authorization")
    assert api.get(f"/api/v1/repairs/{first['id']}").status_code == 401


@pytest.mark.parametrize(
    "start,end,old,new,code",
    [
        (0, 1, "x=1\n", "x=2\n", None),
        (1, 3, "x=1\n", "x=2\n", "PATCH_RANGE"),
        (1, 1, "wrong", "x=2\n", "PATCH_CONFLICT"),
        (1, 1, "x=1\n", "if (\n", "PATCH_SYNTAX"),
        (1, 1, "x=1\n", "api_key = 'some-new-value-1234'\n", "PATCH_SENSITIVE"),
    ],
)
def test_edits_reject_bad_ranges_conflicts_and_unsafe_content(start, end, old, new, code):
    if code is None:
        with pytest.raises(ValueError):
            Edit(start_line=start, end_line=end, old_text=old, new_text=new)
    else:
        with pytest.raises(DomainError, match=code):
            apply_edits("x=1\n", [Edit(start_line=start, end_line=end, old_text=old, new_text=new)])


def test_overlapping_edits_and_extra_wire_keys_rejected():
    with pytest.raises(DomainError, match="PATCH_RANGE"):
        apply_edits(
            "x=1\n", [Edit(start_line=1, end_line=1, old_text="x=1\n", new_text="x=2\n")] * 2
        )
    with pytest.raises(ValueError):
        RepairWire.model_validate(
            {"schema_version": "repair-1.0", "explanation": "x", "edits": [], "command": "run"}
        )
