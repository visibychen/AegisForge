"""Codex's independent review of Claude's stage-2 implementation."""

import asyncio
import hashlib
import json
from types import SimpleNamespace

from app.services.patch_review import build_line_map, finding_delta
from app.services.receipts import digest
from app.services.repairs import run_repair_once
from app.validation.runner import daemon_source
from tests.test_m4_review import configure, provider_factory
from tests.test_repairs import repair, target


def test_unequal_diff_block_cannot_reuse_one_old_finding_for_two_new_calls(api, monkeypatch):
    source = (
        "import os\nos.system(request.args['cmd'])\ncursor.execute('SELECT ' + request.args['q'])\n"
    )
    finding, artifact = target(api, source)
    configure(api, monkeypatch)
    ident = repair(api, finding, artifact, "deepseek").json()["repair"]["id"]
    replacement = (
        "import os\nsafe = request.args['cmd']\n"
        "cursor.execute('SELECT ' + request.args['q_updated'])\n"
        "cursor.execute('SELECT ' + request.args['introduced'])\n"
    )
    asyncio.run(
        run_repair_once(api.app.state.engine, api.app.state.settings, provider_factory(replacement))
    )
    item = api.get(f"/api/v1/repairs/{ident}").json()["repair"]
    assert item["status"] == "candidate"
    assert item["checks"]["delta"]["rules"]["introduced"]
    assert item["validation_status"] == "failed"


def test_moved_statement_matches_once_but_clone_is_a_new_risk():
    old = "danger(value)\nsafe()\n"
    new = "safe()\ndanger(value)\ndanger(value)\n"
    delta = finding_delta(
        [("CWE-78", 1, 1, "rule"), ("CWE-78", 1, 1, "parent:rule")],
        ("CWE-78", 1, 1),
        [("CWE-78", 2, 2, "rule"), ("CWE-78", 3, 3, "rule")],
        build_line_map(old, new),
        old,
        new,
    )
    assert len(delta["persisting"]) == 1 and len(delta["introduced"]) == 1


def test_neighboring_sinks_are_not_collapsed_by_overlapping_other_engine():
    old = "danger(a)\ndanger(b)\n"
    new = "safe(a)\ndanger(b)\n"
    delta = finding_delta(
        [("CWE-78", 1, 1, "rule"), ("CWE-78", 2, 2, "rule"), ("CWE-78", 1, 2, "llm")],
        ("CWE-78", 1, 1),
        [("CWE-78", 2, 2, "rule")],
        build_line_map(old, new),
        old,
        new,
    )
    assert delta["target_resolved"] and len(delta["preexisting"]) == 1


def test_candidate_receipt_is_bound_and_only_one_candidate_is_stored(api, monkeypatch):
    from app.models import Artifact
    from sqlalchemy import func, select
    from sqlalchemy.orm import Session

    finding, artifact = target(api)
    configure(api, monkeypatch)
    ident = repair(api, finding, artifact, "deepseek").json()["repair"]["id"]
    replacement = "safe = request.args['cmd']\n"
    asyncio.run(
        run_repair_once(api.app.state.engine, api.app.state.settings, provider_factory(replacement))
    )
    item = api.get(f"/api/v1/repairs/{ident}").json()["repair"]
    contract = item["checks"]["contract"]
    assert contract["digest"] == digest({k: v for k, v in contract.items() if k != "digest"})
    assert contract["source_sha256"] == artifact["sha256"]
    assert contract["candidate_sha256"] == hashlib.sha256(replacement.encode()).hexdigest()
    assert "synthetic-review-key" not in json.dumps(contract)
    with Session(api.app.state.engine) as session:
        assert session.scalar(select(func.count()).select_from(Artifact)) == 2


def test_daemon_mount_translation_stays_under_trusted_data_root(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGISFORGE_VALIDATOR_HOST_DATA_DIR", "/host/data")
    settings = SimpleNamespace(data_dir=tmp_path)
    assert (
        daemon_source(settings, tmp_path / "validation-id/candidate.py")
        == "/host/data/validation-id/candidate.py"
    )
    import pytest

    with pytest.raises(ValueError):
        daemon_source(settings, tmp_path.parent / "outside.py")


def test_browser_sample_copies_keep_frozen_development_identity():
    from app.validation.registry import ROOT, load_cases

    examples = json.loads(
        (ROOT / "frontend/src/examples/controlledSamples.json").read_text("utf-8")
    )
    for case in load_cases():
        item = next(e for e in examples if e["id"] == case["id"])
        assert hashlib.sha256(item["source"].encode()).hexdigest() == case["source_sha256"]


def test_desktop_mount_conversion_and_rejection():
    import pytest
    from app.validation.runner import ResultError, normalize_daemon_root

    assert (
        normalize_daemon_root(r"D:\projects\forge\data")
        == "/run/desktop/mnt/host/d/projects/forge/data"
    )
    assert normalize_daemon_root("/srv/data") == "/srv/data"
    for value in ("relative/data", "/srv/../secret", r"D:\data\..\secret"):
        with pytest.raises(ResultError):
            normalize_daemon_root(value)


def test_execution_contract_survives_rejected_model_patch(api, monkeypatch):
    finding, artifact = target(api)
    configure(api, monkeypatch)
    ident = repair(api, finding, artifact, "deepseek").json()["repair"]["id"]
    asyncio.run(
        run_repair_once(api.app.state.engine, api.app.state.settings, provider_factory("broken(\n"))
    )
    item = api.get(f"/api/v1/repairs/{ident}").json()["repair"]
    assert item["status"] == "failed" and item["error_code"] == "PATCH_SYNTAX"
    assert item["checks"]["contract"]["source_sha256"] == artifact["sha256"]


def test_repair_mutations_initialize_database_after_api_restart(api):
    from uuid import uuid4

    from app.main import create_app
    from fastapi.testclient import TestClient

    for action in ("create", "cancel", "validate"):
        fresh = create_app(api.app.state.settings)
        with TestClient(fresh, raise_server_exceptions=False) as client:
            client.headers["Authorization"] = "Bearer test-token"
            if action == "create":
                response = client.post(
                    "/api/v1/repairs",
                    headers={"Idempotency-Key": str(uuid4())},
                    json={
                        "finding_id": str(uuid4()),
                        "source_sha256": "a" * 64,
                        "model_alias": "fake",
                    },
                )
            else:
                response = client.post(f"/api/v1/repairs/{uuid4()}/{action}")
            assert response.status_code == 404
        fresh.state.engine.dispose()
