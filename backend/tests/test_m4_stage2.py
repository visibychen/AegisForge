"""M4 stage 2: gates, phased candidates, recovery, limits and the dynamic-evidence state machine.

No Docker is used anywhere: dynamic runs are replaced by in-process stand-ins that return the
same record shape the real runner produces.
"""

import asyncio
import hashlib
import json
from datetime import timedelta

import pytest
from app.models import Job, ModelCall, Repair
from app.services.queue import claim, transaction, utcnow
from app.services.repairs import claim_repair, run_repair_once
from app.validation.runner import (
    ResultError,
    mark_interrupted,
    parse_harness_output,
    validate_one,
)
from sqlalchemy.exc import OperationalError
from tests.test_m4_review import configure, provider_factory
from tests.test_repairs import repair, target

REPLACEMENT = "import subprocess\nsubprocess.run(['echo', request.args['cmd']], shell=False)\n"
SOURCE = (
    "from flask import request\nimport os\n\n"
    "def run():\n    os.system(request.args['cmd'])\n    return 'ok'\n"
)
TESTS = ["business_ping", "business_second_host", "security_shell_boundary"]


def run(api, factory=None):
    return asyncio.run(run_repair_once(api.app.state.engine, api.app.state.settings, factory))


def view(api, ident):
    return api.get(f"/api/v1/repairs/{ident}").json()["repair"]


def real_repair(api, monkeypatch, source=None, replacement=REPLACEMENT):
    finding, artifact = target(api, source)
    configure(api, monkeypatch)
    ident = repair(api, finding, artifact, "deepseek").json()["repair"]["id"]
    run(api, provider_factory(replacement))
    return ident, artifact, finding


def register(monkeypatch, tmp_path, sha256):
    path = tmp_path / "cases.json"
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {"id": "cmdi-01", "sample_id": "t", "source_sha256": sha256, "tests": TESTS}
                ]
            }
        )
    )
    monkeypatch.setattr("app.validation.registry.REGISTRY", path)


def stand_in(status="passed", candidate=None):
    def run_it(settings, source, case, *, run_id, should_cancel):
        return {
            "status": status,
            "run_id": run_id,
            "case_id": case["id"],
            "tests": [{"name": name, "passed": status == "passed"} for name in case["tests"]],
            "candidate_sha256": candidate or hashlib.sha256(source.encode()).hexdigest(),
            "image_id": "sha256:" + "a" * 64,
            "harness_sha256": "h" * 64,
            "elapsed_ms": 5,
        }

    return run_it


# --- gate ledger and verdicts ------------------------------------------------------------


def test_safe_edit_keeps_structure_and_passes_every_static_gate(api, monkeypatch):
    replacement = SOURCE.replace(
        "os.system(request.args['cmd'])", "subprocess.run(['echo', request.args['cmd']])"
    ).replace("import os", "import subprocess")
    ident, *_ = real_repair(api, monkeypatch, SOURCE, replacement)
    item = view(api, ident)
    states = {g["id"]: g["state"] for g in item["gates"]}
    assert item["status"] == "candidate" and item["checks"]["static_passed"] is True
    assert all(states[name] == "passed" for name in list(states)[:7])
    assert states["dynamic_security"] == "skipped" and item["validation_status"] == "unverified"


@pytest.mark.parametrize(
    ("replacement", "violation"),
    [
        ("import os\n", "removed_definition"),
        (SOURCE.replace("def run():", "def run(extra):"), "signature_changed"),
        (
            SOURCE.replace("os.system(request.args['cmd'])", "eval(request.args['cmd'])"),
            "forbidden_call_added",
        ),
    ],
)
def test_scope_violations_refuse_the_patch_but_explain_why(
    api, monkeypatch, replacement, violation
):
    ident, *_ = real_repair(api, monkeypatch, SOURCE, replacement)
    item = view(api, ident)
    assert item["status"] == "failed" and item["error_code"] == "PATCH_SCOPE"
    assert violation in item["impact"]["violations"]
    assert {g["id"]: g["state"] for g in item["gates"]}["structure"] == "failed"
    assert item["validation_status"] == "failed"
    assert api.get(f"/api/v1/repairs/{ident}/download").status_code == 409


def test_simulated_run_is_explicitly_unverified_with_skipped_gates(api):
    finding, artifact = target(api)
    ident = repair(api, finding, artifact).json()["repair"]["id"]
    run(api)
    item = view(api, ident)
    states = {g["id"]: g["state"] for g in item["gates"]}
    assert item["simulated"] is True and item["validation_status"] == "unverified"
    assert states["target_rules"] == states["target_model"] == "skipped"


# --- phased persistence and time limits --------------------------------------------------


def test_generation_timeout_fails_as_a_tool_error(api):
    finding, artifact = target(api)
    api.app.state.settings.task_timeout_seconds = 0.3
    ident = repair(api, finding, artifact).json()["repair"]["id"]

    class Hang:
        async def generate(self, *_):
            await asyncio.sleep(5)

    with transaction(api.app.state.engine) as session:
        session.get(Repair, ident).model_alias = "deepseek"
    run(api, lambda *_: Hang())
    item = view(api, ident)
    assert item["status"] == "failed" and item["error_code"] == "TASK_TIMEOUT"
    assert item["validation_status"] == "error"


def test_review_timeout_keeps_the_generated_candidate(api, monkeypatch):
    finding, artifact = target(api)
    configure(api, monkeypatch)
    api.app.state.settings.task_timeout_seconds = 0.6
    ident = repair(api, finding, artifact, "deepseek").json()["repair"]["id"]
    base = provider_factory(REPLACEMENT)()

    class SlowReview:
        async def generate(self, request, tgt):
            return await base.generate(request, tgt)

        async def analyze(self, _request):
            await asyncio.sleep(5)

    run(api, lambda *_: SlowReview())
    item = view(api, ident)
    assert item["status"] == "candidate" and item["diff"]
    assert item["checks"]["review"] == {"status": "failed", "error": "TASK_TIMEOUT"}
    assert item["validation_status"] == "unverified"


def test_heartbeat_storage_errors_do_not_stop_the_repair(api, monkeypatch):
    finding, artifact = target(api)
    configure(api, monkeypatch)
    ident = repair(api, finding, artifact, "deepseek").json()["repair"]["id"]
    beats = []

    def broken(*_args):
        beats.append(1)
        raise OperationalError("UPDATE jobs", {}, Exception("database is locked"))

    monkeypatch.setattr("app.services.repairs.heartbeat_repair", broken)
    base = provider_factory(REPLACEMENT)()

    class Patient:
        async def generate(self, request, tgt):
            await asyncio.sleep(2.4)
            return await base.generate(request, tgt)

        async def analyze(self, request):
            return await base.analyze(request)

    run(api, lambda *_: Patient())
    assert len(beats) >= 2 and view(api, ident)["status"] == "candidate"


# --- queue behaviour ---------------------------------------------------------------------


def test_recovered_leases_interrupt_started_calls_and_exhaustion_is_final(api):
    finding, artifact = target(api)
    ident = repair(api, finding, artifact).json()["repair"]["id"]
    engine, settings = api.app.state.engine, api.app.state.settings
    for _ in range(3):
        lease = claim_repair(engine, settings)
        assert lease is not None
        with transaction(engine) as session:
            job = session.get(Job, lease.job_id)
            session.add(
                ModelCall(
                    scan_id=lease.scan_id,
                    job_id=job.id,
                    model="m",
                    prompt_version="p",
                    input_chars=1,
                )
            )
            job.lease_until = utcnow() - timedelta(seconds=1)
    assert claim_repair(engine, settings) is None
    item = view(api, ident)
    assert item["status"] == "failed" and item["error_code"] == "LEASE_EXHAUSTED"
    assert {call["status"] for call in item["calls"]} == {"interrupted"}


def test_scan_worker_never_claims_repair_jobs(api):
    finding, artifact = target(api)
    repair(api, finding, artifact)
    assert claim(api.app.state.engine, api.app.state.settings) is None


def test_one_live_candidate_per_finding_and_a_total_limit(api):
    finding, artifact = target(api)
    first = repair(api, finding, artifact).json()["repair"]["id"]
    assert repair(api, finding, artifact).json()["repair"]["id"] == first
    mixed = repair(api, finding, artifact, "deepseek")
    assert mixed.status_code in {409, 422}
    current = first
    for _ in range(2):
        api.post(f"/api/v1/repairs/{current}/cancel")
        current = repair(api, finding, artifact).json()["repair"]["id"]
        assert current != first
    api.post(f"/api/v1/repairs/{current}/cancel")
    refused = repair(api, finding, artifact)
    assert refused.status_code == 409 and refused.json()["error"]["code"] == "REPAIR_LIMIT"


def test_real_repairs_are_prechecked_against_the_remaining_call_budget(api, monkeypatch):
    finding, artifact = target(api)
    configure(api, monkeypatch)
    api.app.state.settings.max_model_calls = 1
    refused = repair(api, finding, artifact, "deepseek")
    assert refused.status_code == 409 and refused.json()["error"]["code"] == "REPAIR_BUDGET"
    assert repair(api, finding, artifact, "fake").status_code == 202


# --- dynamic evidence state machine ------------------------------------------------------


def test_passed_needs_a_sealed_record_bound_to_the_candidate(api, monkeypatch, tmp_path):
    ident, artifact, _ = real_repair(api, monkeypatch)
    register(monkeypatch, tmp_path, artifact["sha256"])
    assert view(api, ident)["validation_status"] == "unverified"
    assert api.post(f"/api/v1/repairs/{ident}/validate").status_code == 202
    again = api.post(f"/api/v1/repairs/{ident}/validate")
    assert again.json()["error"]["code"] == "VALIDATION_IN_PROGRESS"
    assert validate_one(api.app.state.engine, api.app.state.settings, ident, stand_in())
    item = view(api, ident)
    assert item["dynamic"]["status"] == "passed" and item["dynamic"]["digest"]
    assert {g["state"] for g in item["gates"]} == {"passed"}
    assert item["validation_status"] == "passed"
    for key in ("source_sha256", "candidate_sha256", "tests_sha256", "registry_sha256", "run_id"):
        assert item["dynamic"][key]
    with transaction(api.app.state.engine) as session:
        row = session.get(Repair, ident)
        data = json.loads(row.dynamic_json)
        data["elapsed_ms"] = 1  # any edit breaks the integrity digest
        row.dynamic_json = json.dumps(data)
    assert view(api, ident)["validation_status"] == "error"


def test_a_result_for_different_bytes_is_never_accepted(api, monkeypatch, tmp_path):
    ident, artifact, _ = real_repair(api, monkeypatch)
    register(monkeypatch, tmp_path, artifact["sha256"])
    api.post(f"/api/v1/repairs/{ident}/validate")
    validate_one(api.app.state.engine, api.app.state.settings, ident, stand_in(candidate="0" * 64))
    item = view(api, ident)
    assert item["dynamic"]["status"] == "error" and item["validation_status"] == "error"


def test_failed_dynamic_tests_fail_the_verdict(api, monkeypatch, tmp_path):
    ident, artifact, _ = real_repair(api, monkeypatch)
    register(monkeypatch, tmp_path, artifact["sha256"])
    api.post(f"/api/v1/repairs/{ident}/validate")
    validate_one(api.app.state.engine, api.app.state.settings, ident, stand_in("failed"))
    assert view(api, ident)["validation_status"] == "failed"


def test_unknown_samples_end_explainably_without_looping(api):
    finding, artifact = target(api)
    ident = repair(api, finding, artifact).json()["repair"]["id"]
    run(api)
    engine, settings = api.app.state.engine, api.app.state.settings
    with transaction(engine) as session:
        session.get(Repair, ident).dynamic_requested = True
    assert validate_one(engine, settings, None, stand_in()) is True
    assert view(api, ident)["dynamic"]["error_code"] == "CONTROLLED_SAMPLE_REQUIRED"
    assert validate_one(engine, settings, None, stand_in()) is False


def test_crashed_runner_records_expire_instead_of_staying_running(api):
    finding, artifact = target(api)
    ident = repair(api, finding, artifact).json()["repair"]["id"]
    engine = api.app.state.engine
    old = (utcnow() - timedelta(seconds=900)).isoformat()
    fresh = utcnow().isoformat()
    for started, expected in ((fresh, 0), (old, 1)):
        with transaction(engine) as session:
            session.get(Repair, ident).dynamic_json = json.dumps(
                {"status": "running", "run_id": "r", "started_at": started}
            )
        assert mark_interrupted(engine) == expected
    assert view(api, ident)["dynamic"]["error_code"] == "VALIDATION_INTERRUPTED"


def test_pending_and_running_validations_can_be_cancelled(api, monkeypatch, tmp_path):
    ident, artifact, _ = real_repair(api, monkeypatch)
    register(monkeypatch, tmp_path, artifact["sha256"])
    engine, settings = api.app.state.engine, api.app.state.settings
    api.post(f"/api/v1/repairs/{ident}/validate")
    cancelled = api.post(f"/api/v1/repairs/{ident}/cancel").json()["repair"]
    assert cancelled["dynamic"]["status"] == "cancelled" and not cancelled["dynamic_requested"]
    assert validate_one(engine, settings, ident, stand_in()) is False

    api.post(f"/api/v1/repairs/{ident}/validate")

    def cancelling(settings, source, case, *, run_id, should_cancel):
        assert api.post(f"/api/v1/repairs/{ident}/cancel").status_code == 200
        assert should_cancel() is True
        return {"status": "cancelled", "run_id": run_id, "elapsed_ms": 1}

    assert validate_one(engine, settings, ident, cancelling)
    item = view(api, ident)
    assert item["dynamic"]["status"] == "cancelled" and item["validation_status"] == "unverified"


# --- container result protocol -----------------------------------------------------------

CASE = {"id": "cmdi-01", "tests": TESTS}
NONCE, SHA = "a" * 32, "b" * 64


def line(**override):
    data = {
        "schema_version": "validation-2.0",
        "case": "cmdi-01",
        "nonce": NONCE,
        "candidate_sha256": SHA,
        "tests": [{"name": name, "passed": True} for name in TESTS],
        "passed": True,
    }
    data.update(override)
    return (json.dumps(data) + "\n").encode()


def parse(raw, returncode=0):
    return parse_harness_output(
        raw, case=CASE, nonce=NONCE, candidate_sha256=SHA, returncode=returncode
    )


def test_a_well_formed_single_result_line_is_accepted():
    assert [t["name"] for t in parse(line())] == TESTS
    failing = [{"name": n, "passed": n != TESTS[2]} for n in TESTS]
    assert parse(line(tests=failing, passed=False), 1)[2]["passed"] is False


@pytest.mark.parametrize(
    "raw",
    [
        line(nonce="c" * 32),
        line() + line(),
        line(extra=1),
        line(passed=1),
        line(candidate_sha256="d" * 64),
        line(tests=[{"name": n, "passed": True} for n in reversed(TESTS)]),
        line(tests=[{"name": TESTS[0], "passed": True}]),
        line(tests=[{"name": n, "passed": "yes"} for n in TESTS]),
        line(schema_version="validation-1.0"),
        line(case="xss-01"),
        b"not json\n",
        b'{"nonce": "x", "nonce": "y"}\n',
    ],
)
def test_forged_or_malformed_output_is_a_protocol_error(raw):
    with pytest.raises(ResultError, match="VALIDATION_PROTOCOL"):
        parse(raw)


def test_inconsistent_verdicts_empty_and_oversized_output_are_distinct_errors():
    with pytest.raises(ResultError, match="VALIDATION_PROTOCOL"):
        parse(line(), returncode=1)
    with pytest.raises(ResultError, match="VALIDATION_NO_RESULT"):
        parse(b"\n")
    with pytest.raises(ResultError, match="VALIDATION_OUTPUT_LIMIT"):
        parse(line() + b"x" * 20000)
