"""Regression evidence from the first Claude review, verified by Codex."""

import asyncio

import pytest
from app.llm.deepseek import ProviderError
from app.schemas.contracts import AnalysisResult
from app.services.patches import Edit, RepairWire, apply_edits
from app.services.repairs import run_repair_once
from app.worker.runner import run_once
from tests.test_repairs import repair, target
from tests.test_scans import create, upload


def configure(api, monkeypatch):
    monkeypatch.setenv("AEGISFORGE_DEEPSEEK_API_KEY", "synthetic-review-key")
    api.app.state.settings.model_mode = "real"


def provider_factory(replacement, failed_review=False):
    class Provider:
        async def generate(self, request, _target):
            return RepairWire(
                schema_version="repair-1.0",
                explanation="Synthetic review evidence",
                edits=[
                    Edit(
                        start_line=1,
                        end_line=len(request.content.splitlines()),
                        old_text=request.content,
                        new_text=replacement,
                    )
                ],
            )

        async def analyze(self, _request):
            if failed_review:
                raise ProviderError("MODEL_RATE_LIMIT")
            return AnalysisResult(mode="real", analysis_complete=True)

    return lambda *_: Provider()


def test_generated_candidate_survives_failed_model_recheck(api, monkeypatch):
    finding, artifact = target(api)
    configure(api, monkeypatch)
    ident = repair(api, finding, artifact, "deepseek").json()["repair"]["id"]
    replacement = "import subprocess\nsubprocess.run(['echo', request.args['cmd']], shell=False)\n"
    asyncio.run(
        run_repair_once(
            api.app.state.engine, api.app.state.settings, provider_factory(replacement, True)
        )
    )
    item = api.get(f"/api/v1/repairs/{ident}").json()["repair"]
    assert item["status"] == "candidate" and item["candidate_id"] is not None
    assert item["diff"] and item["validation_status"] == "unverified"


def test_unrelated_original_same_cwe_is_not_a_failed_target(api, monkeypatch):
    source = "import os\nos.system(request.args['first'])\nos.system(request.args['second'])\n"
    finding, artifact = target(api, source)
    configure(api, monkeypatch)
    ident = repair(api, finding, artifact, "deepseek").json()["repair"]["id"]
    replacement = source.replace("os.system(request.args['first'])", "safe = request.args['first']")
    asyncio.run(
        run_repair_once(api.app.state.engine, api.app.state.settings, provider_factory(replacement))
    )
    item = api.get(f"/api/v1/repairs/{ident}").json()["repair"]
    assert item["status"] == "candidate" and item["validation_status"] == "unverified"


def test_new_location_of_existing_cwe_is_an_introduced_risk(api, monkeypatch):
    source = (
        "import os\nos.system(request.args['cmd'])\ncursor.execute('SELECT ' + request.args['q'])\n"
    )
    finding, artifact = target(api, source)
    configure(api, monkeypatch)
    ident = repair(api, finding, artifact, "deepseek").json()["repair"]["id"]
    replacement = source.replace(
        "os.system(request.args['cmd'])", "cursor.execute('SELECT ' + request.args['new'])"
    )
    asyncio.run(
        run_repair_once(api.app.state.engine, api.app.state.settings, provider_factory(replacement))
    )
    item = api.get(f"/api/v1/repairs/{ident}").json()["repair"]
    assert item["status"] == "candidate" and item["validation_status"] == "failed"


def test_simulated_candidate_is_unverified(api):
    finding, artifact = target(api)
    ident = repair(api, finding, artifact).json()["repair"]["id"]
    asyncio.run(run_repair_once(api.app.state.engine, api.app.state.settings))
    assert api.get(f"/api/v1/repairs/{ident}").json()["repair"]["validation_status"] == "unverified"


def test_unterminated_last_line_has_an_applicable_unified_diff():
    _, diff = apply_edits("x=1", [Edit(start_line=1, end_line=1, old_text="x=1", new_text="x=2")])
    assert "-x=1+x=2" not in diff
    assert "\\ No newline at end of file" in diff


def test_repair_protocol_version_is_literal():
    with pytest.raises(ValueError):
        RepairWire(
            schema_version="repair-1x0",
            explanation="bad version",
            edits=[Edit(start_line=1, end_line=1, old_text="x=1", new_text="x=2")],
        )


def test_parent_retry_during_recheck_blocks_stale_candidate_publish(api, monkeypatch):
    artifact_id = upload(api)
    scan = create(api, [artifact_id], strategy="hybrid").json()["scan"]
    asyncio.run(run_once(api.app.state.engine, api.app.state.settings))
    finding = api.get(f"/api/v1/scans/{scan['id']}/findings").json()["findings"][0]
    configure(api, monkeypatch)
    ident = repair(api, finding, scan["artifacts"][0], "deepseek").json()["repair"]["id"]
    base = provider_factory(
        "import subprocess\nsubprocess.run(['echo',request.args['cmd']], shell=False)\n"
    )

    class Racing:
        async def generate(self, request, target):
            return await base().generate(request, target)

        async def analyze(self, _request):
            assert api.post(f"/api/v1/scans/{scan['id']}/retry").status_code == 202
            return AnalysisResult(mode="real", analysis_complete=True)

    asyncio.run(run_repair_once(api.app.state.engine, api.app.state.settings, lambda *_: Racing()))
    item = api.get(f"/api/v1/repairs/{ident}").json()["repair"]
    assert item["error_code"] == "REPAIR_STALE"
    assert item["status"] != "candidate"
