"""One post-hoc repair diagnosis per known historical target; never replaces the baseline.

The historical second detection round found all 18 registered targets. We clone those synthetic
databases and request a later candidate under the new prompts. This is a conditional diagnosis
after outcomes were exposed, not a new first-candidate or end-to-end acceptance experiment.
"""

import argparse
import asyncio
import hashlib
import json
import os
import shutil
import sys
from collections import Counter
from uuid import uuid4

from _environment import ROOT, model_environment, require_conda


def main():
    require_conda()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-real", action="store_true")
    args = parser.parse_args()
    if not args.execute_real:
        parser.error("--execute-real is required")
    sys.path[:0] = [str(ROOT), str(ROOT / "backend")]
    os.environ.update(model_environment())
    from app.core.database import build_engine
    from app.main import create_app
    from app.services.repairs import run_repair_once
    from fastapi.testclient import TestClient

    from evaluation.budget import ExperimentBudget
    from evaluation.experiment import (
        BUDGET_PATH,
        detection_fingerprint,
        load_data,
        request_json,
        settings_for,
        write_json,
    )
    from evaluation.metrics import overlaps

    manifest, _ = load_data()
    records = {r["id"]: r for r in manifest["samples"]}
    cases = json.loads(
        (ROOT / "samples/holdout/controlled_repairs.json").read_text(encoding="utf-8")
    )["samples"]
    original = ROOT / "data/m6-runs/baseline-2026-11-11"
    destination = ROOT / "data/m6-posthoc-repairs"
    destination.mkdir(parents=True, exist_ok=True)
    budget = ExperimentBudget(BUDGET_PATH, 1000, "posthoc-repairs-20261111", 70)
    from app.core.config import Settings

    model = Settings(_env_file=None).deepseek_model
    protocol = {
        "scope": (
            "post-hoc conditional repair diagnosis on exposed cases; not independent acceptance"
        ),
        "historical_detection_round": 2,
        "attempt_kind": "one later candidate per correctly detected historical target",
        "runtime_files": detection_fingerprint(),
        "model": model,
        "case_ids": [c["id"] for c in cases],
        "allowance": 70,
    }
    saved = destination / "protocol.json"
    if saved.exists() and json.loads(saved.read_text(encoding="utf-8")) != protocol:
        raise ValueError("Diagnostic configuration changed; refuse mixing candidates")
    write_json(saved, protocol)
    rows = []
    for case in cases:
        sample = case["id"]
        source = original / f"hybrid-2-{sample}"
        job = destination / sample
        if not source.resolve().is_relative_to(
            original.resolve()
        ) or not job.resolve().is_relative_to(destination.resolve()):
            raise ValueError("Invalid synthetic fixture path")
        if not job.exists():
            shutil.copytree(source, job)
        output = job / "posthoc-result.json"
        if output.exists():
            rows.append(json.loads(output.read_text(encoding="utf-8")))
            continue
        row = {
            "sample_id": sample,
            "cwe": case["cwe"],
            "repeat": 1,
            "first_candidate": False,
            "success": False,
            "posthoc": True,
            "historical_repeat": 2,
        }
        if (job / "posthoc-started.json").exists():
            row["error_code"] = "EXPERIMENT_INTERRUPTED"
        else:
            write_json(job / "posthoc-started.json", {"started": True})
            detection = json.loads((source / "detection.json").read_text(encoding="utf-8"))
            targets = [f for f in detection["findings"] if overlaps(records[sample], f)]
            if not targets:
                row["error_code"] = "TARGET_NOT_DETECTED"
            else:
                settings = settings_for(job, True, model)
                app = create_app(settings)
                app.state.engine = build_engine(settings)
                try:
                    with TestClient(app) as api:
                        api.headers["Authorization"] = (
                            "Bearer " + settings.api_token.get_secret_value()
                        )
                        item = request_json(
                            api,
                            "post",
                            "/api/v1/repairs",
                            headers={"Idempotency-Key": str(uuid4())},
                            json={
                                "finding_id": targets[0]["id"],
                                "source_sha256": detection["source_sha256"],
                                "model_alias": "deepseek",
                            },
                        )["repair"]
                        asyncio.run(
                            run_repair_once(
                                app.state.engine, settings, budget.factory("posthoc-" + sample)
                            )
                        )
                        item = request_json(api, "get", f"/api/v1/repairs/{item['id']}")["repair"]
                        row |= {
                            "repair_id": item["id"],
                            "status": item["status"],
                            "error_code": item["error_code"],
                            "validation_status": item["validation_status"],
                            "checks": {
                                k: item["checks"].get(k)
                                for k in (
                                    "syntax",
                                    "patch",
                                    "roundtrip",
                                    "review",
                                    "delta",
                                    "impact",
                                    "contract",
                                    "patch_diagnostic",
                                )
                            },
                            "gates": item["gates"],
                            "calls": item["calls"],
                        }
                        if item["status"] == "candidate":
                            response = api.get(
                                f"/api/v1/repairs/{item['id']}/download?format=source"
                            )
                            response.raise_for_status()
                            key = settings.deepseek_api_key.get_secret_value()
                            if key and key in response.text:
                                raise ValueError("Candidate credential detected")
                            (job / "posthoc-candidate.txt").write_text(
                                response.text, encoding="utf-8", newline="\n"
                            )
                            row["candidate_source"] = response.text
                            row["candidate_sha256"] = hashlib.sha256(
                                response.text.encode()
                            ).hexdigest()
                except Exception as error:
                    row["error_code"] = getattr(error, "code", "EXPERIMENT_INTERNAL")
                finally:
                    app.state.engine.dispose()
        write_json(output, row)
        rows.append(row)
        print(
            json.dumps(
                {
                    "sample_id": sample,
                    "status": row.get("status"),
                    "error_code": row.get("error_code"),
                    "reservations": budget.summary()["reservations"],
                }
            ),
            flush=True,
        )
    result = {
        "protocol": protocol,
        "denominator": 18,
        "rows": rows,
        "budget": budget.summary(),
        "dynamic_pending": True,
        "course_acceptance_evaluated": False,
    }
    write_json(destination / "summary.json", result)
    target = ROOT / "evaluation/results/m6-posthoc-candidates.json"
    if target.exists() and json.loads(target.read_text(encoding="utf-8")) != result:
        raise ValueError("Refuse overwriting existing post-hoc evidence")
    if not target.exists():
        write_json(target, result)
    print(
        json.dumps(
            {
                "outcomes": dict(Counter(r.get("error_code") or r.get("status") for r in rows)),
                "budget": budget.summary(),
            }
        )
    )
    return 0 if len(rows) == 18 else 1


if __name__ == "__main__":
    raise SystemExit(main())
