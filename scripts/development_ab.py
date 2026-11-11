"""Paid, scoped post-hoc prompt A/B on a fixed DEVELOPMENT subset, never a new holdout claim.

Both arms use the current real API/worker/decoder and rules; the old arm substitutes only the
trusted prompt renderer from Git commit 41a1b03. Its stored product receipt is still the current
runtime receipt, not a claim to reproduce the entire historical product. No candidate executes.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from types import SimpleNamespace

from _environment import ROOT, model_environment, require_conda


def select_subset(records, families_per_cwe=4):
    """Paired safe/vulnerable source families from EACH CWE, plus all development HTTP."""
    chosen = [r for r in records if r["kind"] == "http"]
    for cwe in ("CWE-79", "CWE-89", "CWE-78"):
        source = [r for r in records if r["kind"] == "source" and r["cwe"] == cwe]
        families = sorted({r["family"] for r in source})[:families_per_cwe]
        chosen.extend(r for r in source if r["family"] in families)
    return sorted(chosen, key=lambda r: r["id"])


def historical_prompt(directory):
    # Fixed trusted project module only. This is never uploaded/model-produced Python.
    content = subprocess.check_output(
        ["git", "show", "41a1b03:backend/app/llm/prompts.py"], cwd=ROOT
    )
    path = directory / "trusted-historical-prompts.py"
    path.write_bytes(content)
    spec = importlib.util.spec_from_file_location("aegisforge_trusted_prompt_1_1", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, hashlib.sha256(content.replace(b"\r\n", b"\n")).hexdigest()


def main():
    require_conda()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-real", action="store_true")
    parser.add_argument("--plan", action="store_true")
    args = parser.parse_args()
    sys.path[:0] = [str(ROOT), str(ROOT / "backend")]
    from app.core.config import Settings
    from app.llm.prompts import PROMPT_VERSION

    from evaluation.budget import ExperimentBudget
    from evaluation.experiment import (
        BUDGET_PATH,
        detection_fingerprint,
        file_hash,
        load_data,
        run_detection,
        write_json,
    )
    from evaluation.metrics import evaluate

    manifest, contents = load_data("dev")
    selected = select_subset(manifest["samples"])
    if args.plan:
        print(
            json.dumps(
                {
                    "samples_per_arm": len(selected),
                    "source": sum(r["kind"] == "source" for r in selected),
                    "http": sum(r["kind"] == "http" for r in selected),
                    "minimum_calls": 2 * len(selected),
                    "shared_scope_allowance": 130,
                    "repair_allowance_reserved": 70,
                    "note": "post-hoc development probe; no independent acceptance claim",
                }
            )
        )
        return 0
    if not args.execute_real:
        parser.error("--execute-real is required")
    os.environ.update(model_environment())
    settings = Settings(_env_file=None, model_mode="real")
    if not settings.valid_model_key:
        parser.error("Configure the model credential in the OS environment")
    budget = ExperimentBudget(BUDGET_PATH, 1000, "postdev-ab-20261111", 130)
    ExperimentBudget(BUDGET_PATH, 1000, "posthoc-repairs-20261111", 70)
    directory = ROOT / "data/m6-postdev-ab"
    directory.mkdir(parents=True, exist_ok=True)
    legacy, legacy_sha = historical_prompt(directory)
    config = {"model": settings.deepseek_model}
    protocol = {
        "scope": "post-hoc developmental comparison; holdout exposed, no independent quality claim",
        "sample_ids": [r["id"] for r in selected],
        "sample_hashes": {
            r["id"]: hashlib.sha256(contents[r["id"]].encode()).hexdigest() for r in selected
        },
        "old_renderer_commit": "41a1b03",
        "old_renderer_sha256": legacy_sha,
        "runtime_prompt": PROMPT_VERSION,
        "runtime_files": detection_fingerprint(),
        "new_renderer_sha256": file_hash(ROOT / "backend/app/llm/prompts.py"),
        "model": settings.deepseek_model,
        "temperature": 0,
        "thinking": "disabled",
        "max_tokens": 4096,
        "seed": None,
        "order": (
            "fixed sample order; alternate old/new submission order per pair; "
            "3 isolated API-worker jobs"
        ),
        "receipt_note": (
            "current API/worker runtime in both arms; old arm overrides renderer "
            "in experimental provider adapter only"
        ),
    }
    saved = directory / "protocol.json"
    if saved.exists() and json.loads(saved.read_text(encoding="utf-8")) != protocol:
        raise ValueError("A/B configuration changed; refuse mixing paid results")
    write_json(saved, protocol)

    def run(record, arm):
        job_name = f"ab-{arm}-{record['id']}"

        def factory(runtime, local):
            provider = budget.factory(job_name)(runtime, local)
            if arm == "new":
                return provider

            async def analyze(request):
                def render(req, correction, detail=None):
                    return legacy.messages(req, correction)

                return await provider._run(request, render=render)

            return SimpleNamespace(analyze=analyze)

        row = run_detection(
            directory / arm,
            config,
            budget,
            record,
            contents[record["id"]],
            "hybrid",
            1,
            provider_factory=factory,
        )
        return arm, row

    schedule = [
        (record, arm)
        for index, record in enumerate(selected)
        for arm in (("old", "new") if index % 2 == 0 else ("new", "old"))
    ]
    arms = {"old": [], "new": []}
    with ThreadPoolExecutor(max_workers=3) as pool:
        work = [pool.submit(run, record, arm) for record, arm in schedule]
        for i, future in enumerate(as_completed(work), 1):
            arm, row = future.result()
            arms[arm].append(row)
            print(
                json.dumps(
                    {
                        "done": i,
                        "scheduled": len(schedule),
                        "arm": arm,
                        "sample_id": row["sample_id"],
                        "status": row.get("status"),
                        "reserved": budget.summary()["reservations"],
                    }
                ),
                flush=True,
            )
    summaries = {}
    for arm, rows in arms.items():
        calls = [c for r in rows for c in r.get("calls", [])]
        summaries[arm] = {
            "scheduled": len(selected),
            "recorded": len(rows),
            "complete_model_tasks": sum(bool(r.get("analysis_complete")) for r in rows),
            "model_calls": len(calls),
            "call_outcomes": dict(Counter(c.get("failure_category") or c["status"] for c in calls)),
            **evaluate(selected, rows),
            "records": sorted(rows, key=lambda r: r["sample_id"]),
        }
    report = {
        "protocol": protocol,
        "arms": summaries,
        "budget": budget.summary(),
        "source_labels_human_review": manifest["provenance"]["human_review"],
        "limitations": (
            "Fixed synthetic development subset, one run per arm and mixed current runtime/"
            "historical renderer; not an independent benchmark or causal proof about "
            "individual changes."
        ),
    }
    write_json(directory / "summary.json", report)
    target = ROOT / "evaluation/results/m6-postdev-ab.json"
    if target.exists() and json.loads(target.read_text(encoding="utf-8")) != report:
        raise ValueError("Refuse replacing development A/B evidence")
    if not target.exists():
        write_json(target, report)
    print(
        json.dumps(
            {
                arm: {k: v for k, v in data.items() if k not in {"records", "errors", "metrics"}}
                for arm, data in summaries.items()
            }
        )
    )
    return 0 if all(a["recorded"] == a["scheduled"] for a in summaries.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
