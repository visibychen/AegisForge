"""One predeclared, exposed-case diagnostic inside the ORIGINAL remaining M6 allowance.

No model request is sent without --execute-real. No source/candidate is executed here.
24 fresh hybrid tasks (12 registered vulnerable cases and their safe pairs), then one candidate
per vulnerable case in this new run, including every failed/missing target in the denominator.
This is neither a new independent holdout nor the PLAN's three-round course acceptance.
"""

import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime

from _environment import ROOT, model_environment, require_conda

SELECTED = (
    "SRC-XSS-09-V",
    "SRC-XSS-14-V",
    "SRC-XSS-17-V",
    "SRC-SQLI-09-V",
    "SRC-SQLI-10-V",
    "SRC-SQLI-12-V",
    "SRC-SQLI-14-V",
    "SRC-SQLI-17-V",
    "SRC-SQLI-19-V",
    "SRC-CMDI-09-V",
    "SRC-CMDI-14-V",
    "SRC-CMDI-20-V",
)
RUN = ROOT / "data/m6-targeted-20261112"


def main():
    require_conda()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-real", action="store_true")
    args = parser.parse_args()
    sys.path[:0] = [str(ROOT), str(ROOT / "backend")]
    from evaluation.experiment import (
        BUDGET_PATH,
        detection_fingerprint,
        file_hash,
        generate_repairs,
        job_directory,
        load_data,
        run_detection,
        write_json,
    )
    from evaluation.metrics import evaluate

    manifest, contents = load_data()
    ids = [ident[:-1] + label for ident in SELECTED for label in ("V", "S")]
    records = {r["id"]: r for r in manifest["samples"]}
    selected = [records[ident] for ident in ids]
    protocol = {
        "schema_version": "m6-targeted-1.0",
        "scope": "post-hoc exposed-case targeted diagnostic; not independent acceptance",
        "course_acceptance_evaluated": False,
        "human_review": "pending",
        "sample_ids": ids,
        "case_ids": list(SELECTED),
        "selection_reason": (
            "all six registered SQLi contracts; XSS script-data/HTML boundaries; "
            "command quoting, guarded host and cwd failures identified in the old run"
        ),
        "rounds": 1,
        "detection_tasks": 24,
        "repair_denominator": 12,
        "first_candidate": "first in this new versioned diagnostic only; cases previously exposed",
        "maximum_additional_reservations": 58,
        "global_ceiling": 1000,
        "starting_reservations": 942,
        "minimum_calls_if_all_targets_found": 48,
        "runtime_files": detection_fingerprint(),
        "orchestrator_files": {
            name: file_hash(ROOT / name)
            for name in (
                "scripts/m6_targeted.py",
                "evaluation/experiment.py",
                "evaluation/budget.py",
            )
        },
        "dataset_sha256": file_hash(ROOT / "samples/freeze.json"),
        "sample_hashes": {
            ident: hashlib.sha256(contents[ident].encode()).hexdigest() for ident in ids
        },
    }
    if not args.execute_real:
        print(json.dumps(protocol, ensure_ascii=False, indent=2))
        return 0
    os.environ.update(model_environment())
    from app.core.config import Settings

    from evaluation.budget import BudgetPool, ExperimentBudget

    settings = Settings(_env_file=None)
    if not settings.deepseek_api_key or not settings.deepseek_api_key.get_secret_value():
        raise ValueError("A model key in the OS environment is required")
    protocol |= {"model": settings.deepseek_model, "temperature": 0, "thinking": "disabled"}
    saved = RUN / "protocol.json"
    if saved.exists():
        previous = json.loads(saved.read_text(encoding="utf-8"))
        if any(previous.get(k) != v for k, v in protocol.items()):
            raise ValueError("Code/data/config changed; refuse mixing paid results")
        protocol = previous
    else:
        if not BUDGET_PATH.is_file():
            raise ValueError("The original budget ledger must already exist")
        original = ExperimentBudget(BUDGET_PATH)
        if original.summary()["reservations"] != 942:
            raise ValueError("Expected the original 942 used reservations before first start")
        RUN.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(BUDGET_PATH)) as source:
            with closing(sqlite3.connect(RUN / "budget-before.sqlite")) as backup:
                source.backup(backup)
        protocol |= {
            "created_at": datetime.now(UTC).isoformat(),
            "code_sha": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
            ).strip(),
        }
        write_json(saved, protocol)
    # 19 + 34 old unspent reservations plus the only 5 unallocated reservations.
    # Scope sizes and the global ceiling are preserved, including after a restart.
    budget = BudgetPool(
        [
            ExperimentBudget(BUDGET_PATH, 1000, "postdev-ab-20261111", 130),
            ExperimentBudget(BUDGET_PATH, 1000, "posthoc-repairs-20261111", 70),
            ExperimentBudget(BUDGET_PATH, 1000, "targeted-20261112", 5),
        ]
    )
    config = {"model": settings.deepseek_model, "rounds": 1, "split": "test"}

    def detect(record):
        row = run_detection(RUN, config, budget, record, contents[record["id"]], "hybrid", 1)
        print(
            json.dumps(
                {
                    "sample": record["id"],
                    "status": row.get("status"),
                    "error_code": row.get("error_code"),
                    "reservations": budget.summary()["reservations"],
                }
            ),
            flush=True,
        )
        return row

    with ThreadPoolExecutor(max_workers=2) as workers:
        detections = list(workers.map(detect, selected))
    detection = {
        "protocol": protocol,
        "records": detections,
        "evaluation": evaluate(selected, detections),
        "budget": budget.summary(),
        "course_acceptance_evaluated": False,
    }
    write_json(RUN / "detection-summary.json", detection)
    rows = generate_repairs(RUN, config, budget, selected=SELECTED)
    candidates = []
    for row in rows:
        row = dict(row)
        path = job_directory(RUN, "hybrid", 1, row["sample_id"]) / "candidate.txt"
        if row.get("status") == "candidate":
            source = path.read_text(encoding="utf-8")
            if hashlib.sha256(source.encode()).hexdigest() != row["candidate_sha256"]:
                raise ValueError("Candidate binding mismatch")
            row["candidate_source"] = source
        candidates.append(row)
    bundle = {
        "protocol": protocol,
        "denominator": 12,
        "rows": candidates,
        "budget": budget.summary(),
        "dynamic_pending": True,
        "course_acceptance_evaluated": False,
    }
    write_json(RUN / "candidates.json", bundle)
    print(
        json.dumps(
            {
                "detection": detection["evaluation"]["metrics"]["source"]["micro"],
                "candidates": sum(r.get("status") == "candidate" for r in rows),
                "budget": budget.summary(),
            },
            ensure_ascii=False,
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
