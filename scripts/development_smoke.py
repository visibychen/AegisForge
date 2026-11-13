"""One scoped post-hoc regression on residual development false alarms and recall guards."""

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor

from _environment import ROOT, model_environment, require_conda


def select(records):
    safe = {"SRC-XSS-03-S", "SRC-XSS-04-S", "SRC-CMDI-04-S"}
    targets = safe | {s[:-1] + "V" for s in safe}
    for cwe in ("CWE-79", "CWE-89", "CWE-78"):
        guards = sorted(
            r["id"]
            for r in records
            if r["kind"] == "source"
            and r["cwe"] == cwe
            and r["label"] == "vulnerable"
            and r["id"] not in targets
        )
        targets.update(guards[:2])
    result = sorted((r for r in records if r["id"] in targets), key=lambda r: r["id"])
    if len(result) != 12:
        raise ValueError("Development regression schedule changed")
    return result


def main():
    require_conda()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-real", action="store_true")
    args = parser.parse_args()
    if not args.execute_real:
        parser.error("--execute-real required")
    sys.path[:0] = [str(ROOT), str(ROOT / "backend")]
    os.environ.update(model_environment())
    from app.core.config import Settings
    from app.llm.prompts import PROMPT_VERSION

    from evaluation.budget import ExperimentBudget
    from evaluation.experiment import (
        BUDGET_PATH,
        detection_fingerprint,
        load_data,
        run_detection,
        write_json,
    )
    from evaluation.metrics import evaluate

    manifest, contents = load_data("dev")
    selected = select(manifest["samples"])
    budget = ExperimentBudget(BUDGET_PATH, 1000, "postdev-ab-20261111", 130)
    directory = ROOT / "data/m6-postdev-final"
    config = {"model": Settings(_env_file=None).deepseek_model}
    protocol = {
        "scope": "post-hoc targeted DEVELOPMENT regression, not independent acceptance",
        "sample_ids": [r["id"] for r in selected],
        "selection": "three residual safe false alarms, their V pairs, two extra V guards per CWE",
        "prompt": PROMPT_VERSION,
        "runtime_files": detection_fingerprint(),
        "model": config["model"],
        "temperature": 0,
        "max_tokens": 4096,
        "scope_allowance": 130,
        "global_ceiling": 1000,
    }
    saved = directory / "protocol.json"
    if saved.exists() and json.loads(saved.read_text(encoding="utf-8")) != protocol:
        raise ValueError("Refuse mixing development regression configurations")
    write_json(saved, protocol)

    def run(record):
        return run_detection(directory, config, budget, record, contents[record["id"]], "hybrid", 1)

    with ThreadPoolExecutor(max_workers=3) as pool:
        rows = list(pool.map(run, selected))
    result = {
        "protocol": protocol,
        "scheduled": len(selected),
        "records": rows,
        "budget": budget.summary(),
        **evaluate(selected, rows),
        "limitations": (
            "Outcome-selected synthetic development regression; one run, no holdout claim"
        ),
    }
    target = ROOT / "evaluation/results/m6-postdev-final.json"
    if target.exists() and json.loads(target.read_text(encoding="utf-8")) != result:
        raise ValueError("Refuse replacing development evidence")
    if not target.exists():
        write_json(target, result)
    print(json.dumps({"metrics": result["metrics"], "budget": result["budget"]}))
    return 0 if all(r.get("analysis_complete") for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
