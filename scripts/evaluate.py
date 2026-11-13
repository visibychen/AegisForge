"""PLAN 7.3/7.4: dry-run, frozen detection and first-candidate repair experiments.

``dev-ab`` is a small post-hoc diagnostic on a balanced subset of the DEVELOPMENT split (never the
frozen holdout). It always runs under a named sub-allowance of the one persistent ledger.
"""

import argparse
import json
import os
import re
import sys
from collections import Counter

from _environment import ROOT, model_environment, require_conda


def dev_ab(directory, config, budget, strategy, per_group):
    """Run one balanced development subset and summarise it. Resumable: finished jobs are reused."""
    from evaluation.experiment import load_data, run_detection, write_json
    from evaluation.metrics import evaluate

    manifest, contents = load_data("dev")
    groups: dict = {}
    for record in sorted(manifest["samples"], key=lambda r: r["id"]):
        groups.setdefault((record["kind"], record["cwe"], record["label"]), []).append(record)
    subset = [record for items in groups.values() for record in items[:per_group]]
    rows = []
    for record in subset:
        if budget.remaining() == 0:
            print(json.dumps({"stopped": "sub-allowance exhausted", "done": len(rows)}))
            break
        text = contents[record["id"]]
        rows.append(run_detection(directory, config, budget, record, text, strategy, 1))
        print(json.dumps({"sample": record["id"], "status": rows[-1].get("status")}), flush=True)
    done = {r["sample_id"] for r in rows}
    scored = [r for r in subset if r["id"] in done]
    calls = [call for row in rows for call in row.get("calls", [])]
    categories = Counter(call.get("failure_category") or call.get("status") for call in calls)
    summary = {
        "schema_version": "m6-dev-ab-1.0",
        "kind": "post-hoc development diagnostic; not a baseline and not independent evidence",
        "strategy": strategy,
        "samples": len(subset),
        "completed": len(scored),
        "calls": len(calls),
        "call_outcomes": dict(categories),
        "task_failures": sum(not r.get("analysis_complete") for r in rows),
        "metrics": evaluate(subset, rows)["metrics"],
        "scheduled_sample_ids": [r["id"] for r in subset],
        "note": "Missing scheduled rows remain in the metric denominator.",
        "budget": budget.summary(),
    }
    write_json(directory / "dev-ab-summary.json", summary)
    return summary


def main():
    require_conda()
    sys.path[:0] = [str(ROOT), str(ROOT / "backend")]
    from evaluation.budget import ExperimentBudget
    from evaluation.experiment import (
        BUDGET_PATH,
        detect,
        generate_repairs,
        plan,
        prepare,
        summarize,
    )

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["plan", "detect", "repairs", "summary", "dev-ab"])
    parser.add_argument("--run", default="baseline-2026-11-11")
    parser.add_argument("--split", choices=["test", "dev"], default="test")
    parser.add_argument("--rounds", type=int, choices=[3], default=3)
    parser.add_argument("--workers", type=int, choices=[1, 2, 3], default=3)
    parser.add_argument("--max-calls", type=int, default=1000)
    parser.add_argument("--scope", help="named sub-allowance inside the persistent global ledger")
    parser.add_argument("--allowance", type=int, help="calls reserved for --scope (>= 1)")
    parser.add_argument("--strategy", choices=["llm", "hybrid"], default="hybrid")
    parser.add_argument("--per-group", type=int, default=4, help="dev-ab samples per group")
    parser.add_argument(
        "--execute-real",
        action="store_true",
        help="explicitly authorize paid calls; hard ceiling includes all retries",
    )
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,70}", args.run):
        parser.error("Invalid run name")
    if (args.scope is None) != (args.allowance is None):
        parser.error("--scope and --allowance go together")
    if args.command == "dev-ab" and (args.split != "dev" or not args.scope):
        parser.error("dev-ab needs --split dev and a --scope/--allowance sub-allowance")
    if args.command == "plan":
        print(json.dumps(plan(args.split, args.rounds), ensure_ascii=False, indent=2))
        return 0
    if args.command in {"repairs", "dev-ab"} and not args.execute_real:
        parser.error(f"{args.command} requires --execute-real")
    if args.execute_real:
        os.environ.update(model_environment())
        from app.core.config import Settings

        if not Settings(_env_file=None).valid_model_key:
            parser.error("Configure the OS model credential first; it is never read from dotenv")
    directory, config = prepare(args.run, args.split, args.rounds, args.workers, args.max_calls)
    budget = ExperimentBudget(BUDGET_PATH, args.max_calls, args.scope, args.allowance)
    if args.command == "dev-ab":
        result = dev_ab(directory, config, budget, args.strategy, args.per_group)
        print(json.dumps({k: v for k, v in result.items() if k != "metrics"}, ensure_ascii=False))
    elif args.command == "detect":
        result = detect(directory, config, budget, real=args.execute_real)
        print(
            json.dumps(
                {
                    "hybrid_threshold": {
                        k: v for k, v in result["hybrid_threshold"].items() if k != "rounds"
                    },
                    "budget": result["budget"],
                },
                ensure_ascii=False,
            )
        )
    elif args.command == "repairs":
        generate_repairs(directory, config, budget)
    else:
        result = summarize(directory, config, budget)
        print(
            json.dumps(
                {
                    "hybrid_threshold": {
                        k: v for k, v in result["hybrid_threshold"].items() if k != "rounds"
                    },
                    "budget": result["budget"],
                },
                ensure_ascii=False,
            )
        )
    print("Results:", directory.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
