"""PLAN 7.3/7.4: dry-run, frozen detection and first-candidate repair experiments."""

import argparse
import json
import os
import re
import sys

from _environment import ROOT, model_environment, require_conda


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
    parser.add_argument("command", choices=["plan", "detect", "repairs", "summary"])
    parser.add_argument("--run", default="baseline-2026-11-11")
    parser.add_argument("--split", choices=["test", "dev"], default="test")
    parser.add_argument("--rounds", type=int, choices=[3], default=3)
    parser.add_argument("--workers", type=int, choices=[1, 2, 3], default=3)
    parser.add_argument("--max-calls", type=int, default=1000)
    parser.add_argument(
        "--execute-real",
        action="store_true",
        help="explicitly authorize paid calls; hard ceiling includes all retries",
    )
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,70}", args.run):
        parser.error("Invalid run name")
    if args.command == "plan":
        print(json.dumps(plan(args.split, args.rounds), ensure_ascii=False, indent=2))
        return 0
    if args.command == "repairs" and not args.execute_real:
        parser.error("repairs requires --execute-real")
    if args.execute_real:
        os.environ.update(model_environment())
        from app.core.config import Settings

        if not Settings(_env_file=None).valid_model_key:
            parser.error("Configure the OS model credential first; it is never read from dotenv")
    directory, config = prepare(args.run, args.split, args.rounds, args.workers, args.max_calls)
    budget = ExperimentBudget(BUDGET_PATH, args.max_calls)
    if args.command == "detect":
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
