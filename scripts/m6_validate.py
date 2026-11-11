"""Credential-free Docker-only controls and all 54 first-candidate M6 observations."""

import argparse
import hashlib
import json
import os
import sys

from _environment import ROOT, require_conda


def controls(settings):
    from app.validation.registry import load_cases
    from app.validation.runner import run_container

    from evaluation.experiment import load_data

    _, contents = load_data()
    rows = []
    for case in load_cases(include_holdout=True):
        if not case["id"].startswith("h-"):
            continue
        for label in ("V", "S"):
            source = contents[case["sample_id"][:-1] + label]
            result = run_container(settings, source, case)
            tests = {t["name"]: t["passed"] for t in result.get("tests", [])}
            accepted = (
                result["status"] == "passed"
                if label == "S"
                else result["status"] == "failed"
                and tests.get("business_primary") is True
                and tests.get("security_regression") is False
            )
            row = {
                "sample_id": case["sample_id"],
                "cwe": {"xss": "CWE-79", "sqli": "CWE-89", "cmdi": "CWE-78"}[
                    case["id"].split("-")[1]
                ],
                "control": label,
                "accepted": accepted,
                **result,
            }
            rows.append(row)
            print(
                json.dumps(
                    {
                        k: row.get(k)
                        for k in (
                            "sample_id",
                            "control",
                            "status",
                            "accepted",
                            "error_code",
                            "tests",
                        )
                    }
                ),
                flush=True,
            )
    return {
        "scope": "18 frozen original and AI reference controls; human review pending",
        "passed": len(rows) == 36 and all(r["accepted"] for r in rows),
        "rows": rows,
    }


def candidates(settings, path, baseline, *, posthoc=False):
    from app.validation.registry import load_cases
    from app.validation.runner import run_container

    from evaluation.experiment import file_hash
    from evaluation.gate import candidate_success

    bundle = json.loads(path.read_text(encoding="utf-8"))
    baseline_result = json.loads(baseline.read_text(encoding="utf-8"))
    cases = {
        c["sample_id"]: c for c in load_cases(include_holdout=True) if c["id"].startswith("h-")
    }
    valid_controls = {
        sample: all(
            row["accepted"] for row in baseline_result["rows"] if row["sample_id"] == sample
        )
        and sum(row["sample_id"] == sample for row in baseline_result["rows"]) == 2
        for sample in cases
    }
    inputs = {(row["sample_id"], row["repeat"]): row for row in bundle["rows"]}
    if len(inputs) != len(bundle["rows"]):
        raise ValueError("Duplicate candidate identity")
    rows = []
    repeats = (1,) if posthoc else (1, 2, 3)
    denominator = 18 * len(repeats)
    for repeat in repeats:
        for sample, case in cases.items():
            row = dict(
                inputs.get(
                    (sample, repeat),
                    {"sample_id": sample, "repeat": repeat, "error_code": "CANDIDATE_MISSING"},
                )
            )
            source = row.pop("candidate_source", None)
            row["baseline_accepted"] = valid_controls[sample]
            row["success"] = False
            if source is not None:
                if (
                    not isinstance(source, str)
                    or len(source) > 24000
                    or hashlib.sha256(source.encode()).hexdigest() != row.get("candidate_sha256")
                ):
                    raise ValueError("Invalid candidate binding/size")
                dynamic = run_container(settings, source, case)
                row["dynamic"] = dynamic
                # One shared definition (evaluation/gate.py) for the run and the independent audit.
                row["success"] = candidate_success(row, valid_controls[sample])
            rows.append(row)
            print(
                json.dumps(
                    {
                        "sample_id": sample,
                        "repeat": repeat,
                        "success": row["success"],
                        "dynamic": (row.get("dynamic") or {}).get("status"),
                        "error_code": row.get("error_code"),
                    }
                ),
                flush=True,
            )
    by_cwe = {
        cwe: sum(r["success"] for r in rows if r.get("cwe") == cwe)
        for cwe in ("CWE-79", "CWE-89", "CWE-78")
    }
    total = sum(r["success"] for r in rows)
    # Two different questions. "Complete": all 54 attempts are present and every candidate that
    # exists reached a real passed/failed dynamic verdict (no missing bundle row, no environment
    # error). "Passed": the numeric course threshold. A complete run may still not pass.
    environment_errors = [
        r
        for r in rows
        if r.get("dynamic") and r["dynamic"].get("status") not in {"passed", "failed"}
    ]
    missing = [r for r in rows if r.get("error_code") == "CANDIDATE_MISSING"]
    return {
        "scope": (
            "post-hoc conditional repair diagnosis; not independent acceptance"
            if posthoc
            else "all 54 pre-registered first-candidate repair attempts"
        ),
        "course_acceptance_evaluated": not posthoc,
        "execution_complete": len(rows) == denominator and not environment_errors and not missing,
        "environment_errors": len(environment_errors),
        "missing_candidates": len(missing),
        "bundle_sha256": file_hash(path),
        "controls_sha256": file_hash(baseline),
        "denominator": denominator,
        "successes": total,
        "by_cwe": by_cwe,
        "rounds": [
            {
                "repeat": i,
                "successes": sum(r["success"] for r in rows if r["repeat"] == i),
                "denominator": 18,
            }
            for i in repeats
        ],
        "passed": None if posthoc else total >= 45 and all(n >= 12 for n in by_cwe.values()),
        "rows": rows,
        "human_review_pending": True,
    }


def verdicts(result):
    """Per attempt: the dynamic verdict and each fixed test outcome (no timings or run ids)."""
    return {
        (r.get("sample_id"), r.get("repeat")): (
            r.get("success"),
            (r.get("dynamic") or {}).get("status"),
            sorted((t["name"], t["passed"]) for t in (r.get("dynamic") or {}).get("tests", [])),
        )
        for r in result.get("rows", [])
    }


def main():
    require_conda()
    if os.environ.get("AEGISFORGE_DEEPSEEK_API_KEY"):
        raise SystemExit("Do not provide model credentials to the validation launcher.")
    sys.path[:0] = [str(ROOT), str(ROOT / "backend")]
    from app.core.config import Settings

    from evaluation.experiment import write_json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["controls", "candidates", "diagnostics"])
    parser.add_argument("--bundle", type=lambda p: ROOT / p)
    parser.add_argument(
        "--compare",
        type=lambda p: ROOT / p,
        help="committed result to replay against; any changed verdict exits 3",
    )
    parser.add_argument(
        "--require-threshold",
        action="store_true",
        help="exit 1 when the numeric repair threshold is not met (strict acceptance)",
    )
    parser.add_argument(
        "--baseline", type=lambda p: ROOT / p, default=ROOT / "data/m6-controls-ci.json"
    )
    parser.add_argument(
        "--output", type=lambda p: ROOT / p, default=ROOT / "data/m6-controls-ci.json"
    )
    args = parser.parse_args()
    settings = Settings(_env_file=None, data_dir=ROOT / "data/m6-validation", model_mode="fake")
    if args.command in {"candidates", "diagnostics"} and args.bundle is None:
        parser.error("--bundle required")
    if args.command == "diagnostics" and args.require_threshold:
        parser.error("Post-hoc diagnostics cannot evaluate the formal course threshold")
    result = (
        controls(settings)
        if args.command == "controls"
        else candidates(settings, args.bundle, args.baseline, posthoc=args.command == "diagnostics")
    )
    write_json(args.output, result)
    print(
        "M6 validation:",
        "not evaluated (post-hoc)"
        if args.command == "diagnostics"
        else "passed"
        if result["passed"]
        else "failed",
    )
    if args.command == "controls":
        return 0 if result["passed"] else 1
    # Execution (2), replay drift (3), numeric threshold (1): separate verdicts.
    if not result["execution_complete"]:
        print("Execution incomplete: missing candidate rows or a Docker/environment error.")
        return 2
    if args.compare:
        committed = json.loads(args.compare.read_text(encoding="utf-8"))
        if verdicts(committed) != verdicts(result):
            print("Replay differs from the committed record.")
            return 3
        print("Replay equals the committed record.")
    if args.command == "diagnostics":
        print("Diagnostic execution complete; this does not evaluate course acceptance.")
        return 0
    if not result["passed"]:
        print("Execution complete; the numeric repair threshold is NOT met.")
    return 1 if args.require_threshold and not result["passed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
