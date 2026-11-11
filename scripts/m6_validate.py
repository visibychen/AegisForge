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


def candidates(settings, path, baseline):
    from app.validation.registry import load_cases
    from app.validation.runner import run_container

    from evaluation.experiment import file_hash

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
    for repeat in range(1, 4):
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
                checks = row.get("checks", {})
                # Conservatively require both rechecks with no introduced risk of any level.
                deltas = checks.get("delta") or {}
                reviewed = (checks.get("review") or {}).get("status") == "complete"
                no_new = all(
                    not (deltas.get(kind) or {}).get("introduced") for kind in ("rules", "model")
                )
                row["success"] = (
                    valid_controls[sample]
                    and dynamic["status"] == "passed"
                    and all(checks.get(k) == "passed" for k in ("syntax", "patch", "roundtrip"))
                    and reviewed
                    and no_new
                )
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
    return {
        "scope": "all 54 pre-registered first-candidate repair attempts",
        "bundle_sha256": file_hash(path),
        "controls_sha256": file_hash(baseline),
        "denominator": 54,
        "successes": total,
        "by_cwe": by_cwe,
        "rounds": [
            {
                "repeat": i,
                "successes": sum(r["success"] for r in rows if r["repeat"] == i),
                "denominator": 18,
            }
            for i in range(1, 4)
        ],
        "passed": total >= 45 and all(n >= 12 for n in by_cwe.values()),
        "rows": rows,
        "human_review_pending": True,
    }


def main():
    require_conda()
    if os.environ.get("AEGISFORGE_DEEPSEEK_API_KEY"):
        raise SystemExit("Do not provide model credentials to the validation launcher.")
    sys.path[:0] = [str(ROOT), str(ROOT / "backend")]
    from app.core.config import Settings

    from evaluation.experiment import write_json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["controls", "candidates"])
    parser.add_argument("--bundle", type=lambda p: ROOT / p)
    parser.add_argument(
        "--baseline", type=lambda p: ROOT / p, default=ROOT / "data/m6-controls-ci.json"
    )
    parser.add_argument(
        "--output", type=lambda p: ROOT / p, default=ROOT / "data/m6-controls-ci.json"
    )
    args = parser.parse_args()
    settings = Settings(_env_file=None, data_dir=ROOT / "data/m6-validation", model_mode="fake")
    if args.command == "candidates" and args.bundle is None:
        parser.error("--bundle required")
    result = (
        controls(settings)
        if args.command == "controls"
        else candidates(settings, args.bundle, args.baseline)
    )
    write_json(args.output, result)
    print("M6 validation:", "passed" if result["passed"] else "failed")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
