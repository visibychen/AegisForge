"""Zero-model-call, Docker-only review-v1 controls, partial-fix probes and all 18 later attempts."""

import argparse
import hashlib
import os
import sys

from _environment import ROOT, require_conda


def partial_fixes(contents):
    xss = contents["SRC-XSS-14-V"]
    needle = 'query = request.args.get("q", "")'
    if xss.count(needle) != 1:
        raise ValueError("Fixed XSS probe no longer matches its synthetic fixture")
    xss = xss.replace(needle, needle + '.replace("\'", "\\\\\'")')
    sql = contents["SRC-SQLI-12-S"]
    needle = '("display_name", "email", "timezone")'
    if sql.count(needle) != 1:
        raise ValueError("Fixed SQL probe no longer matches its synthetic fixture")
    sql = sql.replace(needle, '("display_name",)')
    command = """import subprocess
from flask import Flask, request
app = Flask(__name__)
@app.post("/backup")
def backup():
    database = request.form["database"]
    result = subprocess.run(["pg_dump", database], shell=False)
    return {"status": result.returncode}
"""
    return {"SRC-XSS-14-V": xss, "SRC-SQLI-12-V": sql, "SRC-CMDI-09-V": command}


def main():
    require_conda()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="data/m6-review-validation-ci.json")
    args = parser.parse_args()
    if os.environ.get("AEGISFORGE_DEEPSEEK_API_KEY"):
        parser.error("Model credentials must not enter the validation launcher")
    sys.path[:0] = [str(ROOT), str(ROOT / "backend")]
    from app.core.config import Settings
    from app.validation.registry import review_validator_fingerprint
    from app.validation.runner import run_container

    from evaluation.experiment import file_hash, load_data, write_json
    from evaluation.review_validation import (
        LEGACY_TESTS,
        PROTOCOL,
        cases,
        outcomes,
        selected_candidates,
        source_bound,
        success,
    )

    settings = Settings(
        _env_file=None, model_mode="fake", data_dir=ROOT / "data/m6-review-validation"
    )
    _, contents = load_data()
    scheduled, selected = cases(), selected_candidates()
    controls, valid = [], {}
    for sample, case in scheduled.items():
        accepted = []
        for label in ("V", "S"):
            source = contents[sample[:-1] + label]
            dynamic = run_container(settings, source, case, profile="review-v1")
            observed = outcomes(dynamic, case["tests"])
            ok = bool(
                observed
                and (
                    all(observed.values())
                    if label == "S"
                    else observed["business_primary"] and not observed["security_regression"]
                )
            )
            controls.append(
                {
                    "sample_id": sample,
                    "control": label,
                    "accepted": ok,
                    "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                    "dynamic": dynamic,
                }
            )
            accepted.append(ok)
            print(f"Control {sample} {label}: {ok}", flush=True)
        valid[sample] = all(accepted)
    negatives = []
    for sample, source in partial_fixes(contents).items():
        case = scheduled[sample]
        legacy = run_container(settings, source, {**case, "tests": LEGACY_TESTS})
        review = run_container(settings, source, case, profile="review-v1")
        a, b = outcomes(legacy, LEGACY_TESTS), outcomes(review, case["tests"])
        ok = bool(
            a and all(a.values()) and b and not all(b.values()) and all(b[n] for n in LEGACY_TESTS)
        )
        negatives.append(
            {
                "sample_id": sample,
                "candidate_sha256": hashlib.sha256(source.encode()).hexdigest(),
                "legacy": legacy,
                "review": review,
                "accepted": ok,
            }
        )
        print(f"Partial-fix probe {sample}: {ok}", flush=True)
    rows = []
    for sample, case in scheduled.items():
        selection = selected[sample]
        attempt = selection["attempt"]
        dynamic = {"status": "not_generated", "tests": []}
        if attempt.get("candidate_source") is not None:
            if not source_bound(attempt):
                raise ValueError("Candidate source binding differs")
            dynamic = run_container(
                settings, attempt["candidate_source"], case, profile="review-v1"
            )
        passed = success(attempt, dynamic, valid[sample], case)
        rows.append(
            {
                "sample_id": sample,
                "cwe": case["cwe"],
                "origin_file": selection["origin_file"],
                "origin_index": selection["origin_index"],
                "candidate_sha256": attempt.get("candidate_sha256"),
                "dynamic": dynamic,
                "success": passed,
            }
        )
        print(f"Latest attempt {sample}: {passed}", flush=True)
    result = {
        "schema_version": "m6-review-validation-1.0",
        "scope": "post-hoc latest scheduled attempts",
        "course_acceptance_evaluated": False,
        "model_calls": 0,
        "protocol_sha256": file_hash(PROTOCOL),
        "validator_fingerprint": review_validator_fingerprint(),
        "origin_files": {
            relative: file_hash(ROOT / relative)
            for relative in {s["origin_file"] for s in selected.values()}
        },
        "controls": controls,
        "negative_controls": negatives,
        "rows": rows,
        "denominator": 18,
        "successes": sum(r["success"] for r in rows),
        "by_cwe": {
            c: sum(r["success"] for r in rows if r["cwe"] == c)
            for c in ("CWE-79", "CWE-89", "CWE-78")
        },
        "controls_accepted": all(c["accepted"] for c in controls),
        "negative_controls_accepted": all(c["accepted"] for c in negatives),
        "ci": {"run_id": os.environ.get("GITHUB_RUN_ID"), "code_sha": os.environ.get("GITHUB_SHA")},
    }
    write_json(ROOT / args.output, result)
    complete = all(r["dynamic"]["status"] in {"passed", "failed", "not_generated"} for r in rows)
    print(
        {
            k: result[k]
            for k in ("successes", "by_cwe", "controls_accepted", "negative_controls_accepted")
        }
    )
    return (
        0
        if complete and result["controls_accepted"] and result["negative_controls_accepted"]
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())
