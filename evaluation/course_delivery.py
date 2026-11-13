"""Explicit course-delivery closure. Numeric research targets remain reported, not mandatory.

No legacy record or scoring method changes. The gate checks complete evidence and actual
functional/negative-control observations; it never executes a source or calls a model.
"""

import hashlib
import re
import subprocess
from collections import Counter

from evaluation.experiment import detection_fingerprint, load_data, plan
from evaluation.gate import ROOT, canon, file_hash, read_json, verify_all
from evaluation.metrics import CWES, evaluate
from evaluation.review_validation import (
    LEGACY_TESTS,
    PROTOCOL,
    cases,
    outcomes,
    selected_candidates,
    source_bound,
    success,
)

MANIFEST = ROOT / "evaluation/manifests/m6-course-delivery-v1.json"
CI_SCOPE = (
    "backend/app",
    "frontend/src",
    "frontend/tests",
    "deploy/validator",
    "deploy/review-validator",
    "scripts/build_validator.py",
    "scripts/m6_review_validate.py",
    "scripts/ci_workbench.py",
    "environment.yml",
    "backend/requirements.lock",
    "backend/requirements-dev.lock",
    "frontend/package-lock.json",
)


def validate_ci_code(ci):
    files = (
        subprocess.check_output(
            ["git", "ls-files", "-z", "--", *CI_SCOPE],
            cwd=ROOT,
        )
        .decode("utf-8")
        .strip("\0")
        .split("\0")
    )
    if set(ci["code_files"]) != set(files):
        raise ValueError("CI product/controller file inventory differs")
    for relative, digest in ci["code_files"].items():
        path = ROOT / relative
        if (
            not path.resolve().is_relative_to(ROOT.resolve())
            or ".." in relative.split("/")
            or file_hash(path) != digest
        ):
            raise ValueError("Code changed after the recorded CI")
    return True


def validate_review(data):
    """Recompute all counts/flags from the fixed sources, schedule and bound test outcomes."""
    from app.validation.registry import review_validator_fingerprint, validator_fingerprint

    from scripts.m6_review_validate import partial_fixes

    scheduled, selected = cases(), selected_candidates()
    _, contents = load_data()
    expected_fp = review_validator_fingerprint()
    if (
        data["schema_version"] != "m6-review-validation-1.0"
        or data["protocol_sha256"] != file_hash(PROTOCOL)
        or data["validator_fingerprint"] != expected_fp
        or type(data["model_calls"]) is not int
        or data["model_calls"] != 0
    ):
        raise ValueError("Review protocol binding differs")
    files = {row["origin_file"] for row in selected.values()}
    if data["origin_files"] != {p: file_hash(ROOT / p) for p in files}:
        raise ValueError("Selected input files differ")
    run_ids = set()

    def bound(dynamic, source_hash, case, *, legacy=False):
        names = LEGACY_TESTS if legacy else case["tests"]
        result = outcomes(dynamic, names)
        ident = dynamic.get("run_id")
        if (
            result is None
            or dynamic.get("case_id") != case["id"]
            or dynamic.get("candidate_sha256") != source_hash
            or dynamic.get("harness_sha256") != (validator_fingerprint() if legacy else expected_fp)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", dynamic.get("image_id", ""))
            or not isinstance(ident, str)
            or not re.fullmatch(r"[0-9a-f]{32}", ident)
            or ident in run_ids
        ):
            raise ValueError("Unbound or copied container observation")
        run_ids.add(ident)
        return result

    controls = data["controls"]
    expected = {(sample, label) for sample in scheduled for label in ("V", "S")}
    if len(controls) != 36 or {(r["sample_id"], r["control"]) for r in controls} != expected:
        raise ValueError("Control denominator differs")
    valid = {sample: True for sample in scheduled}
    for row in controls:
        sample, label = row["sample_id"], row["control"]
        digest = hashlib.sha256(contents[sample[:-1] + label].encode()).hexdigest()
        observed = bound(row["dynamic"], digest, scheduled[sample])
        accepted = (
            all(observed.values())
            if label == "S"
            else observed["business_primary"] and not observed["security_regression"]
        )
        if row["source_sha256"] != digest or row["accepted"] is not accepted:
            raise ValueError("Control summary differs")
        valid[sample] &= accepted
    negatives = data["negative_controls"]
    probes = partial_fixes(contents)
    if len(negatives) != 3 or {r["sample_id"] for r in negatives} != set(probes):
        raise ValueError("Negative-control denominator differs")
    negative_ok = True
    for row in negatives:
        sample = row["sample_id"]
        digest = hashlib.sha256(probes[sample].encode()).hexdigest()
        a = bound(row["legacy"], digest, scheduled[sample], legacy=True)
        b = bound(row["review"], digest, scheduled[sample])
        accepted = all(a.values()) and not all(b.values()) and all(b[n] for n in LEGACY_TESTS)
        if row["candidate_sha256"] != digest or row["accepted"] is not accepted:
            raise ValueError("Negative-control summary differs")
        negative_ok &= accepted
    rows = data["rows"]
    if len(rows) != 18 or {r["sample_id"] for r in rows} != set(scheduled):
        raise ValueError("Repair denominator differs")
    by_cwe = {c: 0 for c in CWES}
    for row in rows:
        sample = row["sample_id"]
        origin, case = selected[sample], scheduled[sample]
        attempt = origin["attempt"]
        if (
            row["origin_file"] != origin["origin_file"]
            or row["origin_index"] != origin["origin_index"]
            or row["cwe"] != case["cwe"]
            or row["candidate_sha256"] != attempt.get("candidate_sha256")
        ):
            raise ValueError("A selected attempt was replaced")
        if attempt.get("candidate_source") is not None:
            if not source_bound(attempt):
                raise ValueError("Candidate hash differs")
            bound(row["dynamic"], attempt["candidate_sha256"], case)
        elif row["dynamic"] != {"status": "not_generated", "tests": []}:
            raise ValueError("Absent candidate has fabricated observations")
        accepted = success(attempt, row["dynamic"], valid[sample], case)
        if type(row["success"]) is not bool or row["success"] != accepted:
            raise ValueError("Candidate success differs")
        by_cwe[case["cwe"]] += accepted
    total = sum(by_cwe.values())
    if (
        type(data["denominator"]) is not int
        or data["denominator"] != 18
        or type(data["successes"]) is not int
        or data["successes"] != total
        or data["by_cwe"] != by_cwe
        or data["controls_accepted"] is not all(valid.values())
        or data["negative_controls_accepted"] is not negative_ok
    ):
        raise ValueError("Repair totals differ")
    return {
        "denominator": 18,
        "successes": total,
        "by_cwe": by_cwe,
        "controls_valid": all(valid.values()),
        "partial_fixes_rejected": negative_ok,
        "three_categories_demonstrated": all(n > 0 for n in by_cwe.values()),
    }


def validate_human(receipt, resolution):
    frozen = read_json(ROOT / "samples/freeze.json")
    samples = frozen["samples"]["dev"] | frozen["samples"]["test"]
    rows = receipt["records"]
    if len(rows) != 180 or {r["sample_id"] for r in rows} != set(samples):
        raise ValueError("Human review coverage differs")
    if any(r["sample_sha256"] != samples[r["sample_id"]] for r in rows):
        raise ValueError("Human sample hashes differ")
    if Counter(r["decision"] for r in rows) != {"agree": 179, "disagree": 1}:
        raise ValueError("Human decisions differ")
    dynamic = receipt["dynamic_records"]
    if (
        len(dynamic) != 18
        or {r["sample_id"] for r in dynamic} != set(cases())
        or Counter(r["decision"] for r in dynamic) != {"agree": 15, "disagree": 3}
    ):
        raise ValueError("Human dynamic review differs")
    if len(receipt["files"]) != 9:
        raise ValueError("Review material count differs")
    for relative, digest in receipt["files"].items():
        path = ROOT / relative
        if not path.resolve().is_relative_to((ROOT / "docs/reviews").resolve()):
            raise ValueError("Review path outside evidence directory")
        if file_hash(path) != digest:
            raise ValueError("Human material hash differs")
    if (
        resolution["Q1"]["primary_root_cause"] != "CWE-1336"
        or resolution["Q1"]["impact_category"] != "CWE-79"
        or resolution["Q1"]["historical_labels_changed"] is not False
        or resolution["Q1"]["samples"] != ["SRC-XSS-03-V", "SRC-XSS-03-S"]
    ):
        raise ValueError("Classification resolution differs")
    expected = {"Q2": "h-xss-14", "Q3": "h-sqli-12", "Q4": "h-cmdi-09"}
    for key, case_id in expected.items():
        if resolution[key]["case_id"] != case_id:
            raise ValueError("Review resolution differs")
    return True


def verify_course(manifest_path=MANIFEST):
    try:
        manifest = read_json(manifest_path)
        if manifest["schema_version"] != "m6-course-manifest-1.0":
            raise ValueError("Unknown course manifest")
        evidence = {}
        for name, binding in manifest["files"].items():
            path = ROOT / binding["path"]
            if not path.resolve().is_relative_to((ROOT / "evaluation").resolve()):
                raise ValueError("Evidence path outside evaluation")
            value = read_json(path)
            if file_hash(path) != binding["sha256"]:
                raise ValueError("Evidence hash differs")
            evidence[name] = value
        if set(evidence) != {
            "protocol",
            "review",
            "human",
            "resolutions",
            "regression",
            "coverage",
            "api_performance",
            "model_performance",
            "boundary",
            "resources",
            "browsers",
            "python_audit",
            "npm_audit",
            "ci",
        }:
            raise ValueError("Incomplete course evidence")
        checks = []

        def check(name, value):
            checks.append({"id": name, "met": bool(value)})

        protocol = evidence["protocol"]
        check(
            "explicit_user_authorized_profile",
            protocol == read_json(PROTOCOL)
            and protocol["regression_thresholds"]["enforced"] is False
            and protocol["repair_thresholds"]["numeric_success_targets_enforced"] is False,
        )
        samples = load_data()[0]["samples"]
        original = verify_all(samples=samples, plan=plan())
        check("original_full_three_round_records_intact", original["ok"])
        reviewed = validate_review(evidence["review"])
        check("all_reference_controls", reviewed["controls_valid"])
        check("partial_fix_probes_rejected", reviewed["partial_fixes_rejected"])
        check("three_real_repair_categories", reviewed["three_categories_demonstrated"])
        check(
            "human_review_and_classification_resolution",
            validate_human(evidence["human"], evidence["resolutions"]),
        )
        replay = evidence["regression"]
        check("regression_runtime_bound", replay["runtime_files"] == detection_fingerprint())
        baseline_path = ROOT / "evaluation/results/m6-detection-baseline.json"
        if replay["input_sha256"] != file_hash(baseline_path):
            raise ValueError("Replay input differs")
        archived = read_json(baseline_path)["records"]
        from scripts.replay_adjudication import replay as replay_intervals

        groups = {}
        for key, group in replay["groups"].items():
            if "/hybrid/" not in key:
                continue
            repeat = int(key.rsplit("/", 1)[1])
            old = [r for r in archived if r["strategy"] == "hybrid" and r["repeat"] == repeat]
            reconstructed, _ = replay_intervals(old, samples, load_data()[1])
            if canon(reconstructed) != group["records"]:
                raise ValueError("Archived predictions were replaced during replay")
            computed = evaluate(samples, group["records"])
            if canon(computed) != group["after"]:
                raise ValueError("Regression metrics differ")
            groups[key] = computed["metrics"]
        check(
            "three_regression_rounds_recorded",
            set(groups) == {"baseline/hybrid/1", "baseline/hybrid/2", "baseline/hybrid/3"},
        )
        perf = evidence["api_performance"]
        check(
            "api_measurement_complete",
            perf["requests"] == 100
            and perf["latency"]["count"] == 100
            and perf["unexpected_errors"] == 0
            and len(perf["observations"]) == 100
            and len(perf["submissions"]) == 10
            and all(r["status"] == 200 for r in perf["observations"])
            and all(r["status"] == 202 for r in perf["submissions"]),
        )
        for name in ("model_performance", "boundary", "resources", "browsers", "python_audit"):
            check(name + "_evidence", evidence[name].get("passed") is True)
        for name, count in (("model_performance", 5), ("boundary", 1)):
            rows = evidence[name]["rows"]
            check(
                name + "_complete",
                len(rows) == count
                and all(
                    r["status"] == "completed" and r["analysis_complete"] is True for r in rows
                ),
            )
        resources = {r["probe"]: r for r in evidence["resources"]["rows"]}
        fs = resources["filesystem"]["observation"]
        check(
            "resource_boundaries_observed",
            resources["memory"]["exit_code"] == 137
            and resources["pids"]["observation"]["blocked"] is True
            and fs["root_write_denied"] is True
            and fs["tmp_write"] is True
            and fs["socket"] is False
            and fs["external"] is False
            and fs["uid"] == 65532,
        )
        browser_runs = evidence["browsers"]["runs"]
        check(
            "two_browsers_observed",
            {r["browser"] for r in browser_runs} == {"chromium", "firefox"}
            and all(
                r["exit_code"] == 0
                and r["stats"]["expected"] > 0
                and r["stats"]["unexpected"] == r["stats"]["flaky"] == 0
                for r in browser_runs
            ),
        )
        for relative, digest in evidence["python_audit"]["locks"].items():
            check("lock_" + relative, file_hash(ROOT / relative) == digest)
        check(
            "npm_audit_recorded", evidence["npm_audit"]["metadata"]["vulnerabilities"]["total"] == 0
        )
        ci = evidence["ci"]
        check(
            "validation_and_browser_ci_provenance",
            str(evidence["review"]["ci"]["run_id"])
            == str(evidence["browsers"]["run_id"])
            == str(ci["run_id"]),
        )
        ordinary = {
            "Backend (ubuntu-latest)",
            "Backend (windows-latest)",
            "Frontend",
            "Controlled Docker regressions (development only)",
            "M6 registered holdout controls",
            "M6 record integrity (recomputed, no thresholds)",
            "Workbench Compose E2E",
        }
        check(
            "ordinary_ci_passed",
            set(ci["jobs"]) == ordinary and all(v == "success" for v in ci["jobs"].values()),
        )
        check("ci_code_bindings_present", validate_ci_code(ci))
        check("coverage_measurement_present", evidence["coverage"]["totals"]["num_branches"] > 0)
        budget = read_json(ROOT / "evaluation/results/m6-mutation-candidates.json")["budget"]
        check(
            "recorded_budget_within_authorization",
            budget["reservations"] <= budget["ceiling"] == 1000,
        )
        ok = all(c["met"] for c in checks)
        return {
            "verdict": "course_delivery_accepted_with_limitations"
            if ok
            else "course_delivery_incomplete",
            "integrity_ok": True,
            "profile": "course-delivery-v1",
            "checks": checks,
            "numeric_targets_enforced": False,
            "human_review_disposition": {
                "Q1": "SSTI root cause and XSS impact annotated; historical scoring preserved",
                "Q2_Q3_Q4": "bound safe and partial-fix controls verified"
                if (reviewed["controls_valid"] and reviewed["partial_fixes_rejected"])
                else "supplemental evidence incomplete",
            },
            "repairs": reviewed,
            "regression": groups,
            "original_reference_requirements": original["requirements"],
            "original_strict_profile_passed": bool(original["requirements"])
            and all(r["met"] for r in original["requirements"]),
            "limitations": [
                "exposed samples, not independent generalization evidence",
                "later attempts, not the original first-candidate repair rate",
                "archived model intervals lack raw contributor ranges/prose",
                "single human reviewer; no second human signature",
                "M7 report formatting, plagiarism check and release remain separate",
            ],
        }
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        StopIteration,
        RecursionError,
    ):
        return {
            "verdict": "records_invalid",
            "integrity_ok": False,
            "profile": "course-delivery-v1",
            "note": "Incomplete or inconsistent bound course evidence; contents withheld",
        }
