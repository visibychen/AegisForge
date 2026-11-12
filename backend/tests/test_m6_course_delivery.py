"""Tamper tests use simulated container records only; no sample or candidate executes here."""

import copy
import hashlib
import sys
from pathlib import Path
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]

from app.validation.registry import (  # noqa: E402
    review_validator_fingerprint,
    validator_fingerprint,
)
from m6_review_validate import partial_fixes  # noqa: E402

from evaluation.course_delivery import (  # noqa: E402
    validate_ci_code,
    validate_human,
    validate_review,
    verify_course,
)
from evaluation.experiment import file_hash, load_data  # noqa: E402
from evaluation.gate import read_json  # noqa: E402
from evaluation.review_validation import (  # noqa: E402
    LEGACY_TESTS,
    PROTOCOL,
    cases,
    selected_candidates,
    success,
)


@pytest.fixture
def observations():
    scheduled, selected = cases(), selected_candidates()
    contents = load_data()[1]
    fp = review_validator_fingerprint()

    def observed(case, source, *, legacy=False, failed=()):
        names = LEGACY_TESTS if legacy else case["tests"]
        return {
            "status": "failed" if failed else "passed",
            "case_id": case["id"],
            "run_id": uuid4().hex,
            "image_id": "sha256:" + "a" * 64,
            "candidate_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "harness_sha256": validator_fingerprint() if legacy else fp,
            "tests": [{"name": name, "passed": name not in failed} for name in names],
        }

    controls = []
    for sample, case in scheduled.items():
        for label in ("V", "S"):
            source = contents[sample[:-1] + label]
            controls.append(
                {
                    "sample_id": sample,
                    "control": label,
                    "accepted": True,
                    "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                    "dynamic": observed(
                        case, source, failed=("security_regression",) if label == "V" else ()
                    ),
                }
            )
    negatives = []
    for sample, source in partial_fixes(contents).items():
        case = scheduled[sample]
        negatives.append(
            {
                "sample_id": sample,
                "accepted": True,
                "candidate_sha256": hashlib.sha256(source.encode()).hexdigest(),
                "legacy": observed(case, source, legacy=True),
                "review": observed(case, source, failed=(case["tests"][-1],)),
            }
        )
    rows = []
    for sample, origin in selected.items():
        case, attempt = scheduled[sample], origin["attempt"]
        dynamic = observed(case, attempt["candidate_source"])
        rows.append(
            {
                "sample_id": sample,
                "cwe": case["cwe"],
                "origin_file": origin["origin_file"],
                "origin_index": origin["origin_index"],
                "candidate_sha256": attempt["candidate_sha256"],
                "dynamic": dynamic,
                "success": success(attempt, dynamic, True, case),
            }
        )
    return {
        "schema_version": "m6-review-validation-1.0",
        "model_calls": 0,
        "protocol_sha256": file_hash(PROTOCOL),
        "validator_fingerprint": fp,
        "origin_files": {
            p: file_hash(ROOT / p) for p in {o["origin_file"] for o in selected.values()}
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
        "controls_accepted": True,
        "negative_controls_accepted": True,
    }


def test_complete_observations_are_recomputed(observations):
    result = validate_review(observations)
    assert result["denominator"] == 18
    assert result["controls_valid"] and result["partial_fixes_rejected"]


@pytest.mark.parametrize("damage", ["missing", "copied", "candidate", "test", "total", "partial"])
def test_changed_or_partial_review_evidence_is_not_accepted(observations, damage):
    data = copy.deepcopy(observations)
    if damage == "missing":
        data["rows"].pop()
    elif damage == "copied":
        data["rows"][0]["dynamic"]["run_id"] = data["controls"][0]["dynamic"]["run_id"]
    elif damage == "candidate":
        data["rows"][0]["candidate_sha256"] = "0" * 64
    elif damage == "test":
        data["rows"][0]["dynamic"]["tests"][0]["passed"] = 1
    elif damage == "total":
        data["successes"] += 1
    else:
        probe = data["negative_controls"][0]
        probe["review"]["tests"] = [
            t for t in probe["review"]["tests"] if t["name"] in LEGACY_TESTS
        ]
    with pytest.raises(ValueError):
        validate_review(data)


def test_review_coverage_and_root_cause_annotation_are_verified():
    receipt = read_json(ROOT / "evaluation/results/m6-human-review-20261112.json")
    resolution = read_json(ROOT / "evaluation/annotations/m6-human-review-resolutions.json")
    assert validate_human(receipt, resolution)
    changed = copy.deepcopy(receipt)
    changed["records"].pop()
    with pytest.raises(ValueError, match="coverage"):
        validate_human(changed, resolution)
    resolution["Q1"]["historical_labels_changed"] = True
    with pytest.raises(ValueError, match="Classification"):
        validate_human(receipt, resolution)


def test_no_manifest_fails_closed_without_exposing_file_contents(tmp_path):
    result = verify_course(tmp_path / "missing.json")
    assert result["verdict"] == "records_invalid" and result["integrity_ok"] is False
    assert str(tmp_path) not in str(result)


def test_course_delivery_uses_the_authorized_profile_without_rewriting_original_targets():
    result = verify_course()
    assert result["verdict"] == "course_delivery_accepted_with_limitations"
    assert result["original_strict_profile_passed"] is False
    assert result["numeric_targets_enforced"] is False
    assert result["repairs"]["denominator"] == 18


def test_a_missing_ci_code_binding_is_rejected_even_if_remaining_hashes_match():
    ci = read_json(ROOT / "evaluation/results/m6-closure-ci.json")
    assert validate_ci_code(ci)
    ci["code_files"].pop("backend/app/main.py")
    with pytest.raises(ValueError, match="inventory"):
        validate_ci_code(ci)
