import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from app.core.errors import DomainError  # noqa: E402

from evaluation.budget import ExperimentBudget  # noqa: E402
from evaluation.metrics import evaluate  # noqa: E402


def record(ident="v", label="vulnerable", cwe="CWE-79", kind="source"):
    return {
        "id": ident,
        "label": label,
        "cwe": cwe,
        "kind": kind,
        "lines": [3, 4] if label == "vulnerable" else None,
    }


def finding(cwe="CWE-79", start=3, end=3):
    return {"cwe": cwe, "location": {"kind": "source", "start_line": start, "end_line": end}}


def test_matching_is_one_to_one_wrong_location_and_cwe_are_false_positives():
    result = evaluate(
        [record()],
        [
            {
                "sample_id": "v",
                "analysis_complete": True,
                "findings": [finding(), finding(), finding("CWE-89"), finding(start=9, end=9)],
            }
        ],
    )
    counts = result["metrics"]["source"]["micro"]
    assert (counts["tp"], counts["fp"], counts["fn"]) == (1, 3, 0)
    assert counts["precision"] == 0.25


def test_missing_failures_and_safe_cross_cwe_findings_stay_in_denominator():
    result = evaluate(
        [record(), record("s", "safe")],
        [{"sample_id": "s", "analysis_complete": False, "findings": [finding("CWE-78")]}],
    )
    counts = result["metrics"]["source"]["micro"]
    assert (counts["tp"], counts["fp"], counts["fn"], counts["tasks"], counts["failed"]) == (
        0,
        1,
        1,
        2,
        2,
    )
    assert counts["safe_false_alarm_rate"] == 1
    assert result["complete"] is False


def test_zero_denominator_is_none_and_http_is_separate():
    result = evaluate(
        [record("h", "normal", None, "http")],
        [{"sample_id": "h", "analysis_complete": True, "findings": []}],
    )
    assert result["metrics"]["http"]["micro"]["precision"] is None
    assert result["metrics"]["source"]["micro"]["tasks"] == 0
    with pytest.raises(ValueError, match="duplicate"):
        evaluate([], [{"sample_id": "x"}, {"sample_id": "x"}])


def test_global_budget_is_atomic_and_restart_does_not_reset_it(tmp_path):
    budget = ExperimentBudget(tmp_path / "budget.db", 7)

    def reserve(_):
        try:
            return budget.reserve("job")
        except DomainError as error:
            assert error.code == "EXPERIMENT_BUDGET"
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = [x for x in pool.map(reserve, range(30)) if x is not None]
    assert len(set(ids)) == 7
    restarted = ExperimentBudget(tmp_path / "budget.db", 7)
    assert restarted.summary()["reservations"] == 7
    with pytest.raises(DomainError):
        restarted.reserve("later")
    with pytest.raises(ValueError, match="change"):
        ExperimentBudget(tmp_path / "budget.db", 8)


def test_evaluator_uses_actual_upload_queue_worker_without_paid_calls(tmp_path, monkeypatch):
    from evaluation.experiment import run_detection

    monkeypatch.delenv("AEGISFORGE_DEEPSEEK_API_KEY", raising=False)
    source = (
        "from flask import request\ndef greet():\n"
        '    return "<p>" + request.args["name"] + "</p>"\n'
    )
    budget = ExperimentBudget(tmp_path / "budget.db", 10)
    row = run_detection(tmp_path, {"model": "deepseek-flash"}, budget, record(), source, "rules", 1)
    assert row["status"] == "completed", row
    assert row["analysis_complete"] is True
    assert row["findings"][0]["cwe"] == "CWE-79"
    assert budget.summary()["reservations"] == 0
    again = run_detection(
        tmp_path, {"model": "deepseek-flash"}, budget, record(), source, "rules", 1
    )
    assert again == row


def test_m6_runner_registers_exact_frozen_ids_and_cannot_accept_an_unknown_source():
    import json

    from app.validation.registry import load_cases, match_case

    registered = json.loads((ROOT / "samples/holdout/controlled_repairs.json").read_text())[
        "samples"
    ]
    hashes = json.loads((ROOT / "samples/freeze.json").read_text())["samples"]["test"]
    cases = [c for c in load_cases(include_holdout=True) if c["id"].startswith("h-")]
    assert len(cases) == 18
    assert {c["sample_id"] for c in cases} == {c["id"] for c in registered}
    for case in cases:
        assert case["source_sha256"] == hashes[case["sample_id"]]
        assert match_case(case["source_sha256"]) == case
        assert case["tests"] == ["business_primary", "business_secondary", "security_regression"]
    with pytest.raises(DomainError):
        match_case("0" * 64)


def test_development_ab_subset_preserves_each_cwe_pair_and_all_http():
    sys.path.insert(0, str(ROOT / "scripts"))
    from development_ab import select_subset

    from evaluation.datasets import load_dev_samples

    manifest, _ = load_dev_samples()
    selected = select_subset(manifest["samples"])
    assert len(selected) == len({r["id"] for r in selected}) == 48
    for cwe in ("CWE-79", "CWE-89", "CWE-78"):
        source = [r for r in selected if r["kind"] == "source" and r["cwe"] == cwe]
        assert len(source) == 8
        assert sum(r["label"] == "vulnerable" for r in source) == 4
        for family in {r["family"] for r in source}:
            assert {r["label"] for r in source if r["family"] == family} == {"vulnerable", "safe"}
    assert {r["id"] for r in selected if r["kind"] == "http"} == {
        r["id"] for r in manifest["samples"] if r["kind"] == "http"
    }
