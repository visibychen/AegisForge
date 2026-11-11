"""A later diagnostic candidate cannot become a formal first-candidate acceptance record."""

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT)]

import m6_validate  # noqa: E402
from app.validation import runner  # noqa: E402
from app.validation.registry import load_cases  # noqa: E402


def test_diagnostics_are_conditional_even_when_every_container_verdict_passes(
    tmp_path, monkeypatch
):
    cases = [c for c in load_cases(include_holdout=True) if c["id"].startswith("h-")]
    source = "this candidate must never execute on the host"
    rows = [
        {
            "sample_id": c["sample_id"],
            "repeat": 1,
            "cwe": {"xss": "CWE-79", "sqli": "CWE-89", "cmdi": "CWE-78"}[c["id"].split("-")[1]],
            "candidate_source": source,
            "candidate_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "checks": {
                "syntax": "passed",
                "patch": "passed",
                "roundtrip": "passed",
                "review": {"status": "complete"},
                "delta": {"rules": {"introduced": []}, "model": {"introduced": []}},
            },
        }
        for c in cases
    ]
    bundle, controls = tmp_path / "bundle.json", tmp_path / "controls.json"
    bundle.write_text(json.dumps({"rows": rows}), encoding="utf-8")
    controls.write_text(
        json.dumps(
            {
                "rows": [
                    {
                        "sample_id": c["sample_id"],
                        "control": label,
                        "accepted": True,
                        "status": "passed" if label == "S" else "failed",
                        "tests": [
                            {"name": name, "passed": label == "S" or name != "security_regression"}
                            for name in (
                                "business_primary",
                                "business_secondary",
                                "security_regression",
                            )
                        ],
                    }
                    for c in cases
                    for label in ("V", "S")
                ]
            }
        ),
        encoding="utf-8",
    )
    calls = []

    def fake_container(settings, candidate, case):
        assert candidate == source
        calls.append(case["id"])
        return {
            "status": "passed",
            "tests": [
                {"name": name, "passed": True}
                for name in ("business_primary", "business_secondary", "security_regression")
            ],
        }

    monkeypatch.setattr(runner, "run_container", fake_container)
    report = m6_validate.candidates(None, bundle, controls, posthoc=True)
    assert len(calls) == report["successes"] == report["denominator"] == 18
    assert report["execution_complete"] is True
    assert report["passed"] is None
    assert report["course_acceptance_evaluated"] is False
    # The same single-round bundle is incomplete for the registered three-round experiment.
    formal = m6_validate.candidates(None, bundle, controls)
    assert formal["denominator"] == 54 and formal["execution_complete"] is False
    assert formal["missing_candidates"] == 36 and formal["passed"] is False
    forged = json.loads(controls.read_text(encoding="utf-8"))
    for row in forged["rows"]:
        row["tests"] = []  # an accepted flag alone is not evidence of a valid control
    controls.write_text(json.dumps(forged), encoding="utf-8")
    diagnostic = m6_validate.candidates(None, bundle, controls, posthoc=True)
    assert diagnostic["successes"] == 0
    assert all(r["baseline_accepted"] is False for r in diagnostic["rows"])
