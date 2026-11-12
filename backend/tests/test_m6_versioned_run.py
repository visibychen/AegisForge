"""Unit fixtures simulate container observations; no candidate code executes in these tests."""

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from evaluation import targeted  # noqa: E402
from evaluation.gate import candidate_success, control_validity, file_hash  # noqa: E402


@pytest.fixture
def run_files(tmp_path, monkeypatch):
    def read(name):
        return json.loads((ROOT / "evaluation/results" / name).read_text(encoding="utf-8"))

    detection = read("m6-mutation-detection.json")
    bundle = read("m6-mutation-candidates.json")
    controls = read("m6-controls-final-baseline.json")
    valid = control_validity(controls)
    observations = []
    for original in bundle["rows"]:
        row = {k: copy.deepcopy(v) for k, v in original.items() if k != "candidate_source"}
        row["baseline_accepted"] = valid[row["sample_id"]]
        row["dynamic"] = {
            "status": "passed",
            "tests": [
                {"name": name, "passed": True}
                for name in ("business_primary", "business_secondary", "security_regression")
            ],
        }
        row["success"] = candidate_success(row, True)
        observations.append(row)
    files = {
        "detection": detection,
        "bundle": bundle,
        "controls": controls,
        "dynamic": {
            "rows": observations,
            "denominator": len(observations),
            "successes": sum(r["success"] for r in observations),
            "by_cwe": {
                c: sum(r["success"] for r in observations if r["cwe"] == c)
                for c in ("CWE-79", "CWE-89", "CWE-78")
            },
            "passed": None,
            "course_acceptance_evaluated": False,
            "execution_complete": True,
        },
    }
    folder = tmp_path / "evaluation/results"
    folder.mkdir(parents=True)
    frozen = tmp_path / "samples/freeze.json"
    frozen.parent.mkdir()
    frozen.write_bytes((ROOT / "samples/freeze.json").read_bytes())
    monkeypatch.setattr(targeted, "ROOT", tmp_path)
    monkeypatch.setattr(targeted, "_verify_code", lambda _: None)  # separately exercised below

    def save():
        for name in ("detection", "bundle", "controls"):
            (folder / f"{name}.json").write_text(json.dumps(files[name]), encoding="utf-8")
        dynamic = files["dynamic"]
        dynamic["bundle_sha256"] = file_hash(folder / "bundle.json")
        dynamic["controls_sha256"] = file_hash(folder / "controls.json")
        (folder / "dynamic.json").write_text(json.dumps(dynamic), encoding="utf-8")
        manifest = {
            "schema_version": "m6-diagnostic-run-1.0",
            "run_id": "unit-only",
            "course_acceptance_evaluated": False,
            "human_review": "pending",
            "files": {
                name: {
                    "path": f"evaluation/results/{name}.json",
                    "sha256": file_hash(folder / f"{name}.json"),
                }
                for name in files
            },
        }
        path = folder / "run.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path

    return files, save


def test_valid_diagnostic_remains_unaccepted(run_files):
    _, save = run_files
    result = targeted.verify_run(save())
    assert result["integrity_ok"] is True
    assert result["verdict"] == "diagnostic_only"
    assert result["course_acceptance_evaluated"] is False


@pytest.mark.parametrize("damage", ["score", "missing", "success", "source", "scope", "budget"])
def test_rehashed_tampering_is_rejected_by_recomputation(run_files, damage):
    files, save = run_files
    if damage == "score":
        files["detection"]["evaluation"]["metrics"]["source"]["micro"]["fp"] += 1
    elif damage == "missing":
        files["dynamic"]["rows"] = []
    elif damage == "success":
        files["dynamic"]["rows"][0]["success"] = not files["dynamic"]["rows"][0]["success"]
    elif damage == "source":
        files["bundle"]["rows"][0]["candidate_source"] += "\n# tampered"
    elif damage == "scope":
        files["dynamic"]["passed"] = True
    else:
        files["bundle"]["budget"]["reservations"] = 1001
    assert targeted.verify_run(save())["verdict"] == "records_invalid"


def test_bound_file_rejects_paths_outside_results(tmp_path, monkeypatch):
    monkeypatch.setattr(targeted, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="outside"):
        targeted._bound_file({"path": "../private.json", "sha256": "0" * 64})


def test_recorded_runtime_hashes_are_verified_against_git_history():
    import subprocess

    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    name = "backend/app/core/config.py"
    protocol = {
        "code_sha": sha,
        "runtime_files": {name: file_hash(ROOT / name)},
        "orchestrator_files": {},
    }
    targeted._verify_code(protocol)
    protocol["runtime_files"][name] = "0" * 64
    with pytest.raises(ValueError, match="Git history"):
        targeted._verify_code(protocol)
