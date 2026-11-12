"""Trusted driver unit fixtures; synthetic sources are parsed, never executed on the host."""

import ast
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from app.validation.runner import run_container

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]

from m6_review_validate import partial_fixes  # noqa: E402

from evaluation import review_validation as review  # noqa: E402
from evaluation.experiment import load_data  # noqa: E402


def test_latest_selection_covers_all_targets_without_inspecting_success():
    selected = review.selected_candidates()
    assert len(selected) == 18
    assert selected["SRC-SQLI-12-V"]["origin_file"].endswith("m6-mutation-candidates.json")
    assert selected["SRC-XSS-09-V"]["origin_file"].endswith("m6-targeted-candidates.json")
    assert selected["SRC-XSS-11-V"]["origin_file"].endswith("m6-posthoc-candidates.json")


def test_failed_newest_scheduled_attempt_cannot_fall_back_to_an_old_success(monkeypatch):
    protocol = {"repair_thresholds": {"selection_priority": ["new", "old"]}}
    inputs = {
        str(review.PROTOCOL): protocol,
        str(review.ROOT / "new"): {"rows": [{"sample_id": "s", "status": "failed"}]},
        str(review.ROOT / "old"): {"rows": [{"sample_id": "s", "status": "candidate"}]},
    }
    monkeypatch.setattr(review, "read_json", lambda p: inputs[str(p)])
    monkeypatch.setattr(review, "cases", lambda: {"s": {}})
    assert review.selected_candidates()["s"]["attempt"]["status"] == "failed"


def test_extra_test_failure_cannot_be_hidden_by_three_legacy_passes():
    names = review.cases()["SRC-XSS-14-V"]["tests"]
    dynamic = {
        "status": "failed",
        "tests": [{"name": n, "passed": n in review.LEGACY_TESTS} for n in names],
    }
    assert review.outcomes(dynamic, names)[names[-1]] is False
    assert review.success({}, dynamic, True, {"tests": names}) is False
    dynamic["status"] = "passed"
    assert review.outcomes(dynamic, names) is None
    dynamic["tests"][0]["passed"] = 1
    assert review.outcomes(dynamic, names) is None


def test_fixed_partial_fix_probes_have_valid_syntax_without_running_them():
    probes = partial_fixes(load_data()[1])
    assert len(probes) == 3
    for source in probes.values():
        ast.parse(source)
    tree = ast.parse(probes["SRC-XSS-14-V"])
    escaped = [
        ast.literal_eval(n.args[1])
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "replace"
    ]
    assert escaped == ["\\'"]


def test_unknown_validator_profile_never_launches_docker(api, monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("An unsupported profile must not launch a process")

    monkeypatch.setattr("app.validation.runner.subprocess.run", forbidden)
    result = run_container(api.app.state.settings, "x=1", {"id": "h-xss-14"}, profile="user-image")
    assert result["error_code"] == "VALIDATION_PROFILE"


def driver():
    spec = importlib.util.spec_from_file_location(
        "review_driver_test", ROOT / "deploy/review-validator/review_cases.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("partial_write", [False, True])
def test_mixed_unknown_update_must_be_rejected_atomically(monkeypatch, partial_write):
    module = driver()
    state = [[1, "Alice", "a@example.invalid", "UTC"], [2, "Bob", "b@example.invalid", "UTC"]]

    def request(_path, **kwargs):
        data = kwargs["data"]
        if "nonexistent_column" in data:
            if partial_write:
                state[0][1] = data["display_name"]
            return 400, {}, b""
        for key, value in data.items():
            state[0][{"email": 2, "timezone": 3}[key]] = value
        return 200, {}, b""

    base = SimpleNamespace(request=request, database=lambda *_: [tuple(r) for r in state])
    monkeypatch.setitem(sys.modules, "holdout_cases", base)
    monkeypatch.setitem(sys.modules, "harness", SimpleNamespace(bounded_file=lambda *_: b""))
    results = {}
    module.run_extra("h-sqli-12", None, results)
    assert results["business_email"] and results["business_timezone"]
    assert results["business_reject_unknown_atomically"] is not partial_write


def test_backup_success_response_requires_an_actual_new_file(monkeypatch):
    module, unlinked = driver(), []
    monkeypatch.setattr(
        module, "Path", lambda p: SimpleNamespace(unlink=lambda **kw: unlinked.append((p, kw)))
    )
    base = SimpleNamespace(
        command_request=lambda *_: (200, {}, b""), json_body=lambda _: {"status": 0}
    )

    def missing(*_args, **_kwargs):
        raise FileNotFoundError

    monkeypatch.setitem(sys.modules, "holdout_cases", base)
    monkeypatch.setitem(sys.modules, "harness", SimpleNamespace(bounded_file=missing))
    results = {}
    module.run_extra("h-cmdi-09", None, results)
    assert len(unlinked) == 2 and not any(results.values())
