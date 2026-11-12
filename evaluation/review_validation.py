"""Fixed review-v1 schedules, deterministic candidate selection and strict outcome checks."""

import ast
import copy
import hashlib

from evaluation.gate import ROOT, candidate_success, read_json, registered_cases

PROTOCOL = ROOT / "evaluation/protocols/m6-course-delivery-v1.json"
LEGACY_TESTS = ["business_primary", "business_secondary", "security_regression"]


def extra_tests():
    tree = ast.parse((ROOT / "deploy/review-validator/review_cases.py").read_text(encoding="utf-8"))
    node = next(
        n
        for n in tree.body
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "EXTRA_TESTS" for t in n.targets)
    )
    return ast.literal_eval(node.value)


def cases():
    extra = extra_tests()
    return {
        sample: {**case, "tests": [*case["tests"], *extra.get(case["id"], [])]}
        for sample, case in registered_cases().items()
    }


def selected_candidates():
    """Newest scheduled row wins, including failed attempts. Selection never reads success."""
    selected = {}
    paths = read_json(PROTOCOL)["repair_thresholds"]["selection_priority"]
    for relative in paths:
        bundle = read_json(ROOT / relative)
        seen = set()
        for index, row in enumerate(bundle["rows"]):
            sample = row["sample_id"]
            if sample in seen:
                raise ValueError("Duplicate scheduled sample in candidate bundle")
            seen.add(sample)
            if sample not in selected:
                selected[sample] = {
                    "origin_file": relative,
                    "origin_index": index,
                    "attempt": copy.deepcopy(row),
                }
    registered = cases()
    if set(selected) != set(registered):
        raise ValueError("Every one of the 18 registered targets must remain in the schedule")
    return selected


def outcomes(dynamic, names):
    if not isinstance(dynamic, dict) or dynamic.get("status") not in {"passed", "failed"}:
        return None
    tests = dynamic.get("tests")
    if (
        not isinstance(tests, list)
        or len(tests) != len(names)
        or any(
            not isinstance(t, dict) or set(t) != {"name", "passed"} or type(t["passed"]) is not bool
            for t in tests
        )
        or [t["name"] for t in tests] != names
    ):
        return None
    result = {t["name"]: t["passed"] for t in tests}
    if (dynamic["status"] == "passed") != all(result.values()):
        return None
    return result


def legacy_outcome(dynamic):
    tests = [t for t in dynamic.get("tests", []) if t.get("name") in LEGACY_TESTS]
    return {
        **dynamic,
        "tests": tests,
        "status": "passed" if all(t["passed"] for t in tests) else "failed",
    }


def success(attempt, dynamic, control_valid, case):
    observed = outcomes(dynamic, case["tests"])
    return bool(
        observed
        and all(observed.values())
        and candidate_success({**attempt, "dynamic": legacy_outcome(dynamic)}, control_valid)
    )


def source_bound(row):
    source = row.get("candidate_source")
    return (
        isinstance(source, str)
        and len(source.encode()) <= 24000
        and hashlib.sha256(source.encode()).hexdigest() == row.get("candidate_sha256")
    )
