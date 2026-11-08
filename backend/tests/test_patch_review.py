"""Pure tests for patch application, finding delta, structure review and the gate ledger."""

import pytest
from app.core.errors import DomainError
from app.services.patch_review import (
    build_gates,
    build_line_map,
    finding_delta,
    review_structure,
    summarize,
    verdict_for,
)
from app.services.patches import Edit, apply_edits, apply_unified_diff
from app.validation.registry import dynamic_binding, seal


def edit(old, new, start=1, end=1):
    return Edit(start_line=start, end_line=end, old_text=old, new_text=new)


# --- diff and patch hygiene -------------------------------------------------------------


def test_diff_roundtrips_for_unterminated_and_multi_hunk_sources():
    source = "".join(f"line{i}\n" for i in range(30)) + "last"
    candidate, diff = apply_edits(
        source,
        [edit("line2\n", "changed2\n", 3, 3), edit("last", "changed-last", 31, 31)],
    )
    assert apply_unified_diff(source, diff) == candidate
    assert diff.count("\\ No newline at end of file") == 2
    assert "-last+changed-last" not in diff


def test_unchanged_candidate_has_an_empty_diff_that_replays():
    candidate, diff = apply_edits("x = 1\n", [edit("x = 1\n", "x = 1\n")])
    assert diff == "" and candidate == "x = 1\n"


def test_replacement_must_keep_the_line_ending():
    with pytest.raises(DomainError, match="PATCH_NEWLINE"):
        apply_edits("x=1\ny=2\n", [edit("x=1\n", "x=2")])
    # An unterminated final line may be replaced by an unterminated line.
    assert apply_edits("x=1", [edit("x=1", "x=2")])[0] == "x=2"


@pytest.mark.parametrize("new", ["x = 1\r\n", "x = 1\x0c\n", "﻿x = 1\n", "x = ' '\n"])
def test_candidates_must_satisfy_the_snapshot_character_rules(new):
    with pytest.raises(DomainError, match="PATCH_ENCODING"):
        apply_edits("x=1\n", [edit("x=1\n", new)])


# --- finding delta ----------------------------------------------------------------------


def test_delta_separates_target_unrelated_original_and_introduced():
    old = "a\nb\nc\nd\n"
    new = "a\nB\nc\nd\ne\n"
    line_map = build_line_map(old, new)
    baseline = [("CWE-78", 2, 2, "rule"), ("CWE-78", 4, 4, "rule")]
    delta = finding_delta(
        baseline,
        ("CWE-78", 2, 2),
        [("CWE-78", 2, 2, "rule"), ("CWE-78", 4, 4, "rule"), ("CWE-89", 5, 5, "llm")],
        line_map,
    )
    assert [i["start_line"] for i in delta["persisting"]] == [2]
    assert [i["start_line"] for i in delta["preexisting"]] == [4]
    assert [i["cwe"] for i in delta["introduced"]] == ["CWE-89"]
    assert delta["target_resolved"] is False


def test_unchanged_line_with_no_baseline_is_introduced_not_ignored():
    line_map = build_line_map("a\nb\n", "a\nb\n")
    delta = finding_delta([], ("CWE-78", 1, 1), [("CWE-79", 2, 2, "rule")], line_map)
    assert delta["target_resolved"] and len(delta["introduced"]) == 1


# --- structure review -------------------------------------------------------------------

ROUTE = (
    "from flask import Flask, request\napp = Flask(__name__)\n\n"
    "@app.route('/a')\ndef a():\n    return request.args['x']\n"
)


def review(old, new, start=1, end=1):
    return review_structure(old, new, start, end)


def test_scripts_without_any_definition_are_not_rejected():
    impact = review("import os\nos.system(x)\n", "import subprocess\nsubprocess.run([x])\n")
    assert impact["violations"] == []


@pytest.mark.parametrize(
    ("new", "violation"),
    [
        ("from flask import Flask\napp = Flask(__name__)\n", "removed_definition"),
        (ROUTE.replace("def a():", "def b():"), "removed_definition"),
        (ROUTE.replace("def a():", "def a(extra):"), "signature_changed"),
        (ROUTE.replace("@app.route('/a')", "@app.route('/other')"), "decorator_changed"),
        (
            ROUTE.replace("return request.args['x']", "return eval(request.args['x'])"),
            "forbidden_call_added",
        ),
    ],
)
def test_contract_changes_and_forbidden_calls_are_violations(new, violation):
    assert violation in review(ROUTE, new, 6, 6)["violations"]


def test_helper_functions_and_safe_edits_are_allowed():
    new = (
        ROUTE.replace("    return request.args['x']\n", "    return escape(request.args['x'])\n")
        + "\ndef helper():\n    return 1\n"
    )
    assert review(ROUTE, new, 6, 6)["violations"] == []


def test_wide_rewrite_is_refused_only_for_long_files():
    old = "".join(f"value_{i} = {i}\n" for i in range(50))
    new = "".join(f"other_{i} = {i}\n" for i in range(50))
    assert "wide_rewrite" in review(old, new, 1, 1)["violations"]
    assert review("a = 1\n", "b = 2\n")["violations"] == []


def test_far_edits_warn_but_import_only_edits_do_not():
    old = "import os\n" + "".join(f"v{i} = {i}\n" for i in range(40))
    far = old.replace("v38 = 38\n", "v38 = 'changed'\n")
    assert "far_edit" in review(old, far, 2, 2)["warnings"]
    imported = old.replace("import os\n", "import os\nimport shlex\n")
    warnings = review(old, imported, 35, 35)["warnings"]
    assert "far_edit" not in warnings and "shlex" in "".join(
        review(old, imported, 35, 35)["imports_added"]
    )


def test_risky_additions_warn_without_refusing():
    new = ROUTE.replace("return request.args['x']", "return os.system(request.args['x'])")
    impact = review(ROUTE, "import os\n" + new, 6, 6)
    assert "risky_call_added" in impact["warnings"] and impact["violations"] == []


# --- gates and verdict ------------------------------------------------------------------


def static_checks(**overrides):
    checks = {
        "mode": "real",
        "syntax": "passed",
        "patch": "passed",
        "roundtrip": "passed",
        "impact": {"violations": [], "warnings": []},
        "review": {"status": "complete", "error": None},
        "delta": {
            "rules": {
                "target_resolved": True,
                "persisting": [],
                "preexisting": [],
                "introduced": [],
            },
            "model": {
                "target_resolved": True,
                "persisting": [],
                "preexisting": [],
                "introduced": [],
            },
        },
    }
    checks.update(overrides)
    return summarize(checks)


def dynamic_passed(candidate="c" * 64, source="s" * 64):
    return seal(
        {
            "status": "passed",
            "candidate_sha256": candidate,
            "source_sha256": source,
            "tests": [
                {"name": "business_a", "passed": True},
                {"name": "security_a", "passed": True},
            ],
        }
    )


def verdict(checks, dynamic, status="candidate", code=None, candidate="c" * 64):
    binding = dynamic_binding("s" * 64, dynamic, candidate)
    gates = build_gates(checks, dynamic, binding)
    return verdict_for(status, code, checks, gates), gates


def test_passed_requires_every_static_and_dynamic_gate():
    checks = static_checks()
    assert checks["static_passed"] is True
    assert verdict(checks, dynamic_passed())[0] == "passed"
    assert verdict(checks, {})[0] == "unverified"  # no dynamic evidence


def test_failed_static_evidence_outranks_a_tool_error():
    checks = static_checks()
    checks["delta"]["rules"]["introduced"] = [
        {"cwe": "CWE-89", "start_line": 3, "end_line": 3, "sources": ["rule"]}
    ]
    summarize(checks)
    assert verdict(checks, {"status": "error", "error_code": "VALIDATION_TIMEOUT"})[0] == "failed"
    assert verdict(static_checks(), {"status": "error", "error_code": "X"})[0] == "error"


def test_fake_runs_can_never_reach_passed():
    checks = static_checks(mode="fake", review={"status": "not_applicable", "error": None})
    assert checks["static_passed"] is False
    assert verdict(checks, dynamic_passed())[0] == "unverified"


def test_dynamic_record_bound_to_another_candidate_or_edited_is_an_error():
    checks = static_checks()
    assert verdict(checks, dynamic_passed(), candidate="d" * 64)[0] == "error"
    forged = dict(dynamic_passed())
    forged["tests"] = [
        {"name": "security_a", "passed": True},
        {"name": "business_a", "passed": True},
    ]
    assert verdict(checks, forged)[0] == "error"
    unsealed = {k: v for k, v in dynamic_passed().items() if k != "digest"}
    assert verdict(checks, unsealed)[0] == "error"


def test_failed_dynamic_test_names_its_gate():
    checks = static_checks()
    failing = seal(
        {
            "status": "failed",
            "candidate_sha256": "c" * 64,
            "source_sha256": "s" * 64,
            "tests": [
                {"name": "business_a", "passed": True},
                {"name": "security_a", "passed": False},
            ],
        }
    )
    result, gates = verdict(checks, failing)
    states = {g["id"]: g["state"] for g in gates}
    assert result == "failed"
    assert states["dynamic_security"] == "failed" and states["dynamic_business"] == "passed"


def test_review_failure_is_unverified_and_generation_tool_errors_are_errors():
    checks = static_checks(review={"status": "failed", "error": "MODEL_RATE_LIMIT"})
    checks["delta"].pop("model")
    summarize(checks)
    assert verdict(checks, {})[0] == "unverified"
    assert verdict({}, {}, status="failed", code="TASK_TIMEOUT")[0] == "error"
    assert verdict({}, {}, status="failed", code="MODEL_AUTH_FAILED")[0] == "error"
    assert verdict({}, {}, status="failed", code="PATCH_SYNTAX")[0] == "failed"
    assert verdict({}, {}, status="failed", code="REPAIR_STALE")[0] == "unverified"
