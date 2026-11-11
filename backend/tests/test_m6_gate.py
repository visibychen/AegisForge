"""The audit recomputes every number from raw rows; tampering fails, a truthful miss passes."""

import copy
import csv
import hashlib
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from evaluation import gate  # noqa: E402
from evaluation.metrics import CWES, detection_threshold  # noqa: E402

SAMPLES = [
    {"id": "v", "kind": "source", "label": "vulnerable", "cwe": "CWE-79", "lines": [3, 3]},
    {"id": "s", "kind": "source", "label": "safe", "cwe": "CWE-79", "lines": None},
    {"id": "h", "kind": "http", "label": "attack", "cwe": "CWE-79", "lines": None},
]


def source_finding(line=3, sources=("rule",)):
    location = {"kind": "source", "start_line": line, "end_line": line}
    return {"cwe": "CWE-79", "location": location, "sources": list(sources)}


def http_finding():
    return {"cwe": "CWE-79", "location": {"kind": "http", "field": "query.0"}, "sources": ["llm"]}


def record(strategy, repeat, sample):
    findings = {"v": [source_finding()], "s": [source_finding(9)], "h": [http_finding()]}
    return {
        "sample_id": sample,
        "strategy": strategy,
        "repeat": repeat,
        "analysis_complete": True,
        "status": "completed",
        "findings": [
            {**f, "sources": ["rule" if strategy == "rules" else "llm"]} for f in findings[sample]
        ],
        "calls": [{"status": "succeeded"}] if strategy != "rules" else [],
    }


def detection_files():
    records = [
        record(strategy, repeat, sample["id"])
        for strategy, rounds in gate.STRATEGY_ROUNDS.items()
        for repeat in range(1, rounds + 1)
        for sample in SAMPLES
    ]
    recomputed = gate.recompute_groups(SAMPLES, records)
    groups = gate.canon(recomputed)
    summary = {
        "manifest": {"human_review": "pending"},
        "groups": groups,
        "hybrid_threshold": gate.canon(detection_threshold(recomputed["hybrid"])),
        "budget": {"reservations": 18, "ceiling": 1000},  # 18 recorded model calls
        "records": records,
        "human_review_pending": True,
    }
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    columns = ("tp", "fp", "fn", "precision", "recall", "f1", "tasks", "failed")
    writer.writerow(["strategy", "repeat", "kind", *columns])
    for strategy, entries in groups.items():
        for entry in entries:
            for kind in ("source", "http"):
                micro = entry["metrics"][kind]["micro"]
                writer.writerow([strategy, entry["repeat"], kind, *[micro[k] for k in columns]])
    return summary, buffer.getvalue()


def failed(results):
    return {item["name"] for item in results if not item["ok"]}


def audit_detection(summary, text, plan=None):
    return failed(gate.verify_detection(summary, SAMPLES, text, plan))


def test_untouched_detection_records_pass_and_every_tamper_is_caught():
    summary, text = detection_files()
    assert audit_detection(summary, text) == set()

    dropped = copy.deepcopy(summary)
    dropped["records"].pop()
    assert "detection.schedule" in audit_detection(dropped, text)

    moved = copy.deepcopy(summary)
    moved["records"][0]["findings"] = []  # a lost true positive that the file does not admit
    assert "detection.metrics_recomputed" in audit_detection(moved, text)

    flipped = copy.deepcopy(summary)
    flipped["hybrid_threshold"]["passed"] = not flipped["hybrid_threshold"]["passed"]
    assert "detection.threshold_recomputed" in audit_detection(flipped, text)

    assert "detection.csv" in audit_detection(summary, text.replace("0.5", "0.6", 1))

    reviewed = copy.deepcopy(summary)
    reviewed["human_review_pending"] = False
    assert "detection.historical_review_state" in audit_detection(reviewed, text)

    spent = copy.deepcopy(summary)
    spent["budget"]["reservations"] = 0  # fewer reservations than recorded calls is impossible
    assert "detection.budget" in audit_detection(spent, text)


def test_a_changed_frozen_dataset_is_detected_when_a_plan_is_supplied():
    summary, text = detection_files()
    keys = ("dataset_sha256", "records_sha256", "sample_hashes", "samples", "source", "http")
    summary["manifest"] |= {"dataset_sha256": "a", "records_sha256": "b", "sample_hashes": {}}
    summary["manifest"] |= {"samples": 3, "source": 2, "http": 1}
    same = {k: summary["manifest"][k] for k in keys}
    assert "detection.frozen_data_unchanged" not in audit_detection(summary, text, same)
    changed = {**same, "dataset_sha256": "changed"}
    assert "detection.frozen_data_unchanged" in audit_detection(summary, text, changed)


def test_success_rule_needs_valid_controls_a_passed_dynamic_run_and_clean_rechecks():
    ok = {
        "checks": {
            "syntax": "passed",
            "patch": "passed",
            "roundtrip": "passed",
            "review": {"status": "complete"},
            "delta": {"rules": {"introduced": []}, "model": {"introduced": []}},
        },
        "dynamic": dynamic_result(True),
    }
    assert gate.candidate_success(ok, True)
    assert not gate.candidate_success(ok, False)
    for change in (
        lambda r: r["dynamic"].update(status="failed"),
        lambda r: r["dynamic"].update(status="error"),
        lambda r: r["checks"].update(syntax="failed"),
        lambda r: r["checks"]["review"].update(status="failed"),
        lambda r: r["checks"]["delta"]["model"].update(introduced=[{"cwe": "CWE-79"}]),
        lambda r: r.pop("dynamic"),
    ):
        broken = copy.deepcopy(ok)
        change(broken)
        assert not gate.candidate_success(broken, True)


def dynamic_result(good, case=None, digest=None):
    return {
        "status": "passed" if good else "failed",
        "tests": [
            {"name": name, "passed": good or name != "security_regression"}
            for name in sorted(gate.TEST_NAMES)
        ],
        "case_id": case,
        "candidate_sha256": digest,
        "image_id": "sha256:" + "a" * 64,
        "harness_sha256": "b" * 64,
    }


def build_repairs(tmp_path, successes):
    """18 cases x 3 rounds; the first ``successes`` attempts (round-major) succeed."""
    registered = gate.registered_cases()
    groups = [[(s, c["cwe"]) for s, c in registered.items() if c["cwe"] == cwe] for cwe in CWES]
    cases = [c for group in zip(*groups, strict=True) for c in group]
    control_rows = [
        {
            "sample_id": sample,
            "control": label,
            "accepted": True,
            "cwe": cwe,
            **dynamic_result(label == "S", registered[sample]["id"]),
        }
        for sample, cwe in cases
        for label in ("V", "S")
    ]
    controls = {"passed": True, "rows": control_rows}
    rows, bundle_rows = [], []
    for index, (repeat, (sample, cwe)) in enumerate((r, c) for r in (1, 2, 3) for c in cases):
        source = f"x = {index}\n"
        digest = hashlib.sha256(source.encode()).hexdigest()
        good = index < successes
        bundle_rows.append(
            {
                "sample_id": sample,
                "repeat": repeat,
                "candidate_source": source,
                "candidate_sha256": digest,
            }
        )
        rows.append(
            {
                "sample_id": sample,
                "cwe": cwe,
                "repeat": repeat,
                "candidate_sha256": digest,
                "first_candidate": True,
                "checks": {
                    "syntax": "passed",
                    "patch": "passed",
                    "roundtrip": "passed",
                    "review": {"status": "complete"},
                    "delta": {"rules": {"introduced": []}, "model": {"introduced": []}},
                },
                "dynamic": dynamic_result(good, registered[sample]["id"], digest),
                "baseline_accepted": True,
                "success": good,
            }
        )
    for original, row in zip(bundle_rows, rows, strict=True):
        original.update(
            {
                k: row.get(k)
                for k in (
                    "sample_id",
                    "repeat",
                    "cwe",
                    "checks",
                    "status",
                    "error_code",
                    "candidate_sha256",
                    "first_candidate",
                )
            }
        )
    bundle = {"rows": bundle_rows}
    bundle_path, controls_path = tmp_path / "bundle.json", tmp_path / "controls.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    controls_path.write_text(json.dumps(controls), encoding="utf-8")
    by_cwe = {cwe: sum(r["success"] for r in rows if r["cwe"] == cwe) for cwe in CWES}
    total = sum(r["success"] for r in rows)
    repairs = {
        "bundle_sha256": gate.file_hash(bundle_path),
        "controls_sha256": gate.file_hash(controls_path),
        "denominator": 54,
        "successes": total,
        "by_cwe": by_cwe,
        "rounds": [
            {"repeat": i, "successes": sum(r["success"] for r in rows if r["repeat"] == i)}
            for i in (1, 2, 3)
        ],
        "passed": total >= 45 and all(n >= 12 for n in by_cwe.values()),
        "rows": rows,
    }
    return repairs, bundle_path, controls_path, controls, bundle


def audit(parts):
    repairs, bundle_path, controls_path, controls, bundle = parts
    return gate.verify_repairs(repairs, bundle_path, controls_path, controls, bundle)


def test_a_truthful_record_below_the_threshold_is_valid_but_not_accepted(tmp_path):
    parts = build_repairs(tmp_path, successes=36)
    assert failed(audit(parts)) == set()  # integrity does not depend on the numbers
    repairs, _, _, controls, _ = parts
    assert repairs["passed"] is False
    requirements = gate.repair_requirements(repairs, controls)
    assert [r["observed"] for r in requirements][0] == 36
    assert not all(r["met"] for r in requirements)


def test_meeting_the_threshold_needs_the_total_and_every_class(tmp_path):
    parts = build_repairs(tmp_path, successes=54)
    assert failed(audit(parts)) == set()
    assert all(r["met"] for r in gate.repair_requirements(parts[0], parts[3]))
    skewed = build_repairs(tmp_path, successes=45)  # round-major: classes stay balanced
    assert failed(audit(skewed)) == set()


def test_repair_tampering_is_detected(tmp_path):
    base = build_repairs(tmp_path, successes=36)

    inflated = copy.deepcopy(base[0])
    inflated["passed"] = True  # a hand-edited flag
    assert "repairs.passed_recomputed" in failed(audit((inflated, *base[1:])))

    recount = copy.deepcopy(base[0])
    recount["successes"] = 45
    assert "repairs.success_recomputed" in failed(audit((recount, *base[1:])))

    relabelled = copy.deepcopy(base[0])
    relabelled["rows"][0]["success"] = not relabelled["rows"][0]["success"]
    assert "repairs.success_recomputed" in failed(audit((relabelled, *base[1:])))

    short = copy.deepcopy(base[0])
    short["rows"].pop()
    assert "repairs.rows_unique_and_complete" in failed(audit((short, *base[1:])))

    bad_controls = copy.deepcopy(base[3])
    bad_controls["rows"][0]["accepted"] = False
    assert "repairs.controls" in failed(audit((base[0], base[1], base[2], bad_controls, base[4])))

    rebound = copy.deepcopy(base[0])
    rebound["rows"][0]["candidate_sha256"] = "0" * 64
    assert "repairs.candidate_sha_binding" in failed(audit((rebound, *base[1:])))

    base[1].write_text(base[1].read_text(encoding="utf-8") + " ", encoding="utf-8")
    assert "repairs.file_bindings" in failed(audit(base))


def test_an_environment_error_is_not_an_execution_complete_record(tmp_path):
    repairs, *rest = build_repairs(tmp_path, successes=36)
    repairs["rows"][5]["dynamic"] = {"status": "error"}
    assert "repairs.execution_complete" in failed(audit((repairs, *rest)))


def test_missing_files_fail_instead_of_being_skipped(tmp_path):
    report = gate.verify_all(tmp_path, SAMPLES)
    assert report["ok"] is False and not report["requirements"]
    assert {item["name"] for item in report["checks"] if not item["ok"]} >= {
        "file.m6-detection-baseline.json",
        "file.m6-repairs-baseline.json",
    }
    unreadable = gate.verify_all(tmp_path, None)
    assert unreadable["ok"] is False


def test_csv_order_is_irrelevant_but_duplicate_or_changed_counts_fail():
    summary, text = detection_files()
    lines = text.splitlines()
    reordered = "\n".join([lines[0], *reversed(lines[1:])]) + "\n"
    assert audit_detection(summary, reordered) == set()
    assert "detection.csv" in audit_detection(summary, reordered + lines[1] + "\n")


def test_malformed_evidence_fails_closed_without_echoing_contents(tmp_path):
    marker = "private-sentinel"
    invalid = (
        '{"x":1,"x":2}',
        '{"x":NaN}',
        "[]",
        '{"x":Infinity}',
        '{"x":' + marker,
        "\ufeff{}",
    )
    for value in invalid:
        path = tmp_path / "input.json"
        path.write_text(value, encoding="utf-8")
        try:
            gate.read_json(path)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid evidence accepted")
    for filename in gate.FILES.values():
        (tmp_path / filename).write_text("{}", encoding="utf-8")
    report = gate.verify_all(tmp_path, SAMPLES)
    assert report["ok"] is False
    assert marker not in json.dumps(report)
    (tmp_path / gate.FILES["detection"]).write_text('{"records":42}', encoding="utf-8")
    report = gate.verify_all(tmp_path, SAMPLES)
    assert report["ok"] is False
    assert report["checks"][0]["name"] == "records.parse"


def test_oversized_evidence_is_rejected_before_json_parsing(tmp_path):
    path = tmp_path / "large.json"
    path.write_bytes(b" " * (gate.MAX_RECORD_BYTES + 1))
    try:
        gate.read_json(path)
    except ValueError:
        pass
    else:
        raise AssertionError("Unbounded evidence accepted")


def test_coherent_dynamic_flag_without_fixed_tests_is_rejected(tmp_path):
    parts = build_repairs(tmp_path, successes=54)
    repairs = copy.deepcopy(parts[0])
    repairs["rows"][0]["dynamic"] = {"status": "passed"}
    assert {"repairs.dynamic_bindings", "repairs.success_recomputed"} <= failed(
        audit((repairs, *parts[1:]))
    )


def test_missing_delta_engine_or_modified_static_checks_are_not_a_clean_recheck(tmp_path):
    parts = build_repairs(tmp_path, successes=54)
    repairs = copy.deepcopy(parts[0])
    repairs["rows"][0]["checks"]["delta"].pop("model")
    assert {"repairs.candidate_sha_binding", "repairs.success_recomputed"} <= failed(
        audit((repairs, *parts[1:]))
    )
    repairs = copy.deepcopy(parts[0])
    repairs["rows"][0]["checks"]["review"]["status"] = "failed"
    assert "repairs.candidate_sha_binding" in failed(audit((repairs, *parts[1:])))


def test_boolean_repeat_fake_cwe_and_missing_bundle_row_fail(tmp_path):
    parts = build_repairs(tmp_path, successes=54)
    for key, value in (("repeat", True), ("cwe", "CWE-999"), ("sample_id", "unregistered")):
        repairs = copy.deepcopy(parts[0])
        repairs["rows"][0][key] = value
        assert "repairs.rows_unique_and_complete" in failed(audit((repairs, *parts[1:])))
    bundle = copy.deepcopy(parts[4])
    bundle["rows"].pop()
    assert "repairs.candidate_sha_binding" in failed(audit((*parts[:4], bundle)))


def test_false_control_acceptance_and_candidate_or_test_binding_fail(tmp_path):
    parts = build_repairs(tmp_path, successes=54)
    controls = copy.deepcopy(parts[3])
    controls["rows"][0]["tests"] = []
    assert "repairs.control_bindings" in failed(audit((*parts[:3], controls, parts[4])))
    for mutate in (
        lambda d: d.update(candidate_sha256="c" * 64),
        lambda d: d.update(case_id="wrong-case"),
        lambda d: d["tests"][0].update(passed=1),
        lambda d: d["tests"][0].update(passed=False),
        lambda d: d.update(image_id="sha256:" + "d" * 64),
    ):
        repairs = copy.deepcopy(parts[0])
        mutate(repairs["rows"][0]["dynamic"])
        assert "repairs.dynamic_bindings" in failed(audit((repairs, *parts[1:])))


def test_invalid_auxiliary_evidence_exits_two_without_echoing_private_content(
    tmp_path, monkeypatch, capsys
):
    sys.path.insert(0, str(ROOT / "scripts"))
    import acceptance

    monkeypatch.setattr(
        gate,
        "verify_all",
        lambda *a, **kw: {
            "ok": True,
            "checks": [],
            "requirements": [{"id": "stub", "met": True}],
        },
    )
    monkeypatch.setattr(acceptance, "RECORDED_ONLY", ("aux.json",))
    (tmp_path / "aux.json").write_text("private-auxiliary-content", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["acceptance", "--results", str(tmp_path)])
    assert acceptance.main() == 2
    output = capsys.readouterr().out
    assert '"verdict": "records_invalid"' in output
    assert "private-auxiliary-content" not in output
