"""Auditable M6 gates: record integrity (recomputed) is separate from numeric acceptance.

``verify_*`` answers one question: *are the committed formal records complete, consistent and
untampered?* It recomputes every metric from the raw per-task / per-attempt rows and compares it
with what the files claim, so a hand-edited ``passed`` flag, a dropped row or a changed count fails.
A record set that is truthful but misses the course thresholds is **valid**: integrity passes.

``*_requirements`` answers the other question: *do the recomputed numbers meet the course
thresholds?* Nothing here relaxes a threshold, selects a best round or skips a failed denominator.
"""

import csv
import hashlib
import io
import json
import os
import re
import stat
from pathlib import Path

from evaluation.metrics import CWES, detection_threshold, evaluate

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "evaluation" / "results"
STRATEGY_ROUNDS = {"rules": 1, "llm": 3, "hybrid": 3}
REPAIR_ROUNDS = 3
REPAIR_CASES = 18
FILES = {
    "detection": "m6-detection-baseline.json",
    "csv": "m6-detection-baseline.csv",
    "repairs": "m6-repairs-baseline.json",
    "bundle": "m6-baseline-candidates.json",
    "controls": "m6-controls-final-baseline.json",
}
STATIC_CHECKS = ("syntax", "patch", "roundtrip")
MAX_RECORD_BYTES = 8 * 1024 * 1024
TEST_NAMES = {"business_primary", "business_secondary", "security_regression"}


def registered_cases():
    labels = read_json(ROOT / "samples/holdout/controlled_repairs.json")["samples"]
    cwes = {row["id"]: row["cwe"] for row in labels}
    cases = read_json(ROOT / "samples/controlled/m6_cases.json")["cases"]
    result = {case["sample_id"]: {**case, "cwe": cwes[case["sample_id"]]} for case in cases}
    if len(result) != REPAIR_CASES or set(result) != set(cwes):
        raise ValueError("Invalid registered repair schedule")
    return result


def test_outcomes(dynamic):
    tests = dynamic.get("tests")
    if not isinstance(tests, list) or len(tests) != len(TEST_NAMES):
        return None
    if any(not isinstance(t, dict) or type(t.get("passed")) is not bool for t in tests):
        return None
    outcomes = {t.get("name"): t["passed"] for t in tests}
    if set(outcomes) != TEST_NAMES:
        return None
    expected = "passed" if all(outcomes.values()) else "failed"
    return outcomes if dynamic.get("status") == expected else None


def control_accepted(row):
    tests = test_outcomes(row)
    if tests is None:
        return False
    if row.get("control") == "S":
        return row.get("status") == "passed"
    return (
        row.get("control") == "V"
        and row.get("status") == "failed"
        and tests["business_primary"] is True
        and tests["security_regression"] is False
    )


def bounded_text(path):
    path = Path(path)
    if path.is_symlink() or path.is_junction():
        raise ValueError("Linked evidence is not accepted")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_RECORD_BYTES:
            raise ValueError("Evidence must be a bounded regular file")
        raw = stream.read(MAX_RECORD_BYTES + 1)
        if len(raw) > MAX_RECORD_BYTES:
            raise ValueError("Evidence exceeds the size limit")
    return raw.decode("utf-8")


def read_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate evidence key")
            result[key] = value
        return result

    def constant(_value):
        raise ValueError("Nonfinite evidence value")

    result = json.loads(bounded_text(path), object_pairs_hook=pairs, parse_constant=constant)
    if not isinstance(result, dict):
        raise ValueError("Evidence must be an object")
    return result


def file_hash(path) -> str:
    return hashlib.sha256(Path(path).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def canon(value):
    """JSON round trip, so freshly computed values compare equal to values read from a file."""
    return json.loads(json.dumps(value, sort_keys=True, allow_nan=False))


def check(name: str, ok: bool, detail: str = "") -> dict:
    return {"name": name, "ok": bool(ok), "detail": detail}


def candidate_success(row: dict, control_valid: bool) -> bool:
    """First-candidate success of the M6 protocol (one definition for the run and the audit).

    Stricter than PLAN on purpose: both rechecks must complete with no introduced risk of any
    level, and the fixed dynamic validation must be fully passed on valid control pairs.
    """
    checks = row.get("checks") or {}
    deltas = checks.get("delta") or {}
    reviewed = (checks.get("review") or {}).get("status") == "complete"
    no_new = all(
        isinstance(deltas.get(kind), dict)
        and isinstance(deltas[kind].get("introduced"), list)
        and not deltas[kind]["introduced"]
        for kind in ("rules", "model")
    )
    dynamic = row.get("dynamic") or {}
    return bool(
        control_valid
        and dynamic.get("status") == "passed"
        and test_outcomes(dynamic) is not None
        and all(checks.get(key) == "passed" for key in STATIC_CHECKS)
        and reviewed
        and no_new
    )


# --- detection ----------------------------------------------------------------------------------


def expected_schedule(samples: list[dict]) -> set[tuple]:
    return {
        (strategy, repeat, record["id"])
        for strategy, rounds in STRATEGY_ROUNDS.items()
        for repeat in range(1, rounds + 1)
        for record in samples
    }


def group_rows(records: list[dict], strategy: str, repeat: int) -> list[dict]:
    return [r for r in records if r.get("strategy") == strategy and r.get("repeat") == repeat]


def recompute_groups(samples: list[dict], records: list[dict]) -> dict:
    return {
        strategy: [
            {"repeat": repeat, **evaluate(samples, group_rows(records, strategy, repeat))}
            for repeat in range(1, rounds + 1)
        ]
        for strategy, rounds in STRATEGY_ROUNDS.items()
    }


def verify_detection(summary: dict, samples: list[dict], csv_text=None, plan=None) -> list:
    """Recompute the detection summary from its raw rows and reconcile JSON, CSV and manifest."""
    records = summary.get("records") or []
    identities = [(r.get("strategy"), r.get("repeat"), r.get("sample_id")) for r in records]
    expected = expected_schedule(samples)
    model_tasks = sum(1 for r in records if r.get("strategy") in {"llm", "hybrid"})
    results = [
        check(
            "detection.schedule",
            all(type(r.get("repeat")) is int for r in records)
            and len(identities) == len(set(identities))
            and set(identities) == expected,
            f"{len(records)} rows, {len(expected)} scheduled",
        ),
        check(
            "detection.model_tasks",
            model_tasks == 2 * REPAIR_ROUNDS * len(samples),
            f"{model_tasks} real-model tasks (samples x 3 rounds x 2 strategies)",
        ),
    ]
    expected_hashes = (plan or {}).get("sample_hashes")
    source_ok = all(
        type(r.get("analysis_complete")) is bool
        and (r.get("status") == "completed") is r["analysis_complete"]
        and isinstance(r.get("calls"), list)
        and (not expected_hashes or r.get("source_sha256") == expected_hashes[r["sample_id"]])
        and all(
            isinstance(f.get("sources"), list)
            and bool(f["sources"])
            and set(f["sources"])
            <= (
                {"rule"}
                if r["strategy"] == "rules"
                else {"llm"}
                if r["strategy"] == "llm"
                else {"rule", "llm"}
            )
            for f in r.get("findings", [])
        )
        and (r["strategy"] != "rules" or not r["calls"])
        and (r["strategy"] == "rules" or bool(r["calls"]))
        for r in records
    )
    results.append(
        check("detection.row_bindings", source_ok, "strict state, strategy and input hash")
    )
    recomputed = recompute_groups(samples, records)
    stored = summary.get("groups") or {}
    metrics_ok = all(
        len(stored.get(strategy) or []) == len(entries)
        and all(canon(a) == b for a, b in zip(entries, stored[strategy], strict=True))
        for strategy, entries in recomputed.items()
    )
    results.append(check("detection.metrics_recomputed", metrics_ok, "every group equals the file"))
    threshold = detection_threshold(recomputed["hybrid"])
    recorded = summary.get("hybrid_threshold") or {}
    results.append(
        check(
            "detection.threshold_recomputed",
            canon(threshold) == recorded,
            f"recomputed passed={threshold['passed']}, file passed={recorded.get('passed')}",
        )
    )
    budget = summary.get("budget") or {}
    called = sum(len(r.get("calls") or []) for r in records)
    reserved, ceiling = budget.get("reservations") or 0, budget.get("ceiling") or 0
    results.append(
        check(
            "detection.budget",
            called <= reserved <= ceiling <= 1000,
            f"{called} recorded calls <= {reserved} reservations <= ceiling {ceiling}",
        )
    )
    pending = "pending" in str((summary.get("manifest") or {}).get("human_review")).lower()
    results.append(
        check(
            "detection.historical_review_state",
            summary.get("human_review_pending") is pending,
            "recorded historical state matches its manifest; no human identity is authenticated",
        )
    )
    if plan is not None:
        manifest = summary.get("manifest") or {}
        keys = (
            "dataset_sha256",
            "records_sha256",
            "sample_hashes",
            "samples",
            "source",
            "http",
            "human_review",
        )
        results.append(
            check(
                "detection.frozen_data_unchanged",
                all(manifest.get(key) == plan.get(key) for key in keys),
                "freeze file, records and per-sample hashes equal the baseline manifest",
            )
        )
    if csv_text is not None:
        ok, detail = reconcile_csv(csv_text, recomputed)
        results.append(check("detection.csv", ok, detail))
    return results


def reconcile_csv(text: str, recomputed: dict):
    reader = csv.DictReader(io.StringIO(text))
    columns = [
        "strategy",
        "repeat",
        "kind",
        "tp",
        "fp",
        "fn",
        "precision",
        "recall",
        "f1",
        "tasks",
        "failed",
    ]
    if reader.fieldnames != columns:
        return False, "CSV schema differs"
    rows = list(reader)
    if any(None in row or any(value is None for value in row.values()) for row in rows):
        return False, "CSV column count differs"
    expected = [
        (strategy, entry["repeat"], kind)
        for strategy, entries in recomputed.items()
        for entry in entries
        for kind in ("source", "http")
    ]
    identities = [(r["strategy"], int(r["repeat"]), r["kind"]) for r in rows]
    if len(identities) != len(set(identities)) or set(identities) != set(expected):
        return False, "CSV rows do not match the scheduled groups"
    lookup = {(s, e["repeat"]): e for s, entries in recomputed.items() for e in entries}
    for row in rows:
        micro = lookup[(row["strategy"], int(row["repeat"]))]["metrics"][row["kind"]]["micro"]
        where = f"{row['strategy']}/{row['repeat']}/{row['kind']}"
        for key in ("tp", "fp", "fn", "tasks", "failed"):
            if int(row[key]) != micro[key]:
                return False, f"{where} {key} differs"
        for key in ("precision", "recall", "f1"):
            value = micro[key]
            empty = row[key] == ""
            if empty != (value is None) or (not empty and float(row[key]) != value):
                return False, f"{where} {key} differs"
    return True, f"{len(rows)} rows reconcile"


def detection_requirements(rounds: list[dict]) -> list[dict]:
    """The PLAN thresholds on recomputed hybrid rounds (the mean of all rounds, never the best)."""
    result = detection_threshold(rounds)
    if "source_mean_precision" not in result:
        return [met("detection.rounds", "three complete rounds", None, False)]
    per_cwe = result["source_per_cwe_mean_recall"]
    rows = [
        ("detection.source_precision", ">= 0.85 (mean)", result["source_mean_precision"], 0.85),
        ("detection.source_recall", ">= 0.85 (mean)", result["source_mean_recall"], 0.85),
        ("detection.http_f1", ">= 0.85 (mean)", result["http_mean_f1"], 0.85),
    ]
    rows += [(f"detection.recall.{cwe}", ">= 0.80 (mean)", per_cwe[cwe], 0.8) for cwe in CWES]
    required = [met(i, need, v, v is not None and v >= floor) for i, need, v, floor in rows]
    complete = all(r["complete"] for r in rounds)
    present = "every scheduled row present"
    return required + [met("detection.rounds_complete", present, complete, complete)]


def met(ident, required, observed, ok) -> dict:
    return {"id": ident, "required": required, "observed": observed, "met": bool(ok)}


# --- repair -------------------------------------------------------------------------------------


def control_validity(controls: dict) -> dict:
    """A case's controls are valid only if both its original (V) and reference (S) were accepted."""
    grouped: dict = {}
    for row in controls.get("rows") or []:
        grouped.setdefault(row.get("sample_id"), []).append(row)
    return {
        sample: len(items) == 2
        and {i.get("control") for i in items} == {"V", "S"}
        and all(i.get("accepted") is True and control_accepted(i) for i in items)
        for sample, items in grouped.items()
    }


def count_successes(rows: list[dict], valid: dict) -> tuple:
    flags = [(r, candidate_success(r, valid.get(r.get("sample_id"), False))) for r in rows]
    by_cwe = {cwe: sum(ok for r, ok in flags if r.get("cwe") == cwe) for cwe in CWES}
    rounds = [sum(ok for r, ok in flags if r.get("repeat") == i) for i in (1, 2, 3)]
    return flags, sum(ok for _, ok in flags), by_cwe, rounds


def repair_threshold_met(total: int, by_cwe: dict) -> bool:
    return total >= 45 and all(by_cwe.get(cwe, 0) >= 12 for cwe in CWES)


def verify_repairs(
    repairs: dict, bundle_path, controls_path, controls: dict, bundle: dict, sample_hashes=None
) -> list:
    registered = registered_cases()
    rows = repairs.get("rows") or []
    identities = [(r.get("sample_id"), r.get("repeat")) for r in rows]
    cases = {i[0] for i in identities}
    results = [
        check(
            "repairs.rows_unique_and_complete",
            all(type(r.get("repeat")) is int for r in rows)
            and set(identities) == {(s, i) for s in registered for i in (1, 2, 3)}
            and all(r.get("cwe") == registered.get(r.get("sample_id"), {}).get("cwe") for r in rows)
            and len(rows) == REPAIR_CASES * REPAIR_ROUNDS
            and len(set(identities)) == len(identities)
            and len(cases) == REPAIR_CASES
            and {i[1] for i in identities} == {1, 2, 3},
            f"{len(rows)} rows for {len(cases)} registered cases",
        )
    ]
    valid = control_validity(controls)
    control_rows = controls.get("rows") or []
    recorded_pass = controls.get("passed") is (all(valid.values()) and len(control_rows) == 36)
    results.append(
        check(
            "repairs.controls",
            len(control_rows) == 2 * REPAIR_CASES and set(valid) == cases and recorded_pass,
            f"{len(control_rows)} control rows, {sum(valid.values())} valid pairs",
        )
    )
    controls_bound = True
    for row in control_rows:
        case = registered.get(row.get("sample_id"), {})
        source_id = str(row.get("sample_id"))[:-1] + str(row.get("control"))
        expected_hash = (sample_hashes or {}).get(source_id)
        controls_bound &= (
            row.get("case_id") == case.get("id")
            and row.get("cwe") == case.get("cwe")
            and row.get("accepted") is control_accepted(row)
            and test_outcomes(row) is not None
            and (not expected_hash or row.get("candidate_sha256") == expected_hash)
        )
    results.append(
        check("repairs.control_bindings", controls_bound, "fixed tests, cases and sources")
    )
    results.append(
        check(
            "repairs.file_bindings",
            repairs.get("bundle_sha256") == file_hash(bundle_path)
            and repairs.get("controls_sha256") == file_hash(controls_path),
            "candidate bundle and control files match the recorded SHA-256",
        )
    )
    bundled = {(r.get("sample_id"), r.get("repeat")): r for r in bundle.get("rows") or []}
    bound = (
        len(bundled) == len(bundle.get("rows") or []) == len(rows)
        and set(bundled) == set(identities)
        and all(type(r.get("repeat")) is int for r in bundle.get("rows") or [])
    )
    dynamic_bindings = True
    runtimes = {(r.get("image_id"), r.get("harness_sha256")) for r in control_rows}
    for row in rows:
        source = bundled.get((row.get("sample_id"), row.get("repeat")), {})
        text = source.get("candidate_source")
        if text is not None:
            bound &= hashlib.sha256(text.encode()).hexdigest() == source.get("candidate_sha256")
        bound &= row.get("candidate_sha256") == source.get("candidate_sha256")
        bound &= all(
            row.get(k) == value
            for k, value in source.items()
            if k not in {"candidate_source", "success"}
        )
        bound &= row.get("first_candidate") is True
        dynamic = row.get("dynamic")
        if text is not None:
            case = registered.get(row.get("sample_id"), {})
            runtime = ((dynamic or {}).get("image_id"), (dynamic or {}).get("harness_sha256"))
            dynamic_bindings &= (
                isinstance(dynamic, dict)
                and test_outcomes(dynamic) is not None
                and dynamic.get("candidate_sha256") == row.get("candidate_sha256")
                and dynamic.get("case_id") == case.get("id")
                and runtime in runtimes
                and len(runtimes) == 1
                and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", str(runtime[0])))
                and bool(re.fullmatch(r"[0-9a-f]{64}", str(runtime[1])))
            )
        else:
            dynamic_bindings &= dynamic is None and bool(row.get("error_code"))
    results.append(check("repairs.candidate_sha_binding", bound, "bundle rows bind to results"))
    results.append(
        check(
            "repairs.dynamic_bindings",
            dynamic_bindings,
            "fixed tests, candidate, case, image and harness match",
        )
    )
    flags, total, by_cwe, rounds = count_successes(rows, valid)
    flagged = all(type(r.get("success")) is bool and ok == r["success"] for r, ok in flags)
    results.append(
        check(
            "repairs.success_recomputed",
            flagged
            and repairs.get("successes") == total
            and repairs.get("by_cwe") == by_cwe
            and [x.get("successes") for x in repairs.get("rounds") or []] == rounds
            and repairs.get("denominator") == REPAIR_CASES * REPAIR_ROUNDS,
            f"recomputed {total}/{REPAIR_CASES * REPAIR_ROUNDS}, by CWE {by_cwe}",
        )
    )
    results.append(
        check(
            "repairs.passed_recomputed",
            repairs.get("passed") is repair_threshold_met(total, by_cwe),
            "the recorded passed flag equals the threshold applied to the recomputed counts",
        )
    )
    broken = [
        r for r in rows if (r.get("dynamic") or {}).get("status") not in {None, "passed", "failed"}
    ]
    explained = all("dynamic" in r or r.get("error_code") for r in rows)
    results.append(
        check(
            "repairs.execution_complete",
            not broken and explained,
            f"{len(broken)} rows ended in an environment error",
        )
    )
    return results


def repair_requirements(repairs: dict, controls: dict) -> list[dict]:
    _, total, by_cwe, _ = count_successes(repairs.get("rows") or [], control_validity(controls))
    return [met("repairs.total", ">= 45/54", total, total >= 45)] + [
        met(f"repairs.{cwe}", ">= 12/18", n, n >= 12) for cwe, n in by_cwe.items()
    ]


# --- loading ------------------------------------------------------------------------------------


def _verify_all(directory=RESULTS, samples=None, plan=None) -> dict:
    """Integrity report for the formal files. A missing file is a failure, never a skipped check."""
    paths = {key: Path(directory) / name for key, name in FILES.items()}
    results = [
        check(f"file.{name}", paths[key].is_file(), "present") for key, name in FILES.items()
    ]
    if samples is None:
        results.append(check("frozen.samples", False, "frozen sample records unavailable"))
    if not all(r["ok"] for r in results):
        return {"ok": False, "checks": results, "requirements": []}
    keys = ("detection", "repairs", "controls", "bundle")
    read = {key: read_json(paths[key]) for key in keys}
    csv_text = bounded_text(paths["csv"])
    results += verify_detection(read["detection"], samples, csv_text, plan)
    results += verify_repairs(
        read["repairs"],
        paths["bundle"],
        paths["controls"],
        read["controls"],
        read["bundle"],
        (plan or {}).get("sample_hashes"),
    )
    hybrid = recompute_groups(samples, read["detection"].get("records") or [])["hybrid"]
    reviewed = read["detection"].get("human_review_pending") is False
    requirements = detection_requirements(hybrid)
    requirements += repair_requirements(read["repairs"], read["controls"])
    state = "completed" if reviewed else "pending"
    requirements.append(met("labels.human_review", "human review completed", state, reviewed))
    return {"ok": all(r["ok"] for r in results), "checks": results, "requirements": requirements}


def verify_all(directory=RESULTS, samples=None, plan=None) -> dict:
    try:
        return _verify_all(directory, samples, plan)
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError):
        return {
            "ok": False,
            "checks": [check("records.parse", False, "Invalid bounded JSON/CSV or record schema")],
            "requirements": [],
        }
