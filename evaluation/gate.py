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
    no_new = all(not (deltas.get(kind) or {}).get("introduced") for kind in ("rules", "model"))
    return bool(
        control_valid
        and (row.get("dynamic") or {}).get("status") == "passed"
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
            len(identities) == len(set(identities)) and set(identities) == expected,
            f"{len(records)} rows, {len(expected)} scheduled",
        ),
        check(
            "detection.model_tasks",
            model_tasks == 2 * REPAIR_ROUNDS * len(samples),
            f"{model_tasks} real-model tasks (samples x 3 rounds x 2 strategies)",
        ),
    ]
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
            "detection.human_review_pending",
            summary.get("human_review_pending") is True and pending,
            "AI-authored labels stay marked as pending human review",
        )
    )
    if plan is not None:
        manifest = summary.get("manifest") or {}
        keys = ("dataset_sha256", "records_sha256", "sample_hashes", "samples", "source", "http")
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
    rows = list(csv.DictReader(io.StringIO(text)))
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
        and all(i.get("accepted") is True for i in items)
        for sample, items in grouped.items()
    }


def count_successes(rows: list[dict], valid: dict) -> tuple:
    flags = [(r, candidate_success(r, valid.get(r.get("sample_id"), False))) for r in rows]
    by_cwe = {cwe: sum(ok for r, ok in flags if r.get("cwe") == cwe) for cwe in CWES}
    rounds = [sum(ok for r, ok in flags if r.get("repeat") == i) for i in (1, 2, 3)]
    return flags, sum(ok for _, ok in flags), by_cwe, rounds


def repair_threshold_met(total: int, by_cwe: dict) -> bool:
    return total >= 45 and all(by_cwe.get(cwe, 0) >= 12 for cwe in CWES)


def verify_repairs(repairs: dict, bundle_path, controls_path, controls: dict, bundle: dict) -> list:
    rows = repairs.get("rows") or []
    identities = [(r.get("sample_id"), r.get("repeat")) for r in rows]
    cases = {i[0] for i in identities}
    results = [
        check(
            "repairs.rows_unique_and_complete",
            len(rows) == REPAIR_CASES * REPAIR_ROUNDS
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
    results.append(
        check(
            "repairs.file_bindings",
            repairs.get("bundle_sha256") == file_hash(bundle_path)
            and repairs.get("controls_sha256") == file_hash(controls_path),
            "candidate bundle and control files match the recorded SHA-256",
        )
    )
    bundled = {(r.get("sample_id"), r.get("repeat")): r for r in bundle.get("rows") or []}
    bound = len(bundled) == len(bundle.get("rows") or [])
    for row in rows:
        source = bundled.get((row.get("sample_id"), row.get("repeat")), {})
        text = source.get("candidate_source")
        if text is not None:
            bound &= hashlib.sha256(text.encode()).hexdigest() == source.get("candidate_sha256")
        bound &= row.get("candidate_sha256") == source.get("candidate_sha256")
    results.append(check("repairs.candidate_sha_binding", bound, "bundle rows bind to results"))
    flags, total, by_cwe, rounds = count_successes(rows, valid)
    flagged = all(ok == r.get("success") for r, ok in flags)
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
        read["repairs"], paths["bundle"], paths["controls"], read["controls"], read["bundle"]
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
