"""Finding-level PLAN 7.3 scoring; failures remain in the scheduled denominator."""

from collections import Counter
from statistics import mean

CWES = ("CWE-79", "CWE-89", "CWE-78")


def ratio(a, b):
    return a / b if b else None


def scores(counts):
    tp, fp, fn = (counts.get(k, 0) for k in ("tp", "fp", "fn"))
    return {
        **{
            k: counts.get(k, 0)
            for k in ("tp", "fp", "fn", "safe", "safe_flagged", "tasks", "failed")
        },
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "safe_false_alarm_rate": ratio(counts.get("safe_flagged", 0), counts.get("safe", 0)),
        "task_failure_rate": ratio(counts.get("failed", 0), counts.get("tasks", 0)),
    }


def overlaps(record, finding):
    if finding.get("cwe") != record.get("cwe"):
        return False
    if record["kind"] == "http":
        return finding.get("location", {}).get("kind") == "http"
    loc = finding.get("location", {})
    start, end = record["lines"]
    return (
        loc.get("kind") == "source"
        and loc.get("start_line", 10**9) <= end
        and loc.get("end_line", 0) >= start
    )


def evaluate(records, rows):
    """One run/strategy. Missing results are failures, never silently excluded."""
    by_id = {row["sample_id"]: row for row in rows}
    if len(by_id) != len(rows):
        raise ValueError("duplicate sample result")
    groups = {kind: {cwe: Counter() for cwe in CWES} for kind in ("source", "http")}
    errors = []
    for record in records:
        row = by_id.get(record["id"], {})
        findings = row.get("findings", [])
        group = groups[record["kind"]]
        # Each prediction contributes once, including duplicates and unrelated CWEs.
        matched = False
        for finding in findings:
            cwe = finding["cwe"]
            if cwe not in group:
                raise ValueError("unknown CWE in result")
            if (
                not matched
                and record["label"] in {"vulnerable", "attack"}
                and overlaps(record, finding)
            ):
                group[cwe]["tp"] += 1
                matched = True
            else:
                group[cwe]["fp"] += 1
        if record["label"] in {"vulnerable", "attack"} and not matched:
            group[record["cwe"]]["fn"] += 1
        # Task/safe denominators are recorded once in the micro totals below.
        if (
            not row.get("analysis_complete", False)
            or not matched
            and record["label"] in {"vulnerable", "attack"}
            or findings
            and record["label"] in {"safe", "normal"}
        ):
            errors.append(
                {
                    "sample_id": record["id"],
                    "complete": row.get("analysis_complete", False),
                    "matched": matched,
                    "finding_count": len(findings),
                    "error_code": row.get("error_code"),
                }
            )
    result = {}
    for kind, per_cwe in groups.items():
        selected = [r for r in records if r["kind"] == kind]
        micro = sum(per_cwe.values(), Counter())
        micro["tasks"] = len(selected)
        for r in selected:
            row = by_id.get(r["id"], {})
            micro["failed"] += not row.get("analysis_complete", False)
            if r["label"] in {"safe", "normal"}:
                micro["safe"] += 1
                micro["safe_flagged"] += bool(row.get("findings"))
        metrics = {cwe: scores(counts) for cwe, counts in per_cwe.items()}
        result[kind] = {
            "micro": scores(micro),
            "per_cwe": metrics,
            "macro": {
                key: mean(values)
                if len(values := [m[key] for m in metrics.values() if m[key] is not None])
                == len(CWES)
                else None
                for key in ("precision", "recall", "f1")
            },
        }
    return {"metrics": result, "errors": errors, "complete": len(rows) == len(records)}


def detection_threshold(rounds):
    if len(rounds) != 3:
        return {"passed": False, "reason": "three complete scheduled rounds required"}

    def average(kind, key):
        values = [r["metrics"][kind]["micro"][key] for r in rounds]
        return mean(values) if all(v is not None for v in values) else None

    precision, recall, http_f1 = (
        average("source", "precision"),
        average("source", "recall"),
        average("http", "f1"),
    )
    per_cwe = {
        cwe: mean(r["metrics"]["source"]["per_cwe"][cwe]["recall"] or 0 for r in rounds)
        for cwe in CWES
    }
    passed = (
        all(r["complete"] for r in rounds)
        and precision is not None
        and precision >= 0.85
        and recall is not None
        and recall >= 0.85
        and http_f1 is not None
        and http_f1 >= 0.85
        and all(value >= 0.8 for value in per_cwe.values())
    )
    return {
        "passed": passed,
        "source_mean_precision": precision,
        "source_mean_recall": recall,
        "source_per_cwe_mean_recall": per_cwe,
        "http_mean_f1": http_f1,
        "rounds": rounds,
    }
