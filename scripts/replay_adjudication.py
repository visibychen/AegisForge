"""Zero-call POST-HOC replay of stored intervals through current rules/merge/adjudication.

Legacy public records have no model prose or individual pre-merge contributors. Evidence is
reconstructed from the stored interval and frozen synthetic source. This is not raw-wire replay,
fresh model inference, an independent holdout or course acceptance. Original records stay intact.
"""

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from uuid import UUID

from _environment import ROOT, require_conda


def replay(records, samples, contents):
    from app.parsers.inputs import parse_input
    from app.rules.detector import detect
    from app.schemas.contracts import Finding
    from app.services.adjudicate import adjudicate
    from app.services.merge import merge_findings

    by_id = {s["id"]: s for s in samples}
    output, decisions = [], []
    for old in records:
        sample = by_id[old["sample_id"]]
        text = contents[sample["id"]]
        parsed = parse_input(sample["kind"], text)
        identity = UUID(old.get("artifact_id") or "00000000-0000-0000-0000-000000000000")
        candidates = []
        strategy = old.get("strategy", "hybrid")
        complete = bool(old.get("analysis_complete"))
        if strategy != "llm":
            rules = detect(identity, sample["kind"], parsed)
            candidates.extend(rules.findings)
            complete &= not rules.truncated
        if strategy != "rules":
            for found in old.get("findings", []):
                if "llm" not in found.get("sources", []):
                    continue
                location = {**found["location"], "artifact_id": str(identity)}
                evidence = (
                    "\n".join(
                        parsed.content.split("\n")[
                            location["start_line"] - 1 : location["end_line"]
                        ]
                    )
                    if sample["kind"] == "source"
                    else parsed.fields[location["field"]]
                )
                candidates.append(
                    Finding(
                        category={"CWE-79": "xss", "CWE-89": "sqli", "CWE-78": "cmdi"}[
                            found["cwe"]
                        ],
                        cwe=found["cwe"],
                        severity=found.get("severity", "high"),
                        location=location,
                        evidence=evidence[:4000] or "[REDACTED]",
                        evidence_truncated=len(evidence) > 4000,
                        explanation="Stored interval replay; original model prose unavailable",
                        recommendation="Review",
                        sources=["llm"],
                        evidence_status=found.get("evidence_status", "potential"),
                    )
                )
        entries = merge_findings(candidates, {str(identity): parsed})
        active, audit = adjudicate(entries, {str(identity): parsed})
        output.append(
            {
                "sample_id": sample["id"],
                "strategy": strategy,
                "repeat": old.get("repeat", 1),
                "analysis_complete": complete,
                "status": old.get("status"),
                "error_code": old.get("error_code"),
                "findings": [
                    {
                        k: e["finding"][k]
                        for k in (
                            "cwe",
                            "severity",
                            "location",
                            "sources",
                            "evidence_status",
                        )
                    }
                    for e in active
                ],
            }
        )
        decisions.append(
            {
                "sample_id": sample["id"],
                "repeat": old.get("repeat", 1),
                "strategy": strategy,
                "raw_candidates": len(candidates),
                "merged": len(entries),
                "kept": audit["kept"],
                "refuted": audit["refuted"],
                "by_criterion": audit["by_criterion"],
            }
        )
    return output, decisions


def main():
    require_conda()
    sys.path[:0] = [str(ROOT), str(ROOT / "backend")]
    from evaluation.experiment import detection_fingerprint, file_hash, load_data, write_json
    from evaluation.metrics import evaluate

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="evaluation/results/m6-detection-baseline.json")
    parser.add_argument("--split", choices=["dev", "test"], default="test")
    parser.add_argument("--output", default="data/m6-opus-offline.json")
    args = parser.parse_args()
    target = ROOT / args.output
    if not target.resolve().is_relative_to((ROOT / "data").resolve()):
        parser.error("Replay output must stay in ignored data; reviewed publication is separate")
    source = ROOT / args.input
    data = json.loads(source.read_text(encoding="utf-8"))
    manifest, contents = load_data(args.split)
    arms = data.get("arms") or {"baseline": data}
    groups = {}
    for arm, value in arms.items():
        grouped = defaultdict(list)
        for row in value["records"]:
            grouped[(row.get("strategy", "hybrid"), row.get("repeat", 1))].append(row)
        for (strategy, repeat), rows in grouped.items():
            selected_ids = {r["sample_id"] for r in rows}
            selected = [s for s in manifest["samples"] if s["id"] in selected_ids]
            new_rows, decisions = replay(rows, selected, contents)
            groups[f"{arm}/{strategy}/{repeat}"] = {
                "before": evaluate(selected, rows),
                "after": evaluate(selected, new_rows),
                "decisions": decisions,
                "records": new_rows,
            }
    result = {
        "scope": "post-hoc legacy-interval reconstruction; not independent acceptance",
        "input_sha256": file_hash(source),
        "split": args.split,
        "dataset_sha256": hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest(),
        "runtime_files": detection_fingerprint(),
        "external_model_calls": 0,
        "course_acceptance_evaluated": False,
        "human_review": "pending",
        "groups": groups,
        "limitations": (
            "Legacy merged intervals lack original contributor ranges/prose; no fresh LLM run"
        ),
    }
    write_json(target, result)
    print(
        json.dumps(
            {
                key: {
                    "before": v["before"]["metrics"]["source"]["micro"],
                    "after": v["after"]["metrics"]["source"]["micro"],
                }
                for key, v in groups.items()
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
