"""Strict M6 numeric acceptance for the core formal experiments.

Exit 0 only if (1) the records pass the integrity audit and (2) every threshold below is met on
the recomputed numbers: hybrid source precision/recall >= 0.85 and each CWE recall >= 0.80 (mean of
the three rounds), HTTP F1 >= 0.85, repairs >= 45/54 with >= 12/18 per CWE, and the AI-authored
labels human-reviewed. Exit 1: records are valid but a threshold is not met. Exit 2: the records
themselves are incomplete or altered, so no verdict is given. Thresholds are never lowered, a best
round is never selected, and failed denominators are never removed.

Not evaluated here (their own recorded evidence is listed, not recomputed): performance, coverage,
dependency audits, resource probes and browser runs.
"""

import argparse
import json
import sys

from _environment import ROOT, require_conda

RECORDED_ONLY = (
    "m6-performance-api.json",
    "m6-performance-live.json",
    "m6-performance-boundary.json",
    "m6-resources-baseline.json",
    "m6-browsers-baseline.json",
)


def main():
    require_conda()
    sys.path[:0] = [str(ROOT), str(ROOT / "backend")]
    from evaluation.experiment import load_data, plan, write_json
    from evaluation.gate import RESULTS, verify_all

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=lambda p: ROOT / p, default=RESULTS)
    parser.add_argument("--output", type=lambda p: ROOT / p)
    args = parser.parse_args()
    try:
        samples = load_data("test")[0]["samples"]
        frozen = plan("test", 3)
    except Exception:  # noqa: BLE001 - reported as an integrity failure below
        samples, frozen = None, None
    report = verify_all(args.results, samples, frozen)
    recorded = {}
    for name in RECORDED_ONLY:
        path = args.results / name
        if path.is_file():
            recorded[name] = {"recorded_passed": json.loads(path.read_text("utf-8")).get("passed")}
    unmet = [item for item in report["requirements"] if not item["met"]]
    verdict = (
        "records_invalid"
        if not report["ok"]
        else "accepted"
        if report["requirements"] and not unmet
        else "not_accepted"
    )
    result = {
        "verdict": verdict,
        "integrity_ok": report["ok"],
        "failed_checks": [c for c in report["checks"] if not c["ok"]],
        "requirements": report["requirements"],
        "unmet": [item["id"] for item in unmet],
        "recorded_not_recomputed": recorded,
    }
    if args.output:
        write_json(args.output, result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return {"accepted": 0, "not_accepted": 1, "records_invalid": 2}[verdict]


if __name__ == "__main__":
    raise SystemExit(main())
