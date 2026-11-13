"""Integrity audit of the formal M6 records. Numeric thresholds are reported, never required.

Exit 0: the committed baseline files are complete, internally consistent and match the frozen
dataset (every metric is recomputed from the raw rows). This says nothing about whether the course
thresholds were met; a truthful record of a miss is a valid record. Use scripts/acceptance.py for
the strict numeric verdict. Exit 1: a file is missing, a count/flag altered, or a row lost.
No network, Docker, model call or credential is involved.
"""

import argparse
import json
import sys

from _environment import ROOT, require_conda


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
        # The audit itself reads the frozen records at run time (that is its job).
        samples = load_data("test")[0]["samples"]
        frozen = plan("test", 3)
    except Exception:  # noqa: BLE001 - an unreadable frozen set is reported as a failed check
        samples, frozen = None, None
    report = verify_all(args.results, samples, frozen)
    unmet = [item["id"] for item in report["requirements"] if not item["met"]]
    summary = {
        "scope": "formal M6 detection and repair records",
        "integrity_ok": report["ok"],
        "failed_checks": [c for c in report["checks"] if not c["ok"]],
        "checks": len(report["checks"]),
        "numeric_requirements_unmet": unmet,
        "note": "integrity is independent of the thresholds; see scripts/acceptance.py",
    }
    if args.output:
        write_json(args.output, {**summary, "report": report})
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
