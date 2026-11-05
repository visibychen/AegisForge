"""Sample-level rule baseline on the DEV split only (never the holdout).

    python evaluation/dev_rules_report.py            # prints a JSON summary to stdout

A vulnerable source sample counts as detected when a finding of its CWE intersects the
labelled lines; a safe sample is a false positive when any finding of the family CWE exists.
HTTP attacks count when a finding of their CWE exists; any finding on a normal request is a
false positive. This is a development aid, not the PLAN 7.3 experiment.
"""

import json
import sys
from collections import Counter
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(ROOT / "evaluation")]

from app.core.errors import DomainError  # noqa: E402
from app.parsers.inputs import parse_input  # noqa: E402
from app.rules.detector import detect  # noqa: E402
from datasets import load_dev_samples  # noqa: E402


def main() -> int:
    manifest, contents = load_dev_samples()
    families = json.loads((ROOT / "samples/dev/families.json").read_text(encoding="utf-8"))
    family_cwe = {family["id"]: family["cwe"] for family in families["families"]}
    tally: Counter = Counter()
    misses: list[str] = []
    for record in manifest["samples"]:
        cwe = family_cwe[record["family"]]
        try:
            parsed = parse_input(record["kind"], contents[record["id"]])
            findings = detect(uuid4(), record["kind"], parsed).findings
        except DomainError as exc:
            tally[(record["kind"], cwe, "input_rejected")] += 1
            misses.append(f"{record['id']}: rejected {exc.code}")
            continue
        relevant = [f for f in findings if f.cwe == cwe]
        if record["label"] == "vulnerable":
            start, end = record["lines"]
            hit = any(
                f.location.start_line <= end and f.location.end_line >= start for f in relevant
            )
        elif record["label"] == "attack":
            hit = bool(relevant)
        else:
            hit = bool(findings if record["kind"] == "http" else relevant)
        positive = record["label"] in {"vulnerable", "attack"}
        outcome = ("TP" if hit else "FN") if positive else ("FP" if hit else "TN")
        tally[(record["kind"], cwe, outcome)] += 1
        if outcome in {"FN", "FP"}:
            misses.append(f"{record['id']}: {outcome}")
    summary = {
        "split": "dev",
        "note": "development aid only; holdout is never read here",
        "counts": {" / ".join(key): value for key, value in sorted(tally.items())},
        "errors": misses,
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
