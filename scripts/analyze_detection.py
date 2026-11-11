"""Zero-cost false-positive attribution over the committed detection baseline (post-hoc).

Reads evaluation/results/m6-detection-baseline.json (never modified) and classifies every reported
finding as a true positive or the kind of false positive it is, grouped by engine agreement, CWE and
evidence status. The counterfactual table asks "what would precision/recall have been under policy
X"; it is exploratory because the holdout labels were already seen. Nothing here changes how
findings are produced or filtered, and no model call is made. A policy can only be adopted after it
is justified on the development split, and any later holdout figure must be called post-hoc.
"""

import argparse
import json
import sys
from collections import Counter

from _environment import ROOT, require_conda

POLICIES = {
    "all_findings": lambda f: True,
    "agreed_by_rule_and_llm_only": lambda f: set(f.get("sources", [])) == {"rule", "llm"},
    "drop_llm_only": lambda f: set(f.get("sources", [])) != {"llm"},
    "drop_rule_only": lambda f: set(f.get("sources", [])) != {"rule"},
}


def classify(records, rows, overlaps):
    """One outcome per reported finding, using the same one-to-one rule as the formal scoring."""
    by_id = {row["sample_id"]: row for row in rows}
    result = []
    for record in records:
        positive = record["label"] in {"vulnerable", "attack"}
        matched = False
        for finding in by_id.get(record["id"], {}).get("findings", []):
            if not positive:
                outcome = "fp_on_safe_sample"
            elif overlaps(record, finding) and not matched:
                outcome, matched = "tp", True
            elif overlaps(record, finding):
                outcome = "fp_duplicate_of_matched"
            elif finding["cwe"] == record["cwe"]:
                outcome = "fp_wrong_location"
            else:
                outcome = "fp_wrong_cwe"
            result.append(
                {
                    "kind": record["kind"],
                    "outcome": outcome,
                    "cwe": finding["cwe"],
                    "sources": "+".join(sorted(finding.get("sources", []))) or "unknown",
                    "evidence_status": finding.get("evidence_status"),
                }
            )
    return result


def attribute(summary, samples, evaluate, overlaps):
    report = {}
    records = summary["records"]
    for strategy in ("rules", "llm", "hybrid"):
        rounds = []
        for repeat in sorted({r["repeat"] for r in records if r["strategy"] == strategy}):
            rows = [r for r in records if r["strategy"] == strategy and r["repeat"] == repeat]
            found = [c for c in classify(samples, rows, overlaps) if c["kind"] == "source"]
            policies = {}
            for name, keep in POLICIES.items():
                kept = [
                    {**r, "findings": [f for f in r.get("findings", []) if keep(f)]} for r in rows
                ]
                micro = evaluate(samples, kept)["metrics"]["source"]["micro"]
                policies[name] = {k: micro[k] for k in ("tp", "fp", "fn", "precision", "recall")}
            rounds.append(
                {
                    "repeat": repeat,
                    "outcomes_by_sources": _count(found, ("sources", "outcome")),
                    "outcomes_by_cwe": _count(found, ("cwe", "outcome")),
                    "outcomes_by_evidence_status": _count(found, ("evidence_status", "outcome")),
                    "counterfactual_policies": policies,
                }
            )
        report[strategy] = rounds
    return report


def _count(items, keys):
    table = Counter(" / ".join(str(item[k]) for k in keys) for item in items)
    return dict(sorted(table.items()))


def main():
    require_conda()
    sys.path[:0] = [str(ROOT), str(ROOT / "backend")]
    from evaluation.experiment import load_data, write_json
    from evaluation.metrics import evaluate, overlaps

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--summary",
        type=lambda p: ROOT / p,
        default=ROOT / "evaluation/results/m6-detection-baseline.json",
    )
    parser.add_argument("--output", type=lambda p: ROOT / p, help="outside evaluation/results")
    args = parser.parse_args()
    frozen = (ROOT / "evaluation/results").resolve()
    if args.output and frozen in (args.output.resolve(), *args.output.resolve().parents):
        parser.error("Refusing to write into the frozen results directory")
    summary = json.loads(args.summary.read_text(encoding="utf-8"))
    samples = load_data("test")[0][
        "samples"
    ]  # labels are read here, at run time, as the scorer does
    report = {
        "kind": "post-hoc exploratory attribution; holdout labels were already seen",
        "source": args.summary.name,
        "strategies": attribute(summary, samples, evaluate, overlaps),
    }
    if args.output:
        write_json(args.output, report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
