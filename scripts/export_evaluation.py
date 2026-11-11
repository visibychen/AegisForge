"""Export source-free benchmark statistics and optional public synthetic candidate fixtures."""

import argparse
import csv
import io
import json
import re
import sys

from _environment import ROOT, model_environment, require_conda


def main():
    require_conda()
    sys.path[:0] = [str(ROOT), str(ROOT / "backend")]
    from evaluation.experiment import write_json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", default="baseline-2026-11-11")
    parser.add_argument("--candidates", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,70}", args.run):
        parser.error("Invalid run name")
    directory = ROOT / "data/m6-runs" / args.run
    target = ROOT / "evaluation/results"
    target.mkdir(parents=True, exist_ok=True)
    summary = json.loads((directory / "detection-summary.json").read_text(encoding="utf-8"))
    # This exact scan reads the OS credential into memory only; never outputs it.
    key = model_environment().get("AEGISFORGE_DEEPSEEK_API_KEY", "")

    def checked(payload):
        if key and key in json.dumps(payload, ensure_ascii=False):
            raise ValueError("Refusing credential publication")
        return payload

    write_json(target / "m6-detection-baseline.json", checked(summary))
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(
        [
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
    )
    for strategy, rounds in summary["groups"].items():
        for repeat in rounds:
            for kind in ("source", "http"):
                row = repeat["metrics"][kind]["micro"]
                writer.writerow(
                    [
                        strategy,
                        repeat["repeat"],
                        kind,
                        *[
                            row.get(k)
                            for k in (
                                "tp",
                                "fp",
                                "fn",
                                "precision",
                                "recall",
                                "f1",
                                "tasks",
                                "failed",
                            )
                        ],
                    ]
                )
    (target / "m6-detection-baseline.csv").write_text(
        buffer.getvalue(), encoding="utf-8", newline=""
    )
    if args.candidates:
        generated = json.loads((directory / "repair-generation.json").read_text(encoding="utf-8"))
        for row in generated["rows"]:
            path = directory / f"hybrid-{row['repeat']}-{row['sample_id']}" / "candidate.txt"
            if path.exists():
                row["candidate_source"] = path.read_text(encoding="utf-8")
        write_json(
            target / "m6-baseline-candidates.json",
            checked(
                {
                    "scope": (
                        "public synthetic fixed-sample candidates only; "
                        "never import or execute on host"
                    ),
                    "baseline_manifest": summary["manifest"],
                    **generated,
                }
            ),
        )
    performance = ROOT / "data/m6-performance"
    for name in ("api", "live"):
        path = performance / f"{name}.json"
        if path.exists():
            write_json(
                target / f"m6-performance-{name}.json",
                checked(json.loads(path.read_text(encoding="utf-8"))),
            )
    for name in ("python", "npm"):
        path = ROOT / f"data/m6-{name}-audit.json"
        if path.exists():
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
            if name == "npm":
                payload = {
                    "method": "npm audit --json",
                    "metadata": payload.get("metadata"),
                    "vulnerabilities": payload.get("vulnerabilities"),
                    "error": payload.get("error"),
                }
            write_json(target / f"m6-{name}-audit-baseline.json", checked(payload))
    print("Exported checked synthetic evidence under evaluation/results.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
