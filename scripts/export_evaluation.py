"""Export source-free benchmark statistics and optional public synthetic candidate fixtures."""

import argparse
import csv
import io
import json
import re
import sys

from _environment import ROOT, model_environment, require_conda


def immutable_json(path, payload, writer):
    if path.exists():
        if json.loads(path.read_text(encoding="utf-8")) != payload:
            raise ValueError("Baseline evidence is immutable; use a separately named result")
        return
    writer(path, payload)


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

    immutable_json(target / "m6-detection-baseline.json", checked(summary), write_json)
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
    csv_path = target / "m6-detection-baseline.csv"
    csv_text = buffer.getvalue().replace("\r\n", "\n")
    if csv_path.exists():
        if csv_path.read_text(encoding="utf-8") != csv_text:
            raise ValueError("Baseline CSV is immutable")
    else:
        csv_path.write_text(csv_text, encoding="utf-8", newline="\n")
    if args.candidates:
        generated = json.loads((directory / "repair-generation.json").read_text(encoding="utf-8"))
        for row in generated["rows"]:
            path = directory / f"hybrid-{row['repeat']}-{row['sample_id']}" / "candidate.txt"
            if path.exists():
                row["candidate_source"] = path.read_text(encoding="utf-8")
        immutable_json(
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
            write_json,
        )
    performance = ROOT / "data/m6-performance"
    for name in ("api", "live", "boundary"):
        path = performance / f"{name}.json"
        if path.exists():
            immutable_json(
                target / f"m6-performance-{name}.json",
                checked(json.loads(path.read_text(encoding="utf-8"))),
                write_json,
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
            immutable_json(target / f"m6-{name}-audit-baseline.json", checked(payload), write_json)
    print("Exported checked synthetic evidence under evaluation/results.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
