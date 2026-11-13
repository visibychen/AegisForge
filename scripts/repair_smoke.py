"""M4 development acceptance: Docker controls/adversarial probes, or bounded live DeepSeek.

No holdout samples, labels or test code are sent to a model. Candidate execution is Docker-only.
"""

import argparse
import asyncio
import importlib.util
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path
from uuid import uuid4

from _environment import ROOT, model_environment, require_conda


def development():
    spec = importlib.util.spec_from_file_location("aegis_dev", ROOT / "evaluation/datasets.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_dev_samples()[1]


def controls(settings, contents):
    from app.validation.registry import load_cases
    from app.validation.runner import run_container

    results = []
    for case in load_cases():
        for suffix in ("V", "S"):
            source = contents[case["sample_id"][:-1] + suffix]
            result = run_container(settings, source, case)
            security = [t for t in result.get("tests", []) if t["name"].startswith("security_")]
            accepted = (
                result["status"] == "passed"
                if suffix == "S"
                else result["status"] == "failed"
                and any(not t["passed"] for t in security)
                and result.get("tests", [{}])[0].get("passed") is True
            )
            row = {"case": case["id"], "control": suffix, **result, "accepted": accepted}
            results.append(row)
            print(json.dumps(row), flush=True)
    case = next(c for c in load_cases() if c["id"] == "cmdi-01")
    probes = {
        "forged_stdout": "import os\nprint('{\"passed\": true}', flush=True)\nos._exit(0)\n",
        "driver_signal": "import os, signal\nos.kill(os.getppid(), signal.SIGSTOP)\n",
        "infinite_loop": "while True:\n    pass\n",
        "hardcoded_business": (
            "from flask import Flask, jsonify\napp=Flask(__name__)\n"
            '@app.route("/ping")\ndef ping():\n    return jsonify(reachable=True)\n'
        ),
        "fifo_log": 'import os\nos.mkfifo("/tmp/ping.log")\n'
        + contents[case["sample_id"][:-1] + "S"],
    }
    for name, source in probes.items():
        result = run_container(settings, source, case)
        row = {"probe": name, **result, "accepted": result["status"] != "passed"}
        results.append(row)
        print(json.dumps(row), flush=True)
    return results


def live(settings, directory, contents):
    from alembic import command
    from alembic.config import Config
    from app.main import create_app
    from app.services.repairs import run_repair_once
    from app.validation.registry import load_cases
    from app.validation.runner import validate_one
    from app.worker.runner import run_once
    from fastapi.testclient import TestClient

    os.environ["AEGISFORGE_DATA_DIR"] = str(directory)
    os.environ["AEGISFORGE_DATABASE_URL"] = settings.resolved_database_url
    command.upgrade(Config(str(ROOT / "backend/alembic.ini")), "head")
    app = create_app(settings)
    results = []
    with TestClient(app) as api:
        api.headers["Authorization"] = "Bearer " + settings.api_token.get_secret_value()
        for case in load_cases():
            response = api.post(
                "/api/v1/artifacts?filename=controlled.py&input_type=source",
                content=contents[case["sample_id"]].encode(),
            )
            response.raise_for_status()
            artifact = response.json()["artifact"]
            response = api.post(
                "/api/v1/scans",
                json={
                    "artifact_ids": [artifact["id"]],
                    "strategy": "hybrid",
                    "model_alias": "deepseek",
                },
            )
            response.raise_for_status()
            scan_id = response.json()["scan"]["id"]
            asyncio.run(run_once(app.state.engine, settings))
            findings = api.get(f"/api/v1/scans/{scan_id}/findings").json()["findings"]
            scan = api.get(f"/api/v1/scans/{scan_id}").json()["scan"]
            wanted = {"xss-01": "CWE-79", "sqli-01": "CWE-89", "cmdi-01": "CWE-78"}[case["id"]]
            finding = next(
                (f for f in findings if f["cwe"] == wanted and "llm" in f["sources"]), None
            )
            if not finding:
                results.append(
                    {"case": case["id"], "accepted": False, "error": "MODEL_TARGET_MISSING"}
                )
                continue
            response = api.post(
                "/api/v1/repairs",
                headers={"Idempotency-Key": str(uuid4())},
                json={
                    "finding_id": finding["id"],
                    "source_sha256": artifact["sha256"],
                    "model_alias": "deepseek",
                },
            )
            response.raise_for_status()
            ident = response.json()["repair"]["id"]
            asyncio.run(run_repair_once(app.state.engine, settings))
            item = api.get(f"/api/v1/repairs/{ident}").json()["repair"]
            if item["status"] == "candidate":
                response = api.post(f"/api/v1/repairs/{ident}/validate")
                response.raise_for_status()
                validate_one(app.state.engine, settings, ident)
                item = api.get(f"/api/v1/repairs/{ident}").json()["repair"]
            row = {
                "case": case["id"],
                "repair_id": ident,
                "scan_id": scan_id,
                "analysis": {
                    "status": scan["status"],
                    "analysis_complete": scan["result"].get("analysis_complete"),
                    "detection_call_count": scan["call_count"],
                    "llm_cwes": sorted({f["cwe"] for f in findings if "llm" in f["sources"]}),
                },
                "status": item["status"],
                "error_code": item["error_code"],
                "validation_status": item["validation_status"],
                "contract": item["checks"].get("contract"),
                "gates": item["gates"],
                "dynamic": item["dynamic"],
                "calls": item["calls"],
                "accepted": item["validation_status"] == "passed",
            }
            results.append(row)
            print(
                json.dumps({k: row[k] for k in ("case", "status", "error_code", "accepted")}),
                flush=True,
            )
    return results


def main():
    require_conda()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["controls", "live"])
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT / "backend"))
    from app.core.config import Settings
    from pydantic import SecretStr

    if args.mode == "live":
        os.environ.update(model_environment())
    ROOT.joinpath("data").mkdir(exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="m4-" + args.mode + "-", dir=ROOT / "data"))
    settings = Settings(
        _env_file=None,
        data_dir=directory,
        database_url=f"sqlite+pysqlite:///{directory.as_posix()}/aegisforge.db",
        model_mode="real" if args.mode == "live" else "fake",
        api_token=SecretStr(secrets.token_urlsafe(32)),
        max_model_calls=12,
        daily_model_calls=12,
    )
    if args.mode == "live" and not settings.valid_model_key:
        raise SystemExit("Configure the model key in the OS environment first.")
    contents = development()
    rows = (
        controls(settings, contents)
        if args.mode == "controls"
        else live(settings, directory, contents)
    )
    report = {
        "scope": "M4 development acceptance; not holdout evaluation",
        "mode": args.mode,
        "model": settings.deepseek_model if args.mode == "live" else None,
        "passed": bool(rows) and all(r["accepted"] for r in rows),
        "results": rows,
    }
    if args.mode == "live":
        report["external_call_count"] = sum(
            row.get("analysis", {}).get("detection_call_count", 0) + len(row.get("calls", []))
            for row in rows
        )
        report["worker_mode"] = "in_process; candidate execution in Docker only"
    payload = json.dumps(report, ensure_ascii=False, indent=2)
    key = settings.deepseek_api_key.get_secret_value()
    if key and key in payload:
        raise SystemExit("Refusing to save credentials.")
    (directory / "summary.json").write_text(payload + "\n", encoding="utf-8")
    print("Sanitized summary:", directory.relative_to(ROOT) / "summary.json")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
