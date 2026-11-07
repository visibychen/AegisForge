"""Bounded live integration demo using development samples only; never a benchmark."""

import argparse
import asyncio
import importlib.util
import json
import os
import secrets
import sys
import tempfile
import time
from pathlib import Path

from _environment import ROOT, model_environment, require_conda


def main():
    require_conda()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, choices=(1, 3), default=3)
    args = parser.parse_args()
    os.environ.update(model_environment())
    if not os.environ.get("AEGISFORGE_DEEPSEEK_API_KEY"):
        raise SystemExit("Configure AEGISFORGE_DEEPSEEK_API_KEY in the environment first.")
    sys.path.insert(0, str(ROOT / "backend"))
    from alembic import command
    from alembic.config import Config
    from app.core.config import Settings
    from app.core.database import build_engine
    from app.main import create_app
    from app.worker.runner import run_once
    from fastapi.testclient import TestClient
    from pydantic import SecretStr

    spec = importlib.util.spec_from_file_location("aegis_dev", ROOT / "evaluation" / "datasets.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manifest, contents = module.load_dev_samples()
    cases = [
        next(
            record
            for record in manifest["samples"]
            if record["kind"] == "source"
            and record["label"] == "vulnerable"
            and record["cwe"] == cwe
        )
        for cwe in ("CWE-79", "CWE-89", "CWE-78")
    ][: args.limit]
    (ROOT / "data").mkdir(exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="m3-live-", dir=ROOT / "data"))
    database_url = f"sqlite+pysqlite:///{directory.as_posix()}/demo.db"
    os.environ["AEGISFORGE_DATA_DIR"] = str(directory)
    os.environ["AEGISFORGE_DATABASE_URL"] = database_url
    command.upgrade(Config(str(ROOT / "backend" / "alembic.ini")), "head")
    settings = Settings(
        _env_file=None,
        data_dir=directory,
        database_url=database_url,
        api_token=SecretStr(secrets.token_urlsafe(32)),
        model_mode="real",
        max_model_calls=4,
        model_output_tokens=2048,
    )
    app = create_app(settings)
    engine = build_engine(settings)
    app.state.engine = engine
    report = {
        "provider": "deepseek",
        "model": settings.deepseek_model,
        "scope": "development integration demo, not holdout evaluation",
        "worker_mode": "in_process",
        "cases": [],
    }
    try:
        with TestClient(app) as api:
            api.headers["Authorization"] = "Bearer " + settings.api_token.get_secret_value()
            for case in cases:
                uploaded = api.post(
                    "/api/v1/artifacts?filename=demo.py&input_type=source",
                    content=contents[case["id"]].encode(),
                )
                uploaded.raise_for_status()
                artifact = uploaded.json()["artifact"]
                if artifact["chunk_count"] != 1:
                    raise SystemExit("Live demo only permits one chunk per sample.")
                created = api.post(
                    "/api/v1/scans",
                    json={
                        "artifact_ids": [artifact["id"]],
                        "strategy": "hybrid",
                        "model_alias": "deepseek",
                    },
                )
                created.raise_for_status()
                scan_id = created.json()["scan"]["id"]
                started = time.monotonic()
                asyncio.run(run_once(engine, settings))
                scan = api.get(f"/api/v1/scans/{scan_id}").json()["scan"]
                findings = api.get(f"/api/v1/scans/{scan_id}/findings").json()["findings"]
                calls = api.get(f"/api/v1/scans/{scan_id}/calls").json()["calls"]
                llm_cwes = sorted({f["cwe"] for f in findings if "llm" in f["sources"]})
                result = {
                    "sample_id": case["id"],
                    "expected_cwe": case["cwe"],
                    "sha256": artifact["sha256"],
                    "status": scan["status"],
                    "error_code": scan["error_code"],
                    "llm_cwes": llm_cwes,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "calls": calls,
                    "prompt_version": scan["prompt_version"],
                    "rule_version": scan["rule_version"],
                }
                result["passed"] = scan["status"] == "completed" and case["cwe"] in llm_cwes
                report["cases"].append(result)
                print(
                    json.dumps(
                        {k: result[k] for k in ("sample_id", "status", "error_code", "passed")}
                    ),
                    flush=True,
                )
    finally:
        engine.dispose()
    report["passed"] = all(case["passed"] for case in report["cases"])
    target = directory / "summary.json"
    payload = json.dumps(report, ensure_ascii=False, indent=2)
    if settings.deepseek_api_key.get_secret_value() in payload:
        raise SystemExit("Refusing to save a summary containing credentials.")
    target.write_text(payload + "\n", encoding="utf-8", newline="\n")
    print("Sanitized summary:", target.relative_to(ROOT))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
