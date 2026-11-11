"""Loopback API load (10 concurrency/100 requests) and bounded sequential live timing."""

import argparse
import asyncio
import json
import math
import os
import platform
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from _environment import ROOT, model_environment, require_conda


def quantiles(values):
    ordered = sorted(values)
    return {
        "count": len(values),
        "p50_ms": ordered[math.ceil(0.5 * len(values)) - 1],
        "p95_ms": ordered[math.ceil(0.95 * len(values)) - 1],
        "max_ms": ordered[-1],
    }


def api_load(directory):
    import httpx
    from app.core.config import Settings
    from app.core.database import build_engine
    from app.models import Base
    from app.worker.runner import run_once
    from pydantic import SecretStr

    token = secrets.token_urlsafe(32)
    settings = Settings(
        _env_file=None,
        data_dir=directory,
        database_url=f"sqlite+pysqlite:///{directory.as_posix()}/state.db",
        model_mode="fake",
        api_token=SecretStr(token),
    )
    engine = build_engine(settings)
    Base.metadata.create_all(engine)
    with socket.socket() as bound:
        bound.bind(("127.0.0.1", 0))
        port = bound.getsockname()[1]
    environment = {k: v for k, v in os.environ.items() if not k.startswith("AEGISFORGE_")}
    environment.update(
        AEGISFORGE_DATA_DIR=str(directory),
        AEGISFORGE_DATABASE_URL=settings.resolved_database_url,
        AEGISFORGE_MODEL_MODE="fake",
        AEGISFORGE_API_TOKEN=token,
    )
    with (directory / "api.log").open("wb") as output:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "app.main:app",
                "--app-dir",
                "backend",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--no-access-log",
            ],
            cwd=ROOT,
            env=environment,
            stdout=output,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        try:
            url = f"http://127.0.0.1:{port}"
            with httpx.Client(
                base_url=url,
                trust_env=False,
                timeout=5,
                headers={"Authorization": "Bearer " + token},
            ) as api:
                deadline = time.monotonic() + 30
                while True:
                    try:
                        if api.get("/health").status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    if time.monotonic() > deadline:
                        raise RuntimeError("Loopback API unavailable")
                    time.sleep(0.1)
                source = (
                    "from flask import request\ndef page():\n"
                    '    return "<p>"+request.args.get("name", "")+"</p>"\n'
                )
                response = api.post(
                    "/api/v1/artifacts?filename=sample.py&input_type=source",
                    content=source.encode(),
                )
                response.raise_for_status()
                artifact = response.json()["artifact"]["id"]

            async def submits():
                async with httpx.AsyncClient(
                    base_url=url,
                    trust_env=False,
                    timeout=30,
                    headers={"Authorization": "Bearer " + token},
                ) as client:

                    async def submit():
                        start = time.perf_counter()
                        response = await client.post(
                            "/api/v1/scans",
                            json={
                                "artifact_ids": [artifact],
                                "strategy": "hybrid",
                                "model_alias": "fake",
                            },
                        )
                        return {
                            "status": response.status_code,
                            "duration_ms": (time.perf_counter() - start) * 1000,
                            "id": response.json().get("scan", {}).get("id"),
                        }

                    return await asyncio.gather(*(submit() for _ in range(10)))

            submissions = asyncio.run(submits())

            async def work():
                for _ in range(10):
                    await run_once(engine, settings)

            asyncio.run(work())
            paths = [
                "/health",
                "/api/v1/capabilities",
                "/api/v1/workspace",
                "/api/v1/workspace/history",
                "/api/v1/scans",
            ]

            async def reads():
                gate = asyncio.Semaphore(10)
                async with httpx.AsyncClient(
                    base_url=url,
                    trust_env=False,
                    timeout=30,
                    headers={"Authorization": "Bearer " + token},
                ) as client:

                    async def read(i):
                        async with gate:
                            started = time.perf_counter()
                            response = await client.get(paths[i % len(paths)])
                            return {
                                "path": paths[i % len(paths)],
                                "status": response.status_code,
                                "duration_ms": (time.perf_counter() - started) * 1000,
                            }

                    return await asyncio.gather(*(read(i) for i in range(100)))

            rows = asyncio.run(reads())
            summary = quantiles([r["duration_ms"] for r in rows])
            errors = sum(r["status"] != 200 for r in rows)
            return {
                "mode": "real loopback HTTP; fake provider; isolated synthetic database",
                "concurrency": 10,
                "requests": 100,
                "latency": summary,
                "unexpected_errors": errors,
                "submissions": submissions,
                "passed": errors == 0
                and summary["p95_ms"] < 500
                and all(r["status"] == 202 for r in submissions),
                "observations": rows,
            }
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            engine.dispose()


def sequential_live(directory):
    from app.core.config import Settings
    from app.core.database import build_engine
    from app.main import create_app
    from app.models import Base
    from app.worker.runner import run_once
    from fastapi.testclient import TestClient
    from pydantic import SecretStr

    from evaluation.budget import ExperimentBudget
    from evaluation.experiment import BUDGET_PATH, request_json

    settings = Settings(
        _env_file=None,
        data_dir=directory,
        database_url=f"sqlite+pysqlite:///{directory.as_posix()}/state.db",
        api_token=SecretStr(secrets.token_urlsafe(32)),
        model_mode="real",
        daily_model_calls=1000,
    )
    app = create_app(settings)
    app.state.engine = build_engine(settings)
    Base.metadata.create_all(app.state.engine)
    budget = ExperimentBudget(BUDGET_PATH, 1000)
    source = (
        "from flask import request\ndef page():\n"
        '    return "<p>"+request.args.get("name", "")+"</p>"\n'
    )
    rows = []
    try:
        with TestClient(app) as api:
            api.headers["Authorization"] = "Bearer " + settings.api_token.get_secret_value()
            artifact = request_json(
                api,
                "post",
                "/api/v1/artifacts?filename=timing.py&input_type=source",
                content=source.encode(),
            )["artifact"]
            for i in range(5):
                item = request_json(
                    api,
                    "post",
                    "/api/v1/scans",
                    json={
                        "artifact_ids": [artifact["id"]],
                        "strategy": "hybrid",
                        "model_alias": "deepseek",
                    },
                )["scan"]
                started = time.perf_counter()
                asyncio.run(
                    run_once(app.state.engine, settings, budget.factory("performance-sequential"))
                )
                item = request_json(api, "get", f"/api/v1/scans/{item['id']}")["scan"]
                rows.append(
                    {
                        "sequence": i + 1,
                        "status": item["status"],
                        "analysis_complete": item["result"].get("analysis_complete"),
                        "service_ms": item["result"].get("service_ms"),
                        "wall_ms": (time.perf_counter() - started) * 1000,
                        "call_count": item["call_count"],
                        "error_code": item["error_code"],
                    }
                )
    finally:
        app.state.engine.dispose()
    return {
        "mode": "5 sequential actual product API/worker real model tasks; no candidate execution",
        "model": settings.deepseek_model,
        "input_bytes": len(source.encode()),
        "rows": rows,
        "passed": len(rows) == 5
        and all(r["analysis_complete"] and r["service_ms"] <= 120000 for r in rows),
        "budget": budget.summary(),
    }


def main():
    require_conda()
    sys.path[:0] = [str(ROOT), str(ROOT / "backend")]
    from evaluation.experiment import write_json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["api", "live"])
    args = parser.parse_args()
    if args.mode == "live":
        os.environ.update(model_environment())
    directory = ROOT / "data" / "m6-performance"
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / (args.mode + ".json")
    if target.exists():
        raise SystemExit("Result exists; refuse silently repeating a measurement or paid task.")
    work = Path(tempfile.mkdtemp(prefix=args.mode + "-", dir=directory))
    result = api_load(work) if args.mode == "api" else sequential_live(work)
    result["platform"] = {
        "os": platform.system(),
        "release": platform.release(),
        "python": platform.python_version(),
        "cpu": platform.processor(),
        "cpu_count": os.cpu_count(),
    }
    write_json(target, result)
    print(
        json.dumps(
            {
                "passed": result["passed"],
                "latency": result.get("latency"),
                "rows": result.get("rows"),
            },
            ensure_ascii=False,
        )
    )
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
