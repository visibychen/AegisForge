"""M6-only orchestration. Frozen holdout labels never enter provider requests.

Every sample uses the actual upload API, task queue, worker, output validation and
merge. Independent synthetic databases avoid changing production rate limits. The
one experiment-wide SQLite ledger bounds all external requests, including retries.
Candidate execution is a separate, credential-free Docker-only phase.
"""

import asyncio
import hashlib
import json
import os
import platform
import secrets
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from evaluation.metrics import detection_threshold, evaluate, overlaps

ROOT = Path(__file__).resolve().parents[1]
RUN_ROOT = ROOT / "data" / "m6-runs"
BUDGET_PATH = ROOT / "data" / "m6-model-budget.sqlite"


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    key = os.environ.get("AEGISFORGE_DEEPSEEK_API_KEY", "")
    if key and key in payload:
        raise ValueError("Refusing credential output")
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(payload, encoding="utf-8", newline="\n")
    temporary.replace(path)


def load_data(split="test"):
    from evaluation.datasets import DEV, HOLDOUT, _load_split, validate

    errors, _ = validate()
    if errors:
        raise ValueError("Frozen data integrity failed")
    return _load_split(HOLDOUT if split == "test" else DEV)


def file_hash(path):
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def detection_fingerprint():
    files = []
    for directory in (
        "core",
        "parsers",
        "rules",
        "llm",
        "services",
        "worker",
        "schemas",
        "models",
        "api",
    ):
        files += sorted((ROOT / "backend/app" / directory).rglob("*.py"))
    return {p.relative_to(ROOT).as_posix(): file_hash(p) for p in files}


def plan(split="test", rounds=3):
    manifest, contents = load_data(split)
    controlled = json.loads(
        (ROOT / "samples/holdout/controlled_repairs.json").read_text(encoding="utf-8")
    )["samples"]
    return {
        "schema_version": "m6-experiment-1.0",
        "split": split,
        "samples": len(manifest["samples"]),
        "source": sum(r["kind"] == "source" for r in manifest["samples"]),
        "http": sum(r["kind"] == "http" for r in manifest["samples"]),
        "rounds": rounds,
        "rules_tasks": len(contents),
        "real_detection_tasks": 2 * rounds * len(contents),
        "registered_repairs": len(controlled) if split == "test" else 0,
        "minimum_calls_if_all_targets_detected": rounds
        * (2 * len(contents) + (2 * len(controlled) if split == "test" else 0)),
        "maximum_output_tokens_per_request": 4096,
        "input_note": (
            "At most 80000 normalized chars/8 chunks per product task; "
            "dry-run verifies dataset parsing. Actual tokens recorded; "
            "fees N/A without billing evidence."
        ),
        "human_review": manifest["provenance"]["human_review"],
        "label_note": (
            "AI-authored frozen labels, pending human review; provisional course benchmark, "
            "not independently adjudicated ground truth."
        ),
        "dataset_sha256": file_hash(ROOT / "samples/freeze.json"),
        "records_sha256": hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest(),
        "sample_hashes": {
            key: hashlib.sha256(text.encode()).hexdigest() for key, text in sorted(contents.items())
        },
    }


def prepare(name, split, rounds, workers, limit):
    from app.core.config import Settings

    directory = RUN_ROOT / name
    config = {
        **plan(split, rounds),
        "workers": workers,
        "call_limit": limit,
        "provider": "deepseek",
        "model": Settings(_env_file=None).deepseek_model,
        "temperature": 0,
        "thinking": "disabled",
        "seed": None,
        "detection_files": detection_fingerprint(),
    }
    if directory.joinpath("manifest.json").exists():
        previous = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        for key, value in config.items():
            if previous.get(key) != value:
                raise ValueError("Run configuration/code/data changed; refuse to mix results")
        return directory, previous
    config |= {
        "created_at": datetime.now(UTC).isoformat(),
        "code_sha": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "runtime": {
            "python": platform.python_version(),
            "os": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "cpu_count": os.cpu_count(),
        },
        "locks": {
            p: file_hash(ROOT / p)
            for p in (
                "environment.yml",
                "backend/requirements.lock",
                "backend/requirements-dev.lock",
                "frontend/package-lock.json",
            )
        },
        "execution": (
            "actual API/worker in process; isolated synthetic DB per sample; "
            "no uploaded code executes on host"
        ),
    }
    write_json(directory / "manifest.json", config)
    return directory, config


def job_directory(directory, strategy, repeat, sample_id):
    return directory / f"{strategy}-{repeat}-{sample_id}"


def settings_for(directory, real, model):
    from app.core.config import Settings
    from pydantic import SecretStr

    return Settings(
        _env_file=None,
        data_dir=directory,
        database_url=f"sqlite+pysqlite:///{directory.as_posix()}/state.db",
        api_token=SecretStr(secrets.token_urlsafe(32)),
        model_mode="real" if real else "fake",
        deepseek_model=model,
        daily_model_calls=1000,
    )


def request_json(api, method, path, **kwargs):
    response = getattr(api, method)(path, **kwargs)
    if response.status_code >= 400:
        from app.core.errors import DomainError

        code = response.json().get("error", {}).get("code", "EVALUATION_API_ERROR")
        raise DomainError(code, "实验接口未完成。", response.status_code)
    return response.json()


def run_detection(
    directory, config, budget, record, content, strategy, repeat, *, provider_factory=None
):
    from app.core.database import build_engine
    from app.main import create_app
    from app.models import Base
    from app.worker.runner import run_once
    from fastapi.testclient import TestClient

    job = job_directory(directory, strategy, repeat, record["id"])
    output = job / "detection.json"
    if output.exists():
        return json.loads(output.read_text(encoding="utf-8"))
    # Never silently repeat a partially paid job after a process interruption.
    if (job / "started.json").exists():
        row = {
            "sample_id": record["id"],
            "strategy": strategy,
            "repeat": repeat,
            "analysis_complete": False,
            "status": "interrupted",
            "error_code": "EXPERIMENT_INTERRUPTED",
            "findings": [],
        }
        write_json(output, row)
        return row
    job.mkdir(parents=True, exist_ok=True)
    write_json(job / "started.json", {"started_at": datetime.now(UTC).isoformat()})
    settings = settings_for(job, strategy != "rules", config["model"])
    app = create_app(settings)
    app.state.engine = build_engine(settings)
    Base.metadata.create_all(app.state.engine)  # migration acceptance is a separate actual test
    row = {
        "sample_id": record["id"],
        "strategy": strategy,
        "repeat": repeat,
        "findings": [],
        "analysis_complete": False,
    }
    start = time.perf_counter()
    try:
        with TestClient(app) as api:
            api.headers["Authorization"] = "Bearer " + settings.api_token.get_secret_value()
            began = time.perf_counter()
            artifact = request_json(
                api,
                "post",
                "/api/v1/artifacts?filename=sample."
                + ("py" if record["kind"] == "source" else "http")
                + "&input_type="
                + record["kind"],
                content=content.encode(),
            )["artifact"]
            row["upload_ms"] = (time.perf_counter() - began) * 1000
            scan = request_json(
                api,
                "post",
                "/api/v1/scans",
                json={
                    "artifact_ids": [artifact["id"]],
                    "strategy": strategy,
                    "model_alias": "fake" if strategy == "rules" else "deepseek",
                },
            )["scan"]
            ident = scan["id"]
            asyncio.run(
                run_once(app.state.engine, settings, provider_factory or budget.factory(job.name))
            )
            scan = request_json(api, "get", f"/api/v1/scans/{ident}")["scan"]
            findings = request_json(api, "get", f"/api/v1/scans/{ident}/findings?limit=100")[
                "findings"
            ]
            calls = request_json(api, "get", f"/api/v1/scans/{ident}/calls")["calls"]
            row |= {
                "scan_id": ident,
                "artifact_id": artifact["id"],
                "source_sha256": artifact["sha256"],
                "status": scan["status"],
                "error_code": scan["error_code"],
                "analysis_complete": scan["result"].get("analysis_complete", False),
                "service_ms": scan["result"].get("service_ms"),
                "coverage": scan["result"].get("coverage"),
                "receipt_digest": scan["receipt"].get("plan_digest"),
                "calls": calls,
                "findings": [
                    {
                        k: f[k]
                        for k in ("id", "cwe", "severity", "location", "sources", "evidence_status")
                    }
                    for f in findings
                ],
            }
    except Exception as error:
        row |= {"status": "error", "error_code": getattr(error, "code", "EXPERIMENT_INTERNAL")}
    finally:
        app.state.engine.dispose()
    row["wall_ms"] = (time.perf_counter() - start) * 1000
    write_json(output, row)
    return row


def detect(directory, config, budget, *, real=False):
    manifest, contents = load_data(config["split"])
    schedule = [
        (r, strategy, repeat)
        for strategy in (["rules", "llm", "hybrid"] if real else ["rules"])
        for repeat in (range(1, config["rounds"] + 1) if strategy != "rules" else [1])
        for r in manifest["samples"]
    ]
    # Fixed schedule; every failed or not-started job remains in the summaries.
    with ThreadPoolExecutor(max_workers=config["workers"]) as pool:
        pending = {
            pool.submit(
                run_detection, directory, config, budget, r, contents[r["id"]], strategy, repeat
            ): (r["id"], strategy, repeat)
            for r, strategy, repeat in schedule
        }
        for i, future in enumerate(as_completed(pending), 1):
            row = future.result()
            print(
                json.dumps(
                    {
                        "done": i,
                        "scheduled": len(schedule),
                        "sample": row["sample_id"],
                        "strategy": row["strategy"],
                        "repeat": row["repeat"],
                        "status": row.get("status"),
                        "calls_reserved": budget.summary()["reservations"],
                    }
                ),
                flush=True,
            )
            statuses = budget.summary()["statuses"]
            if (
                statuses.get("MODEL_AUTH_FAILED")
                or statuses.get("MODEL_BALANCE")
                or budget.summary()["reservations"] >= budget.limit
            ):
                for task in pending:
                    task.cancel()
                break
    return summarize(directory, config, budget)


def summarize(directory, config, budget):
    manifest, _ = load_data(config["split"])
    all_rows, groups = [], {}
    for strategy in ("rules", "llm", "hybrid"):
        groups[strategy] = []
        for repeat in [1] if strategy == "rules" else range(1, config["rounds"] + 1):
            rows = []
            for record in manifest["samples"]:
                path = job_directory(directory, strategy, repeat, record["id"]) / "detection.json"
                if path.exists():
                    rows.append(json.loads(path.read_text(encoding="utf-8")))
            all_rows.extend(rows)
            groups[strategy].append({"repeat": repeat, **evaluate(manifest["samples"], rows)})
    summary = {
        "schema_version": "m6-detection-summary-1.0",
        "manifest": config,
        "groups": groups,
        "hybrid_threshold": detection_threshold(groups["hybrid"]),
        "budget": budget.summary(),
        "records": all_rows,
        "human_review_pending": True,
    }
    write_json(directory / "detection-summary.json", summary)
    return summary


def generate_repairs(directory, config, budget):
    from app.core.database import build_engine
    from app.main import create_app
    from app.services.repairs import run_repair_once
    from fastapi.testclient import TestClient

    manifest, _ = load_data(config["split"])
    records = {r["id"]: r for r in manifest["samples"]}
    controlled = json.loads(
        (ROOT / "samples/holdout/controlled_repairs.json").read_text(encoding="utf-8")
    )["samples"]
    rows = []
    for repeat in range(1, config["rounds"] + 1):
        for case in controlled:
            ident = case["id"]
            job = job_directory(directory, "hybrid", repeat, ident)
            output = job / "repair.json"
            if output.exists():
                rows.append(json.loads(output.read_text(encoding="utf-8")))
                continue
            row = {
                "sample_id": ident,
                "cwe": case["cwe"],
                "repeat": repeat,
                "first_candidate": True,
                "success": False,
            }
            source = job / "detection.json"
            detection = json.loads(source.read_text(encoding="utf-8")) if source.exists() else {}
            targets = [f for f in detection.get("findings", []) if overlaps(records[ident], f)]
            if not targets:
                row["error_code"] = "TARGET_NOT_DETECTED"
            elif (job / "repair-started.json").exists():
                row["error_code"] = "EXPERIMENT_INTERRUPTED"
            else:
                write_json(
                    job / "repair-started.json", {"started_at": datetime.now(UTC).isoformat()}
                )
                settings = settings_for(job, True, config["model"])
                app = create_app(settings)
                app.state.engine = build_engine(settings)
                try:
                    with TestClient(app) as api:
                        api.headers["Authorization"] = (
                            "Bearer " + settings.api_token.get_secret_value()
                        )
                        item = request_json(
                            api,
                            "post",
                            "/api/v1/repairs",
                            headers={"Idempotency-Key": str(uuid4())},
                            json={
                                "finding_id": targets[0]["id"],
                                "source_sha256": detection["source_sha256"],
                                "model_alias": "deepseek",
                            },
                        )["repair"]
                        asyncio.run(
                            run_repair_once(app.state.engine, settings, budget.factory(job.name))
                        )
                        item = request_json(api, "get", f"/api/v1/repairs/{item['id']}")["repair"]
                        row |= {
                            "repair_id": item["id"],
                            "status": item["status"],
                            "error_code": item["error_code"],
                            "validation_status": item["validation_status"],
                            "checks": {
                                k: item["checks"].get(k)
                                for k in (
                                    "syntax",
                                    "patch",
                                    "roundtrip",
                                    "review",
                                    "delta",
                                    "impact",
                                    "contract",
                                    "patch_diagnostic",
                                )
                            },
                            "gates": item["gates"],
                            "calls": item["calls"],
                        }
                        if item["status"] == "candidate":
                            response = api.get(
                                f"/api/v1/repairs/{item['id']}/download?format=source"
                            )
                            response.raise_for_status()
                            key = settings.deepseek_api_key.get_secret_value()
                            if key and key in response.text:
                                raise ValueError("Candidate credential detected")
                            (job / "candidate.txt").write_text(
                                response.text, encoding="utf-8", newline="\n"
                            )
                            row["candidate_sha256"] = hashlib.sha256(
                                response.text.encode()
                            ).hexdigest()
                except Exception as error:
                    row["error_code"] = getattr(error, "code", "EXPERIMENT_INTERNAL")
                finally:
                    app.state.engine.dispose()
            write_json(output, row)
            rows.append(row)
            print(
                json.dumps(
                    {
                        "repair": ident,
                        "repeat": repeat,
                        "status": row.get("status"),
                        "error_code": row.get("error_code"),
                        "reservations": budget.summary()["reservations"],
                    }
                ),
                flush=True,
            )
    write_json(
        directory / "repair-generation.json",
        {
            "denominator": 18 * config["rounds"],
            "rows": rows,
            "budget": budget.summary(),
            "dynamic_pending": True,
        },
    )
    return rows
