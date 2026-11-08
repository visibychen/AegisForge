"""Host-side Docker orchestrator; only the separately launched trusted runner imports it."""

import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select

from app.core.errors import DomainError
from app.models import Artifact, Repair
from app.services.artifacts import load_artifact
from app.services.queue import transaction
from app.validation.registry import ROOT, match_case

IMAGE = "aegisforge-validator:m4"


def command(image_id, name, case, source):
    if not image_id.startswith("sha256:") or len(image_id) != 71:
        raise DomainError("VALIDATOR_IMAGE", "固定验证镜像不可用。", 503)
    return [
        "docker",
        "run",
        "--name",
        name,
        "--network",
        "none",
        "--user",
        "65532:65532",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--cpus",
        "1",
        "--memory",
        "512m",
        "--memory-swap",
        "512m",
        "--pids-limit",
        "64",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=128m,mode=1777",
        "--log-driver",
        "none",
        "--mount",
        f"type=bind,source={source},target=/candidate.py,readonly",
        image_id,
        case,
    ]


def run_container(settings, source: str, case):
    started = time.monotonic()
    name = "aegisforge-validation-" + uuid4().hex
    # Explicit environment whitelist: model/API credentials never enter docker processes.
    environment = {
        k: v
        for k, v in os.environ.items()
        if k.upper()
        in {
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "HOME",
            "APPDATA",
            "LOCALAPPDATA",
            "PROGRAMDATA",
        }
    }
    context = ROOT / "deploy" / "validator"
    fingerprint = hashlib.sha256(
        b"".join(
            (context / f).read_bytes() for f in ("Dockerfile", "requirements.lock", "harness.py")
        )
    ).hexdigest()
    try:
        inspected = subprocess.run(
            ["docker", "image", "inspect", IMAGE],
            capture_output=True,
            env=environment,
            timeout=10,
            check=True,
        )
        image = json.loads(inspected.stdout)[0]
        if image["Config"].get("Labels", {}).get("org.aegisforge.validator") != fingerprint:
            raise ValueError("image changed")
        image_id = image["Id"]
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="validation-", dir=settings.data_dir) as directory:
            path = Path(directory) / "candidate.py"
            path.write_text(source, encoding="utf-8", newline="\n")
            output = Path(directory) / "output.log"
            with output.open("wb") as stream:
                process = subprocess.Popen(
                    command(image_id, name, case["id"], path.resolve()),
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    env=environment,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
                deadline = time.monotonic() + 30
                try:
                    while process.poll() is None:
                        if time.monotonic() > deadline or output.stat().st_size > 131072:
                            raise TimeoutError
                        time.sleep(0.05)
                finally:
                    subprocess.run(
                        ["docker", "rm", "-f", name],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        env=environment,
                        timeout=10,
                    )
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=5)
            if output.stat().st_size > 131072:
                raise ValueError("output budget")
            result = json.loads(output.read_text(encoding="utf-8").splitlines()[-1])
            if result.get("case") != case["id"] or result.get("schema_version") != "validation-1.0":
                raise ValueError("invalid harness response")
            # Copy fixed test names/booleans only; never persist arbitrary container text.
            expected = case["tests"]
            tests = result["tests"]
            if [t["name"] for t in tests] != expected or any(
                type(t["passed"]) is not bool for t in tests
            ):
                raise ValueError("invalid tests")
            return {
                "status": "passed"
                if all(t["passed"] for t in tests) and process.returncode == 0
                else "failed",
                "case_id": case["id"],
                "tests": [{"name": t["name"], "passed": t["passed"]} for t in tests],
                "image_id": image_id,
                "harness_sha256": fingerprint,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            }
    except Exception:
        return {
            "status": "error",
            "error_code": "VALIDATION_ENVIRONMENT",
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }


def validate_one(engine, settings, repair_id=None):
    with transaction(engine) as session:
        query = select(Repair).where(Repair.dynamic_requested.is_(True))
        if repair_id:
            query = query.where(Repair.id == repair_id)
        item = session.scalar(query.order_by(Repair.created_at).limit(1))
        if item is None:
            return False
        case = match_case(item.source_sha256)
        source = load_artifact(settings, session.get(Artifact, item.candidate_id)).content
        candidate_id, ident = item.candidate_id, item.id
        item.dynamic_requested = False
        item.dynamic_json = json.dumps({"status": "running"})
    result = run_container(settings, source, case)
    with transaction(engine) as session:
        item = session.get(Repair, ident)
        if item.candidate_id == candidate_id:
            item.dynamic_json = json.dumps(result)
    return True
