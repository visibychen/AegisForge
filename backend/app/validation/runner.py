"""Host-side Docker orchestrator; only the separately launched trusted runner imports it.

The API and the model worker never import this module (code-path separation only: it does not
by itself remove Docker rights from the OS user that runs them). The container returns exactly
one JSON line on stdout; everything the candidate prints stays inside the container.
"""

import hashlib
import json
import os
import re
import secrets
import subprocess
import tempfile
import time
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import DomainError
from app.models import Artifact, FindingRecord, Repair, ScanTask
from app.services.artifacts import load_artifact
from app.services.queue import transaction, utcnow
from app.services.receipts import canonical
from app.validation.registry import (
    match_case,
    registry_digest,
    seal,
    tests_digest,
    validator_fingerprint,
)

IMAGE = "aegisforge-validator:m4"
PROJECT_LABEL = "org.aegisforge.validation=1"  # only containers with this label are ever swept
RUN_LABEL = "org.aegisforge.validation-run"
NAME_PREFIX = "aegisforge-validation-"
HARD_TIMEOUT = 30  # seconds for the whole container
RESULT_LIMIT = 16 * 1024
STALE_AFTER = 75  # a 'running' record older than this belongs to a crashed runner
RESULT_KEYS = {"schema_version", "case", "nonce", "candidate_sha256", "tests", "passed"}
ENVIRONMENT = frozenset(
    {
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
)


class ResultError(Exception):
    """A content-free validation failure code (never carries container output)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def docker_environment() -> dict[str, str]:
    # Explicit whitelist: model/API credentials never enter docker processes.
    return {k: v for k, v in os.environ.items() if k.upper() in ENVIRONMENT}


def command(image_id, name, case, source, run_id="0" * 32):
    if not image_id.startswith("sha256:") or len(image_id) != 71:
        raise DomainError("VALIDATOR_IMAGE", "固定验证镜像不可用。", 503)
    return [
        "docker",
        "run",
        "-i",
        "--init",
        "--name",
        name,
        "--label",
        PROJECT_LABEL,
        "--label",
        f"{RUN_LABEL}={run_id}",
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
        "128" if case == "xss-01" else "64",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=128m,mode=1777",
        "--log-driver",
        "none",
        "--mount",
        f"type=bind,source={source},target=/candidate.py,readonly",
        image_id,
        case,
    ]


def normalize_daemon_root(source):
    # Docker Desktop reports the original Windows bind source even through its Linux socket.
    # Its Linux daemon resolves that drive through this fixed VM mount prefix.
    if re.match(r"^[A-Za-z]:[\\/]", source):
        value = PureWindowsPath(source)
        if ".." in value.parts:
            raise ResultError("VALIDATION_ENVIRONMENT")
        return str(PurePosixPath("/run/desktop/mnt/host", value.drive[0].lower(), *value.parts[1:]))
    value = PurePosixPath(source)
    if not value.is_absolute() or ".." in value.parts:
        raise ResultError("VALIDATION_ENVIRONMENT")
    return str(value)


def daemon_source(settings, path):
    """Only a trusted deployment launcher supplies the daemon's shared-data bind source."""
    resolved = path.resolve()
    relative = resolved.relative_to(settings.data_dir.resolve())
    host_root = os.environ.get("AEGISFORGE_VALIDATOR_HOST_DATA_DIR")
    if host_root:
        return str(PurePosixPath(normalize_daemon_root(host_root), *relative.parts))
    return str(resolved)


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def parse_harness_output(raw: bytes, *, case, nonce, candidate_sha256, returncode):
    """Validate the container's single result line; return the whitelisted test results."""
    if len(raw) > RESULT_LIMIT:
        raise ResultError("VALIDATION_OUTPUT_LIMIT")
    if not raw.strip():
        raise ResultError("VALIDATION_NO_RESULT")  # driver died or refused to run: never a pass
    try:
        lines = [line for line in raw.decode("utf-8").splitlines() if line.strip()]
        if len(lines) != 1:
            raise ValueError("line count")
        data = json.loads(lines[0], object_pairs_hook=strict_object)
        if not isinstance(data, dict) or set(data) != RESULT_KEYS:
            raise ValueError("keys")
        if data["schema_version"] != "validation-2.0" or data["case"] != case["id"]:
            raise ValueError("identity")
        if not secrets.compare_digest(str(data["nonce"]), nonce):
            raise ValueError("nonce")
        if data["candidate_sha256"] != candidate_sha256:
            raise ValueError("candidate")
        tests = data["tests"]
        if not isinstance(tests, list) or [
            t.get("name") if isinstance(t, dict) else None for t in tests
        ] != list(case["tests"]):
            raise ValueError("tests")
        if any(set(t) != {"name", "passed"} or type(t["passed"]) is not bool for t in tests):
            raise ValueError("test shape")
        passed = all(t["passed"] for t in tests)
        if data["passed"] is not passed or returncode != (0 if passed else 1):
            raise ValueError("verdict")
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise ResultError("VALIDATION_PROTOCOL") from None
    return [{"name": t["name"], "passed": t["passed"]} for t in tests]


def cleanup(process, name, environment):
    """Always reap the local docker client, even when `docker rm` itself fails."""
    try:
        subprocess.run(
            ["docker", "rm", "-f", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            timeout=10,
            check=False,
        )
    except Exception:  # noqa: BLE001 - recycling must never raise
        pass
    finally:
        if process.poll() is None:
            with suppress(Exception):
                process.kill()
        with suppress(Exception):
            process.wait(timeout=5)


def sweep_orphans(environment=None) -> int:
    """Remove leftover containers that carry this project's validation label (and name prefix)."""
    environment = environment or docker_environment()
    listed = subprocess.run(
        [
            "docker",
            "ps",
            "-aq",
            "--filter",
            f"label={PROJECT_LABEL}",
            "--filter",
            f"name={NAME_PREFIX}",
        ],
        capture_output=True,
        text=True,
        env=environment,
        timeout=15,
        check=True,
    )
    ids = [item for item in listed.stdout.split() if re.fullmatch(r"[0-9a-f]{12,64}", item)]
    stale = []
    if ids:
        details = subprocess.run(
            ["docker", "inspect", *ids],
            capture_output=True,
            text=True,
            env=environment,
            timeout=15,
            check=True,
        )
        for item in json.loads(details.stdout):
            labels = item.get("Config", {}).get("Labels", {}) or {}
            created = datetime.fromisoformat(item["Created"][:26] + "+00:00")
            age = (datetime.now(UTC) - created).total_seconds()
            if (
                age > HARD_TIMEOUT + 30
                and item.get("Name", "").startswith("/" + NAME_PREFIX)
                and labels.get("org.aegisforge.validation") == "1"
                and re.fullmatch(r"[0-9a-f]{32}", labels.get(RUN_LABEL, ""))
            ):
                stale.append(item["Id"])
    if stale:
        subprocess.run(
            ["docker", "rm", "-f", *stale],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            timeout=30,
            check=False,
        )
    return len(stale)


def run_container(settings, source: str, case, *, run_id=None, should_cancel=None):
    started = time.monotonic()
    run_id = run_id or uuid4().hex
    nonce = secrets.token_hex(16)
    candidate_sha256 = hashlib.sha256(source.encode("utf-8")).hexdigest()
    environment = docker_environment()
    name = NAME_PREFIX + run_id
    process = None

    def elapsed():
        return int((time.monotonic() - started) * 1000)

    try:
        fingerprint = validator_fingerprint()
        inspected = subprocess.run(
            ["docker", "image", "inspect", IMAGE],
            capture_output=True,
            env=environment,
            timeout=10,
            check=True,
        )
        image = json.loads(inspected.stdout)[0]
        if image["Config"].get("Labels", {}).get("org.aegisforge.validator") != fingerprint:
            raise ResultError("VALIDATOR_IMAGE_STALE")
        image_id = image["Id"]
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="validation-", dir=settings.data_dir) as directory:
            path = Path(directory) / "candidate.py"
            path.write_text(source, encoding="utf-8", newline="\n")
            output = Path(directory) / "result.out"
            cancelled = False
            with output.open("wb") as stream:
                process = subprocess.Popen(
                    command(image_id, name, case["id"], daemon_source(settings, path), run_id),
                    stdin=subprocess.PIPE,
                    stdout=stream,
                    stderr=subprocess.DEVNULL,
                    env=environment,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
                try:
                    # The nonce travels over stdin only: never argv, never the environment.
                    process.stdin.write((nonce + "\n").encode("ascii"))
                    process.stdin.close()
                    deadline = time.monotonic() + HARD_TIMEOUT
                    while process.poll() is None:
                        if should_cancel is not None and should_cancel():
                            cancelled = True
                            break
                        if time.monotonic() > deadline:
                            raise ResultError("VALIDATION_TIMEOUT")
                        if output.stat().st_size > RESULT_LIMIT:
                            raise ResultError("VALIDATION_OUTPUT_LIMIT")
                        time.sleep(0.05)
                finally:
                    cleanup(process, name, environment)
            if cancelled:
                return {"status": "cancelled", "run_id": run_id, "elapsed_ms": elapsed()}
            if process.returncode in {3, 4, 125, 126, 127, 137}:
                raise ResultError("VALIDATION_ENVIRONMENT")
            tests = parse_harness_output(
                output.read_bytes(),
                case=case,
                nonce=nonce,
                candidate_sha256=candidate_sha256,
                returncode=process.returncode,
            )
            return {
                "status": "passed" if all(t["passed"] for t in tests) else "failed",
                "run_id": run_id,
                "case_id": case["id"],
                "tests": tests,
                "candidate_sha256": candidate_sha256,
                "image_id": image_id,
                "harness_sha256": fingerprint,
                "elapsed_ms": elapsed(),
            }
    except ResultError as error:
        return {
            "status": "error",
            "run_id": run_id,
            "error_code": error.code,
            "elapsed_ms": elapsed(),
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "run_id": run_id,
            "error_code": "VALIDATION_TIMEOUT",
            "elapsed_ms": elapsed(),
        }
    except Exception:  # noqa: BLE001 - only a fixed code leaves this function
        return {
            "status": "error",
            "run_id": run_id,
            "error_code": "VALIDATION_ENVIRONMENT",
            "elapsed_ms": elapsed(),
        }


def _record(item) -> dict:
    try:
        value = json.loads(item.dynamic_json)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def mark_interrupted(engine, now=None) -> int:
    """A runner that crashed mid-run must not leave 'running' behind forever."""
    now = now or utcnow()
    count = 0
    with transaction(engine) as session:
        for item in session.scalars(select(Repair).where(Repair.dynamic_json.contains("running"))):
            record = _record(item)
            if record.get("status") != "running":
                continue
            began = record.get("started_at")
            try:
                age = (now - utcnow().fromisoformat(began)).total_seconds() if began else None
            except ValueError:
                age = None
            if age is None or age > STALE_AFTER:
                item.dynamic_json = canonical(
                    {
                        "status": "error",
                        "error_code": "VALIDATION_INTERRUPTED",
                        "run_id": record.get("run_id"),
                        "requested_at": record.get("requested_at"),
                        "finished_at": now.isoformat(),
                    }
                )
                count += 1
    return count


def validate_one(engine, settings, repair_id=None, runner=None):
    runner = runner or run_container
    mark_interrupted(engine)
    run_id = uuid4().hex
    with transaction(engine) as session:
        query = select(Repair).where(Repair.dynamic_requested.is_(True))
        if repair_id:
            query = query.where(Repair.id == repair_id)
        item = session.scalar(query.order_by(Repair.created_at).limit(1))
        if item is None:
            return False
        ident, previous = item.id, _record(item)
        item.dynamic_requested = False
        requested_at = previous.get("requested_at")
        try:
            scan = session.get(ScanTask, item.scan_id)
            if scan is None or scan.deleted_at is not None:
                raise DomainError("SCAN_REMOVED", "所属检测任务已移出历史。", 404)
            finding = session.get(FindingRecord, item.finding_id)
            if finding is None or finding.attempt != scan.retries:
                raise DomainError("REPAIR_ARCHIVED", "旧尝试候选不能重新验证。", 409)
            case = match_case(item.source_sha256)
            candidate = session.get(Artifact, item.candidate_id) if item.candidate_id else None
            if item.status != "candidate" or candidate is None:
                raise DomainError("CANDIDATE_NOT_READY", "候选尚未生成。", 409)
            source = load_artifact(settings, candidate).content
            candidate_sha256, source_sha256 = candidate.sha256, item.source_sha256
        except DomainError as error:
            # An unknown or unusable sample ends explainably instead of looping forever.
            item.dynamic_json = canonical(
                {
                    "status": "error",
                    "error_code": error.code,
                    "run_id": run_id,
                    "requested_at": requested_at,
                    "finished_at": utcnow().isoformat(),
                }
            )
            return True
        started_at = utcnow().isoformat()
        item.dynamic_json = canonical(
            {
                "status": "running",
                "run_id": run_id,
                "requested_at": requested_at,
                "started_at": started_at,
            }
        )

    last_check = [0.0]

    def cancelled() -> bool:
        if time.monotonic() - last_check[0] < 1:
            return False
        last_check[0] = time.monotonic()
        with Session(engine) as session:
            row = session.get(Repair, ident)
            return bool(row is not None and _record(row).get("cancel_requested"))

    result = runner(settings, source, case, run_id=run_id, should_cancel=cancelled)
    record = {
        **result,
        "run_id": run_id,
        "requested_at": requested_at,
        "started_at": started_at,
        "finished_at": utcnow().isoformat(),
        "source_sha256": source_sha256,
        "candidate_sha256": candidate_sha256,
        "case_id": case["id"],
        "tests_sha256": tests_digest(case),
        "registry_sha256": registry_digest(),
    }
    if record["status"] in {"passed", "failed"}:
        if result.get("candidate_sha256") != candidate_sha256:
            record = {k: v for k, v in record.items() if k not in {"tests"}}
            record["status"], record["error_code"] = "error", "VALIDATION_PROTOCOL"
        else:
            record = seal(record)
    with transaction(engine) as session:
        row = session.get(Repair, ident)
        current = _record(row)
        if current.get("run_id") == run_id and current.get("status") == "running":
            row.dynamic_json = canonical(record)
    return True
