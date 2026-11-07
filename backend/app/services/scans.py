import json
from uuid import uuid4

from sqlalchemy import select

from app.core.errors import DomainError
from app.llm.prompts import PROMPT_VERSION
from app.models import Artifact, Job, ScanTask, TaskArtifact
from app.rules.detector import RULE_VERSION
from app.services.artifacts import load_artifact
from app.services.queue import capacity, model_usage, transaction, utcnow

MAX_ATTEMPT_HISTORY = 3


def uses_model(scan_or_request) -> bool:
    return scan_or_request.strategy != "rules" and scan_or_request.model_alias != "fake"


def check_model_budget(session, settings, scan_id, chunks):
    """Refuse up front when the remaining call budget cannot even cover one call per chunk."""
    scan_used, daily_used = model_usage(session, settings, scan_id)
    if settings.daily_model_calls - daily_used < chunks:
        raise DomainError("MODEL_DAILY_BUDGET", "今日服务器模型调用次数不足，请明天再试。", 429)
    if settings.max_model_calls - scan_used < chunks:
        raise DomainError(
            "RETRY_BUDGET", "本任务剩余模型调用预算不足以覆盖全部分块，已保留原结果。", 409
        )


def scan_artifacts(session, scan_id):
    return session.scalars(
        select(Artifact)
        .join(TaskArtifact, Artifact.id == TaskArtifact.artifact_id)
        .where(TaskArtifact.scan_id == scan_id)
        .order_by(Artifact.id)
    ).all()


def check_inputs(settings, artifacts):
    if (
        len(artifacts) > settings.max_files
        or sum(a.size_bytes for a in artifacts) > settings.max_total_bytes
    ):
        raise DomainError("TASK_INPUT_LIMIT", "任务文件数量或总字节数超过限制。")
    parsed = [(artifact, load_artifact(settings, artifact)) for artifact in artifacts]
    if sum(len(p.content) for _, p in parsed) > 80000 or sum(len(p.chunks) for _, p in parsed) > 8:
        raise DomainError("TASK_INPUT_BUDGET", "任务超过 80,000 字符或 8 分块，请缩小输入。")
    return parsed


def require_scan(session, scan_id):
    scan = session.get(ScanTask, scan_id)
    if scan is None:
        raise DomainError("SCAN_NOT_FOUND", "检测任务不存在。", 404)
    return scan


def create_scan(engine, settings, request, key=None):
    if request.model_alias not in settings.model_aliases:
        raise DomainError("MODEL_NOT_AVAILABLE", "所选模型未在服务器配置。")
    key = "create:" + (key or str(uuid4()))
    ids = sorted(str(value) for value in request.artifact_ids)
    with transaction(engine) as session:
        existing = session.scalar(select(Job).where(Job.idempotency_key == key))
        if existing:
            scan = require_scan(session, existing.scan_id)
            old_ids = sorted(a.id for a in scan_artifacts(session, scan.id))
            if (
                old_ids != ids
                or scan.strategy != request.strategy
                or scan.model_alias != request.model_alias
            ):
                raise DomainError("IDEMPOTENCY_CONFLICT", "幂等键已用于不同请求。", 409)
            return scan.id
        capacity(session, settings)
        artifacts = session.scalars(select(Artifact).where(Artifact.id.in_(ids))).all()
        if len(artifacts) != len(ids):
            raise DomainError("ARTIFACT_NOT_FOUND", "部分输入快照不存在。", 404)
        parsed = check_inputs(settings, artifacts)
        if uses_model(request):
            check_model_budget(session, settings, None, sum(len(p.chunks) for _, p in parsed))
        scan = ScanTask(
            strategy=request.strategy,
            model_alias=request.model_alias,
            rule_version=RULE_VERSION,
            prompt_version=PROMPT_VERSION,
        )
        session.add(scan)
        session.flush()
        session.add_all([TaskArtifact(scan_id=scan.id, artifact_id=i) for i in ids])
        session.add(Job(scan_id=scan.id, idempotency_key=key))
        return scan.id


def change_scan(engine, settings, scan_id, action):
    with transaction(engine) as session:
        scan = require_scan(session, scan_id)
        if action == "cancel":
            if scan.status in {"queued", "running"}:
                scan.cancel_requested = True
                if scan.status == "queued":
                    scan.status, scan.finished_at = "cancelled", utcnow()
                    for job in session.scalars(
                        select(Job).where(Job.scan_id == scan_id, Job.status == "queued")
                    ):
                        job.status = "cancelled"
            return
        if scan.status not in {"partial", "failed", "cancelled"}:
            raise DomainError("SCAN_NOT_RETRYABLE", "只能重试部分完成、失败或取消的任务。", 409)
        if scan.retries >= 2:
            raise DomainError("RETRY_LIMIT", "任务最多手动重试两次。", 409)
        capacity(session, settings)
        parsed = check_inputs(settings, scan_artifacts(session, scan.id))
        if uses_model(scan):
            check_model_budget(session, settings, scan.id, sum(len(p.chunks) for _, p in parsed))
        # Keep the previous attempt: its summary moves to history, its findings stay stored
        # under their attempt number and remain readable through ?attempt=N.
        history = json.loads(scan.attempts_json or "[]")
        history.append(
            {
                "attempt": scan.retries,
                "status": scan.status,
                "error_code": scan.error_code,
                "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
                "summary": json.loads(scan.result_json or "{}"),
            }
        )
        scan.attempts_json = json.dumps(history[-MAX_ATTEMPT_HISTORY:], ensure_ascii=False)
        scan.retries += 1
        scan.status, scan.cancel_requested, scan.finished_at = "queued", False, None
        scan.error_code, scan.result_json = None, "{}"
        session.add(Job(scan_id=scan.id, idempotency_key=f"retry:{scan.id}:{scan.retries}"))


def scan_view(session, scan, settings=None):
    artifacts = scan_artifacts(session, scan.id)
    call_count, daily_used = model_usage(session, settings, scan.id)
    budget = (
        {
            "scan_used": call_count,
            "scan_limit": settings.max_model_calls,
            "daily_used": daily_used,
            "daily_limit": settings.daily_model_calls,
        }
        if settings is not None
        else None
    )
    return {
        "id": scan.id,
        "status": scan.status,
        "strategy": scan.strategy,
        "model_alias": scan.model_alias,
        "rule_version": scan.rule_version,
        "prompt_version": scan.prompt_version,
        "error_code": scan.error_code,
        "cancel_requested": scan.cancel_requested,
        "retries": scan.retries,
        "created_at": scan.created_at.isoformat(),
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "artifacts": [
            {
                "id": a.id,
                "display_name": a.display_name,
                "input_type": a.input_type,
                "sha256": a.sha256,
            }
            for a in artifacts
        ],
        "call_count": call_count,
        "budget": budget,
        "attempt": scan.retries,
        "attempts": json.loads(scan.attempts_json or "[]"),
        "result": json.loads(scan.result_json),
    }
