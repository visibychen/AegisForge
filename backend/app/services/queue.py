import json
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.core.errors import DomainError
from app.llm.prompts import PROMPT_VERSION
from app.models import FindingRecord, Job, ModelCall, ScanTask


def utcnow():
    return datetime.now(UTC)


@contextmanager
def transaction(engine):
    with Session(engine) as session:
        session.execute(text("BEGIN IMMEDIATE"))
        try:
            yield session
            session.commit()
        except BaseException:
            session.rollback()
            raise


DB_ATTEMPTS = 3


def with_db_retry(operation, *args, **kwargs):
    """Retry a whole short transaction on transient SQLite errors (bounded, no message echo)."""
    for attempt in range(DB_ATTEMPTS):
        try:
            return operation(*args, **kwargs)
        except OperationalError:
            if attempt == DB_ATTEMPTS - 1:
                raise
            time.sleep(0.2 * (attempt + 1))


def model_usage(session, settings, scan_id):
    """(calls used by this scan across all attempts, server calls used this UTC day)."""
    day = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    scan_used = session.scalar(
        select(func.count()).select_from(ModelCall).where(ModelCall.scan_id == scan_id)
    )
    daily_used = session.scalar(
        select(func.count()).select_from(ModelCall).where(ModelCall.created_at >= day)
    )
    return scan_used, daily_used


@dataclass(frozen=True)
class Lease:
    job_id: str
    scan_id: str
    token: str


def capacity(session, settings):
    count = session.scalar(
        select(func.count()).select_from(Job).where(Job.status.in_(["queued", "running"]))
    )
    if count >= settings.queue_limit:
        raise DomainError("QUEUE_FULL", "队列已满，请等待当前任务完成。", 429)
    recent = session.scalar(
        select(func.count())
        .select_from(Job)
        .where(Job.created_at >= utcnow() - timedelta(minutes=1))
    )
    if recent >= 20:
        raise DomainError("SCAN_RATE_LIMIT", "任务创建过于频繁，请稍后重试。", 429)


def claim(engine, settings, at=None) -> Lease | None:
    at = at or utcnow()
    with transaction(engine) as session:
        for job in session.scalars(
            select(Job).where(Job.status == "running", Job.lease_until <= at)
        ):
            scan = session.get(ScanTask, job.scan_id)
            for call in session.scalars(
                select(ModelCall).where(ModelCall.job_id == job.id, ModelCall.status == "started")
            ):
                call.status = "interrupted"
            job.lease_token = None
            job.lease_until = None
            if scan.cancel_requested:
                job.status, scan.status, scan.finished_at = "cancelled", "cancelled", at
            elif job.attempts >= 3:
                job.status, scan.status, scan.finished_at = "failed", "failed", at
                job.error_code = scan.error_code = "LEASE_EXHAUSTED"
            else:
                job.status, scan.status = "queued", "queued"
        session.flush()
        job = session.scalar(
            select(Job).where(Job.status == "queued").order_by(Job.created_at, Job.id).limit(1)
        )
        if job is None:
            return None
        scan = session.get(ScanTask, job.scan_id)
        token = str(uuid4())
        job.status, job.attempts, job.lease_token = "running", job.attempts + 1, token
        job.heartbeat_at, job.lease_until = at, at + timedelta(seconds=settings.lease_seconds)
        scan.status = "running"
        if scan.attempt_started_at is None:
            scan.attempt_started_at = at
        return Lease(job.id, scan.id, token)


def active(session, lease, *, allow_cancel=False):
    job = session.get(Job, lease.job_id)
    if (
        job is None
        or job.status != "running"
        or job.lease_token != lease.token
        or job.lease_until is None
        or job.lease_until <= utcnow()
    ):
        raise DomainError("LEASE_LOST", "任务执行租约已失效。", 409)
    scan = session.get(ScanTask, lease.scan_id)
    if scan.cancel_requested and not allow_cancel:
        raise DomainError("TASK_CANCELLED", "任务已请求取消。", 409)
    return job, scan


def heartbeat(engine, settings, lease):
    with transaction(engine) as session:
        job, scan = active(session, lease, allow_cancel=True)
        job.heartbeat_at = utcnow()
        job.lease_until = job.heartbeat_at + timedelta(seconds=settings.lease_seconds)
        return scan.cancel_requested


class CallLedger:
    def __init__(self, engine, settings, lease):
        self.engine, self.settings, self.lease = engine, settings, lease

    def reserve(self, chars):
        return with_db_retry(self._reserve, chars)

    def _reserve(self, chars):
        with transaction(self.engine) as session:
            active(session, self.lease)
            scan_used, daily_used = model_usage(session, self.settings, self.lease.scan_id)
            if scan_used >= self.settings.max_model_calls:
                raise DomainError("MODEL_CALL_BUDGET", "本任务模型调用预算已耗尽。", 409)
            if daily_used >= self.settings.daily_model_calls:
                raise DomainError("MODEL_DAILY_BUDGET", "今日服务器模型调用次数已达上限。", 429)
            call = ModelCall(
                scan_id=self.lease.scan_id,
                job_id=self.lease.job_id,
                model=self.settings.deepseek_model,
                prompt_version=PROMPT_VERSION,
                input_chars=chars,
            )
            session.add(call)
            session.flush()
            return call.id

    def finish(self, call_id, status, duration, size, usage, category=None):
        with_db_retry(self._finish, call_id, status, duration, size, usage, category)

    def _finish(self, call_id, status, duration, size, usage, category):
        # Metadata only: never store model text, request content or headers.
        with transaction(self.engine) as session:
            call = session.get(ModelCall, call_id)
            if call:
                call.status, call.duration_ms, call.output_bytes = status, duration, size
                call.input_tokens, call.output_tokens = (
                    usage.get("prompt_tokens"),
                    usage.get("completion_tokens"),
                )
                call.failure_category = category


def publish(engine, lease, status, summary, entries, error_code=None):
    """Publish the current attempt; only a still-valid lease may write a terminal state."""
    with transaction(engine) as session:
        job, scan = active(session, lease, allow_cancel=True)
        if scan.cancel_requested:
            status, summary, entries, error_code = (
                "cancelled",
                {**summary, "warnings": ["任务已取消。"], "analysis_complete": False},
                [],
                None,
            )
        session.execute(
            delete(FindingRecord).where(
                FindingRecord.scan_id == scan.id, FindingRecord.attempt == scan.retries
            )
        )
        for position, entry in enumerate(entries):
            session.add(
                FindingRecord(
                    scan_id=scan.id,
                    artifact_id=entry["finding"]["location"]["artifact_id"],
                    payload=json.dumps(entry, ensure_ascii=False),
                    attempt=scan.retries,
                    position=position,
                )
            )
        scan.status, scan.finished_at, scan.error_code = status, utcnow(), error_code
        scan.result_json = json.dumps(summary, ensure_ascii=False)
        job.status = "completed" if status in {"completed", "partial"} else status
        job.error_code, job.lease_token, job.lease_until = error_code, None, None
